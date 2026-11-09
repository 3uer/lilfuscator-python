#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Lilfuscator v2.2.0
==================
Python source-code obfuscator: layered packing, AST transformations,
decoy classes, junk code, polymorphic loaders, chained-key integrity.

Zero dependencies. Python 3.9+.

Pipeline:
    source -> [strip docstrings] -> [flatten control flow] -> [rename locals]
           -> [numbers] -> [strings] -> compile -> marshal
           -> N pack layers (compress -> RC4 -> encode, chained keys)
           -> polymorphic self-contained loader -> output .py

Integrity model: each layer key = SHA-256(blob-it-wraps + layer seed).
Tampering with ANY byte corrupts every outer decryption. No check to NOP.
"""

import argparse
import ast
import base64
import hashlib
import json
import lzma
import marshal
import os
import platform
import random
import shutil
import sys
import time
import zlib

VERSION = "2.2.0"

# --------------------------------------------------------------------------
# Profiles
# --------------------------------------------------------------------------

PROFILES = {
    "fast":     dict(layers=1, rename=False, rename_style="random",
                     strings=False, numbers=False, strip_docs=True,
                     junk=0, decoys=0, trash=0, antidebug=False,
                     flatten=False, bind=False),
    "balanced": dict(layers=3, rename=True, rename_style="random",
                     strings=True, numbers=True, strip_docs=True,
                     junk=2, decoys=2, trash=3, antidebug=False,
                     flatten=False, bind=False),
    "strong":   dict(layers=5, rename=True, rename_style="confusable",
                     strings=True, numbers=True, strip_docs=True,
                     junk=4, decoys=4, trash=6, antidebug=True,
                     flatten=True, bind=False),
    "paranoid": dict(layers=8, rename=True, rename_style="confusable",
                     strings=True, numbers=True, strip_docs=True,
                     junk=6, decoys=6, trash=10, antidebug=True,
                     flatten=True, bind=True),
}

# --------------------------------------------------------------------------
# Crypto / packing primitives (also emitted into the generated loader)
# --------------------------------------------------------------------------

def rc4(key: bytes, data: bytes) -> bytes:
    """RC4 stream cipher. ~20 lines, stdlib-only, good enough for packing."""
    S = list(range(256))
    j = 0
    kb = list(key)
    for i in range(256):
        j = (j + S[i] + kb[i % len(kb)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for ch in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(ch ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


_COMPRESS = {
    "z": (zlib.compress, zlib.decompress),
    "x": (lzma.compress, lzma.decompress),
}

_ENCODE = {
    "b85": (lambda b: base64.b85encode(b), "b85decode"),
    "b64": (lambda b: base64.b64encode(b), "b64decode"),
    "hx":  (lambda b: b.hex().encode(), "fromhex"),
}


def _chained_key(blob: bytes, seed: bytes, bind_fp: bytes = b"") -> bytes:
    """Layer key derived from the blob it wraps -> tamper-evident chain."""
    return hashlib.sha256(blob + seed + bind_fp).digest()[:16]


# --------------------------------------------------------------------------
# Random name generation
# --------------------------------------------------------------------------

_CONFUSABLE = "_O0Il1lOI0O1lI_"
_LETTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


def gen_name(rng: random.Random, style: str = "random", prefix: str = "_") -> str:
    if style == "confusable":
        n = rng.randint(5, 9)
        return prefix + "".join(rng.choice(_CONFUSABLE) for _ in range(n))
    if style == "hex":
        return prefix + "x" + "".join(rng.choice("0123456789abcdef")
                                      for _ in range(rng.randint(4, 8)))
    n = rng.randint(6, 10)
    first = rng.choice(_LETTERS)
    return prefix + first + "".join(rng.choice(_LETTERS + "0123456789")
                                    for _ in range(n - 1))


def unique_names(rng, count, style, used):
    out = []
    while len(out) < count:
        nm = gen_name(rng, style)
        if nm not in used and not nm.startswith("_lf"):
            used.add(nm)
            out.append(nm)
    return out


# --------------------------------------------------------------------------
# AST helpers
# --------------------------------------------------------------------------

def _attach_parents(tree: ast.AST) -> None:
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child._parent = node


def _in_joined_str(node: ast.AST) -> bool:
    p = getattr(node, "_parent", None)
    while p is not None:
        if isinstance(p, (ast.JoinedStr, ast.FormattedValue)):
            return True
        p = getattr(p, "_parent", None)
    return False


_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)


def _assigned_names(stmts) -> set:
    """Names bound by these statements, not descending into nested scopes."""
    names = set()
    def walk(n):
        for c in ast.iter_child_nodes(n):
            if isinstance(c, _SCOPE_NODES):
                continue
            if isinstance(c, ast.Name) and isinstance(c.ctx, (ast.Store, ast.Del)):
                names.add(c.id)
            if isinstance(c, (ast.Global,)):
                names.difference_update(c.names)
            walk(c)
    for s in stmts:
        walk(s)
    return names


# --------------------------------------------------------------------------
# 1. Docstring stripping
# --------------------------------------------------------------------------

class DocStripper(ast.NodeTransformer):
    def _body(self, node):
        b = node.body
        if (b and isinstance(b[0], ast.Expr)
                and isinstance(b[0].value, ast.Constant)
                and isinstance(b[0].value.value, str)):
            node.body = b[1:] if len(b) > 1 else [ast.Pass()]
        self.generic_visit(node)
        return node

    visit_Module = _body
    visit_FunctionDef = _body
    visit_AsyncFunctionDef = _body
    visit_ClassDef = _body


# --------------------------------------------------------------------------
# 2. Control-flow flattening (conservative)
# --------------------------------------------------------------------------

_FLATTENABLE = (ast.Expr, ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Pass)


class ControlFlowFlattener(ast.NodeTransformer):
    """Rewrite simple function bodies into a while-dispatch loop.

    Only functions whose body is a flat list of simple statements plus an
    optional trailing ``return`` (no loops/ifs/try/yield/global/nonlocal)
    are transformed.
    """

    def visit_FunctionDef(self, node):
        self.generic_visit(node)                      # flatten inner first
        if self._can_flatten(node):
            node = self._flatten(node)
        return node

    @staticmethod
    def _can_flatten(node) -> bool:
        body = node.body
        if len(body) < 2:
            return False
        last = len(body) - 1
        for i, st in enumerate(body):
            if isinstance(st, ast.Return):
                if i != last:
                    return False
            elif not isinstance(st, _FLATTENABLE):
                return False
        for n in ast.walk(node):
            if n is node:
                continue
            if isinstance(n, (ast.Yield, ast.YieldFrom, ast.Await,
                              ast.Global, ast.Nonlocal,
                              ast.FunctionDef, ast.AsyncFunctionDef,
                              ast.ClassDef, ast.Lambda)):
                return False
        return True

    @staticmethod
    def _flatten(node):
        pc, ret, tab = ControlFlowFlattener._names(3)
        stmts = node.body
        blocks = []
        all_names = set()
        for idx, st in enumerate(stmts):
            last = idx == len(stmts) - 1
            blk = ast.FunctionDef(
                name=f"_b{idx}", args=ast.arguments(
                    posonlyargs=[], args=[], vararg=None, kwonlyargs=[],
                    kw_defaults=[], kwarg=None, defaults=[]),
                body=[], decorator_list=[])
            assigns = set(_assigned_names([st]))
            if last and isinstance(st, ast.Return):
                if st.value is not None:
                    blk.body.append(ast.Assign(
                        targets=[ast.Name(id=ret, ctx=ast.Store())],
                        value=st.value))
                    assigns.add(ret)
                blk.body.append(ast.Return(value=ast.Constant(value=-1)))
            else:
                blk.body = [st, ast.Return(
                    value=ast.Constant(value=-1 if last else idx + 1))]
            all_names |= assigns
            if assigns:
                blk.body.insert(0, ast.Nonlocal(names=sorted(assigns)))
            blocks.append(blk)
        node.body = [
            ast.Assign(targets=[ast.Name(id=pc, ctx=ast.Store())],
                       value=ast.Constant(value=0)),
            ast.Assign(targets=[ast.Name(id=ret, ctx=ast.Store())],
                       value=ast.Constant(value=None)),
            *[ast.Assign(targets=[ast.Name(id=nm, ctx=ast.Store())],
                         value=ast.Constant(value=None))
              for nm in sorted(all_names)],
            *blocks,
            ast.Assign(targets=[ast.Name(id=tab, ctx=ast.Store())],
                       value=ast.Dict(
                           keys=[ast.Constant(value=i)
                                 for i in range(len(blocks))],
                           values=[ast.Name(id=b.name, ctx=ast.Load())
                                   for b in blocks])),
            ast.While(
                test=ast.Compare(ast.Name(id=pc, ctx=ast.Load()),
                                 [ast.NotEq()],
                                 [ast.Constant(value=-1)]),
                body=[ast.Assign(
                    targets=[ast.Name(id=pc, ctx=ast.Store())],
                    value=ast.Call(
                        func=ast.Subscript(
                            value=ast.Name(id=tab, ctx=ast.Load()),
                            slice=ast.Name(id=pc, ctx=ast.Load()),
                            ctx=ast.Load()),
                        args=[], keywords=[]))],
                orelse=[]),
            ast.Return(value=ast.Name(id=ret, ctx=ast.Load())),
        ]
        return node

    _counter = 0

    @classmethod
    def _names(cls, n):
        base = f"_lfx{cls._counter}"
        cls._counter += 1
        return [f"{base}_{i}" for i in range(n)]


# --------------------------------------------------------------------------
# 3. Identifier renaming (function-local names only, scope-aware)
# --------------------------------------------------------------------------

class LocalRenamer(ast.NodeTransformer):
    """Rename function-local variables. Top-down: outer scope first.

    Nested scopes keep their own bound names; free-variable references
    follow the enclosing rename. global/nonlocal targets belong to the
    enclosing scope and are renamed only there.
    """

    def __init__(self, rng, style="random", preserve=frozenset()):
        self.rng = rng
        self.style = style
        self.preserve = set(preserve)

    def visit_FunctionDef(self, node):
        self._rename_scope(node)
        self.generic_visit(node)
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    @staticmethod
    def _own_names(fn):
        own = _assigned_names(fn.body)
        a = fn.args
        own.update(x.arg for x in a.posonlyargs + a.args + a.kwonlyargs)
        if a.vararg:
            own.add(a.vararg.arg)
        if a.kwarg:
            own.add(a.kwarg.arg)
        for n in ast.walk(fn):
            if isinstance(n, ast.Global):
                own.difference_update(n.names)
            elif isinstance(n, ast.Nonlocal):
                own.difference_update(n.names)
        return own

    def _rename_scope(self, node):
        locals_ = _assigned_names(node.body)
        for n in ast.walk(node):
            if isinstance(n, ast.Global):
                locals_.difference_update(n.names)
            elif isinstance(n, ast.Nonlocal):
                locals_.difference_update(n.names)
        locals_.discard("__name__")
        locals_ -= self.preserve
        if not locals_:
            return
        mapping = {}
        for old in sorted(locals_):
            new = gen_name(self.rng, self.style)
            while new in mapping.values():
                new = gen_name(self.rng, self.style)
            mapping[old] = new

        def rename_node(n, skip=frozenset()):
            for child in ast.iter_child_nodes(n):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    own = self._own_names(child)
                    for d in child.args.defaults + child.args.kw_defaults:
                        if d is not None:
                            rename_node(d, skip)
                    for dec in child.decorator_list:
                        rename_node(dec, skip)
                    rename_node(child, skip | own)
                    continue
                if isinstance(child, ast.Lambda):
                    a = child.args
                    own = {x.arg for x in
                           a.posonlyargs + a.args + a.kwonlyargs}
                    if a.vararg:
                        own.add(a.vararg.arg)
                    if a.kwarg:
                        own.add(a.kwarg.arg)
                    for d in a.defaults + a.kw_defaults:
                        if d is not None:
                            rename_node(d, skip)
                    rename_node(child, skip | own)
                    continue
                if isinstance(child, ast.ClassDef):
                    for sub in child.body:
                        if isinstance(sub, (ast.FunctionDef,
                                            ast.AsyncFunctionDef)):
                            rename_node(sub, skip)
                    continue
                if isinstance(child, ast.Name):
                    if child.id in mapping and child.id not in skip:
                        child.id = mapping[child.id]
                elif isinstance(child, ast.Nonlocal):
                    child.names = [mapping.get(nm, nm)
                                   if nm not in skip else nm
                                   for nm in child.names]
                rename_node(child, skip)

        for d in node.args.defaults + node.args.kw_defaults:
            if d is not None:
                rename_node(d)
        rename_node(node)


# --------------------------------------------------------------------------
# 4. Number obfuscation: n -> a ^ (a ^ n)
# --------------------------------------------------------------------------

class NumberObfuscator(ast.NodeTransformer):
    def __init__(self, rng):
        self.rng = rng

    def visit_Match(self, node):          # match patterns need literals
        return node

    def visit_Constant(self, node):
        if (type(node.value) is int and node.value not in (0, 1)
                and not _in_joined_str(node)):
            a = self.rng.getrandbits(32)
            b = a ^ node.value
            return ast.copy_location(
                ast.BinOp(left=ast.Constant(value=a),
                          op=ast.BitXor(),
                          right=ast.Constant(value=b)),
                node)
        return node


# --------------------------------------------------------------------------
# 5. String obfuscation (lazy: decrypted at each use site)
# --------------------------------------------------------------------------

class StringObfuscator(ast.NodeTransformer):
    def __init__(self, rng):
        self.rng = rng

    def visit_Match(self, node):
        return node

    def visit_Constant(self, node):
        if not isinstance(node.value, str) or len(node.value) < 2:
            return node
        if _in_joined_str(node):
            return node
        p = getattr(node, "_parent", None)
        if isinstance(p, ast.AnnAssign) and p.annotation is node:
            return node
        choice = self.rng.randint(0, 2)
        if choice == 0:
            # chr()-join
            cps = [ord(c) for c in node.value]
            return ast.copy_location(
                ast.Call(
                    func=ast.Attribute(value=ast.Constant(value=""),
                                       attr="join", ctx=ast.Load()),
                    args=[ast.Call(func=ast.Name(id="map", ctx=ast.Load()),
                                   args=[ast.Name(id="chr", ctx=ast.Load()),
                                         ast.Tuple(elts=[ast.Constant(value=c)
                                                         for c in cps],
                                                   ctx=ast.Load())],
                                   keywords=[])],
                    keywords=[]), node)
        if choice == 1:
            # reversed slicing
            return ast.copy_location(
                ast.Subscript(value=ast.Constant(value=node.value[::-1]),
                              slice=ast.Slice(lower=None, upper=None,
                                              step=ast.Constant(value=-1)),
                              ctx=ast.Load()), node)
        # bytes.fromhex().decode()
        return ast.copy_location(
            ast.Call(
                func=ast.Attribute(
                    value=ast.Call(
                        func=ast.Attribute(
                            value=ast.Name(id="bytes", ctx=ast.Load()),
                            attr="fromhex", ctx=ast.Load()),
                        args=[ast.Constant(value=node.value.encode().hex())],
                        keywords=[]),
                    attr="decode", ctx=ast.Load()),
                args=[], keywords=[]), node)


# --------------------------------------------------------------------------
# 6. Decoy classes / junk code / trash comments (text-level, for the wrapper)
# --------------------------------------------------------------------------

_DECOY_WORDS = ["队列", "缓存", "调度", "句柄", "镜像", "哨兵", "负载", "拓扑",
                "校验", "寻址", "帧", "钩子", "令牌", "网关"]
_DECOY_VERBS = ["初始化", "同步", "回收", "注册", "劫持", "序列化", "归档", "探针"]
_LANGS = ["中文注释", "日本語コメント", "한국어 주석", "Deutscher Kommentar",
          "Русский комментарий", "commentaire français"]


def gen_decoy_classes(rng, count, style):
    out = []
    for _ in range(count):
        cname = rng.choice(_DECOY_WORDS) + rng.choice(_DECOY_WORDS) + str(rng.randint(10, 99))
        m1 = rng.choice(_DECOY_VERBS)
        m2 = rng.choice(_DECOY_VERBS)
        v1, v2, v3 = unique_names(rng, 3, style, set())
        doc = rng.choice(_LANGS)
        out.append(
            f'\nclass {cname}:\n'
            f'    """{doc}: {rng.getrandbits(64):016x}"""\n'
            f'    def __init__(self):\n'
            f'        self.{v1} = {rng.getrandbits(32)}\n'
            f'        self.{v2} = {{}}\n'
            f'    def {m1}(self):\n'
            f'        for {v3} in range({rng.randint(2, 7)}):\n'
            f'            self.{v2}[{v3}] = self.{v1} ^ ({v3} * {rng.randint(3, 91)})\n'
            f'        return len(self.{v2})\n'
            f'    def {m2}(self):\n'
            f'        return self.{m1}() % {rng.randint(2, 13)} == {rng.randint(14, 99)}\n'
        )
    return "".join(out)


def gen_junk(rng, style):
    f1, p1, s1, s2, d1 = unique_names(rng, 5, style, set())
    dead1, dead2, dead3 = unique_names(rng, 3, style, set())
    return (
        f'\n{s1} = object()\n{s2} = object()\n'
        f'def {f1}({p1}):\n'
        f'    _acc = 0\n'
        f'    for _ch in str(id({p1})) + str(len(str({p1}))):\n'
        f'        _acc = (_acc * 131 + ord(_ch)) & 0xFFFFFFFF\n'
        f'    return _acc\n'
        f'# {rng.choice(_LANGS)}\n'
        f'if {f1}({s1}) == {f1}({s2}) + 1:\n'
        f'    {dead1} = [{rng.getrandbits(32) ^ 0xFF} for _ in range({rng.randint(3, 9)})]\n'
        f'    {dead2} = {{{dead1}[0]: {dead1}}} if {dead1} else {{0: None}}\n'
        f'    {dead3} = ({dead1}, {dead2}, str({s1}))\n'
    )


def gen_trash(rng, count):
    lines = []
    for _ in range(count):
        w = rng.choice(_LANGS)
        lines.append(f'# {w} {rng.getrandbits(128):032x} '
                     f'{rng.choice(_DECOY_WORDS)}{rng.randint(0, 999)}')
    lines.append(f'# _cfg = {{"mode": "release", "salt": "{rng.getrandbits(64):016x}", '
                 f'"endpoint": "10.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(0,255)}"}}  # legacy')
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# 7. Packer: compile -> marshal -> N chained layers
# --------------------------------------------------------------------------

def pack_payload(code_bytes: bytes, layers: int, rng, bind_fp: bytes = b"",
                 comp_choice="auto", enc_choice="auto"):
    """Returns (final_blob, specs). Specs are outermost-first tuples
    (enc_op, comp_op, seed_hex, bind_flag). comp_choice/enc_choice:
    'auto' (random per layer) or a fixed op from _COMPRESS/_ENCODE keys;
    comp 'none' = identity. Layer keys derive from (seed, machine
    fingerprint) - there is intentionally NO separate integrity check:
    tampering with any byte produces garbage that crashes inside
    decompress/marshal. Nothing to NOP out."""
    blob = code_bytes
    specs = []
    for i in range(layers):
        comp_op = (comp_choice if comp_choice != "auto"
                   else rng.choice(list(_COMPRESS)))
        enc_op = (enc_choice if enc_choice != "auto"
                  else rng.choice(list(_ENCODE)))
        if comp_op == "none":
            comp_op, comp_fn = "n", (lambda b: b)
        else:
            comp_fn = _COMPRESS[comp_op][0]
        seed = rng.getrandbits(128).to_bytes(16, "big")
        fp = bind_fp if (bind_fp and i == 0) else b""
        key = hashlib.sha256(seed + fp).digest()[:16]
        blob = _ENCODE[enc_op][0](rc4(key, comp_fn(blob)))
        specs.insert(0, (enc_op, comp_op, seed.hex(), bool(fp)))
    return blob, specs

# --------------------------------------------------------------------------
# 8. Loader builder (polymorphic self-contained output file)
# --------------------------------------------------------------------------

_RC4_SRC = '''
def %(rc4)s(k, d):
    S = list(range(256))
    j = 0
    k = list(k)
    for i in range(256):
        j = (j + S[i] + k[i %% len(k)]) & 255
        S[i], S[j] = S[j], S[i]
    o = bytearray()
    i = 0
    j = 0
    for c in d:
        i = (i + 1) & 255
        j = (j + S[i]) & 255
        S[i], S[j] = S[j], S[i]
        o.append(c ^ S[(S[i] + S[j]) & 255])
    return bytes(o)
'''

_ADBG_SRC = '''
def %(adbg)s():
    try:
        if %(sys)s.gettrace() is not None:
            %(os)s._exit(%(r1)d)
    except Exception:
        pass
    try:
        if %(cty)s is not None:
            if %(plt)s.system() == "Windows":
                if %(cty)s.windll.kernel32.IsDebuggerPresent():
                    %(os)s._exit(%(r2)d)
            elif %(cty)s.CDLL("libc.so.6").ptrace(0, 0, None, None) == -1:
                %(os)s._exit(%(r3)d)
    except Exception:
        pass
    try:
        _t0 = %(tme)s.perf_counter()
        _s = 0
        for _i in range(20000):
            _s += _i
        if %(tme)s.perf_counter() - _t0 > 0.35:
            %(os)s._exit(%(r4)d)
    except Exception:
        pass
%(adbg)s()
'''


def build_loader(blob, specs, rng, profile, code_hash=None):
    style = profile.get("rename_style", "random")
    while True:
        n = [gen_name(rng, style) for _ in range(20)]
        if len(set(n)) == 20:
            break
    (sysn, marn, hshn, b64n, zlbn, lzmn, tmen, osn, pltn, uidn,
     rc4n, decn, dcpn, adbgn, blobn, specn, fpvn, keyn, mgl, drvn) = n

    fmt = dict(sys=sysn, mar=marn, hsh=hshn, b64=b64n, zlb=zlbn, lzm=lzmn,
               tme=tmen, os=osn, cty="_ct", plt=pltn, uid=uidn, rc4=rc4n,
               dec=decn, dcp=dcpn, adbg=adbgn, blob=blobn, spec=specn,
               fpv=fpvn, key=keyn, mgl=mgl, drv=drvn,
               r1=rng.randint(1, 255), r2=rng.randint(1, 255),
               r3=rng.randint(1, 255), r4=rng.randint(1, 255))

    head = (
        "#!/usr/bin/env python3\n"
        "# -*- coding: utf-8 -*-\n"
        + gen_trash(rng, profile.get("trash", 0))
        + "import sys as " + sysn + "\n"
        + "import marshal as " + marn + "\n"
        + "import hashlib as " + hshn + "\n"
        + "import base64 as " + b64n + "\n"
        + "import zlib as " + zlbn + "\n"
        + "import lzma as " + lzmn + "\n"
        + "import time as " + tmen + "\n"
        + "import os as " + osn + "\n"
        + "import platform as " + pltn + "\n"
        + "try:\n    import ctypes as _ct\nexcept Exception:\n    _ct = None\n"
        + "try:\n    import uuid as " + uidn + "\nexcept Exception:\n    "
        + uidn + " = None\n"
    )

    helpers = (_RC4_SRC % fmt)
    helpers += (
        "\n" + decn + " = {'b85': " + b64n + ".b85decode, 'b64': "
        + b64n + ".b64decode, 'hx': lambda _b: bytes.fromhex(_b.decode())}\n"
        + dcpn + " = {'z': " + zlbn + ".decompress, 'x': " + lzmn
        + ".decompress, 'n': lambda _b: _b}\n"
    )

    prelude = ""
    if profile.get("decoys"):
        prelude += gen_decoy_classes(rng, profile["decoys"], style)
    if profile.get("junk"):
        prelude += gen_junk(rng, style)

    body_core = ""
    k = int(profile.get("chunks", 1) or 1)
    if k > 1 and len(blob) >= k * 2:
        parts = []
        remaining = blob
        for j in range(k):
            if j == k - 1:
                parts.append(remaining)
            else:
                cut = rng.randint(1, len(remaining) - (k - j - 1))
                parts.append(remaining[:cut])
                remaining = remaining[cut:]
        body_core += (blobn + " = b''.join(["
                      + ", ".join(repr(p) for p in parts) + "])\n")
    else:
        body_core += blobn + " = " + repr(blob) + "\n"
    body_core += (specn + " = " + repr([(e, c, s, b) for e, c, s, b in specs])
                  + "\n"
                  + fpvn + " = ((str(" + pltn + ".node()) + '|' + str(" + uidn
                  + ".getnode())).encode() if " + uidn + " is not None else b'')\n")

    variant = rng.randint(0, 2)
    if variant == 0:
        driver = (
            "for _i, (_e, _c, _sd, _bf) in enumerate(" + specn + "):\n"
            "    " + keyn + " = " + hshn + ".sha256(bytes.fromhex(_sd) "
            "+ (" + fpvn + " if _bf else b'')).digest()[:16]\n"
            "    " + blobn + " = " + decn + "[_e](" + blobn + ")\n"
            "    " + blobn + " = " + rc4n + "(" + keyn + ", " + blobn + ")\n"
            "    " + blobn + " = " + dcpn + "[_c](" + blobn + ")\n"
        )
    elif variant == 1:
        driver = (
            "def " + drvn + "(_d, _i):\n"
            "    if _i == len(" + specn + "):\n"
            "        return _d\n"
            "    _e, _c, _sd, _bf = " + specn + "[_i]\n"
            "    " + keyn + " = " + hshn + ".sha256(bytes.fromhex(_sd) "
            "+ (" + fpvn + " if _bf else b'')).digest()[:16]\n"
            "    _d = " + decn + "[_e](_d)\n"
            "    _d = " + rc4n + "(" + keyn + ", _d)\n"
            "    _d = " + dcpn + "[_c](_d)\n"
            "    return " + drvn + "(_d, _i + 1)\n"
            + blobn + " = " + drvn + "(" + blobn + ", 0)\n"
        )
    else:
        driver = (
            "_i = 0\n"
            "while _i < len(" + specn + "):\n"
            "    _e, _c, _sd, _bf = " + specn + "[_i]\n"
            "    " + keyn + " = " + hshn + ".sha256(bytes.fromhex(_sd) "
            "+ (" + fpvn + " if _bf else b'')).digest()[:16]\n"
            "    " + blobn + " = " + dcpn + "[_c](" + rc4n + "(" + keyn + ", "
            + decn + "[_e](" + blobn + ")))\n"
            "    _i += 1\n"
        )

    tail = (
        mgl + " = {'__name__': __name__, '__file__': __file__, "
        "'__package__': __package__, '__builtins__': __builtins__}\n"
        "exec(" + marn + ".loads(" + blobn + "), " + mgl + ")\n"
    )

    if code_hash:
        tail = (keyn + " = " + hshn + ".sha256(" + blobn + ").digest()\n"
                "if " + keyn + " != " + repr(code_hash) + ":\n"
                "    " + osn + "._exit(" + str(rng.randint(1, 255)) + ")\n"
                + tail)
    adbg = _ADBG_SRC % fmt if profile.get("antidebug") else ""
    parts = [head, prelude, helpers, adbg, body_core, driver, tail]
    return "".join(parts)


# --------------------------------------------------------------------------
# 9. Orchestration
# --------------------------------------------------------------------------

def machine_fingerprint() -> bytes:
    import uuid
    return (str(platform.node()) + "|" + str(uuid.getnode())).encode()


def obfuscate_source(src: str, profile: dict, seed=None) -> str:
    rng = random.Random(seed)
    tree = ast.parse(src)
    _attach_parents(tree)
    if profile.get("strip_docs"):
        tree = DocStripper().visit(tree)
    if profile.get("rename"):
        tree = LocalRenamer(rng, profile.get("rename_style", "random")).visit(tree)
    if profile.get("flatten"):
        ControlFlowFlattener._counter = 0
        tree = ControlFlowFlattener().visit(tree)
    if profile.get("numbers"):
        tree = NumberObfuscator(rng).visit(tree)
    if profile.get("strings"):
        tree = StringObfuscator(rng).visit(tree)
    ast.fix_missing_locations(tree)
    code = compile(tree, "<lilfuscated>", "exec")
    bind_fp = machine_fingerprint() if profile.get("bind") else b""
    payload = marshal.dumps(code)
    code_hash = (hashlib.sha256(payload).digest()
                 if profile.get("integrity") else None)
    blob, specs = pack_payload(
        payload, profile["layers"], rng, bind_fp=bind_fp,
        comp_choice=profile.get("comp_choice", "auto"),
        enc_choice=profile.get("enc_choice", "auto"))
    loader = build_loader(blob, specs, rng, profile, code_hash=code_hash)
    compile(loader, "<lilfuscator-output>", "exec")   # validate output
    return loader


def obfuscate_file(inp, outp, profile, seed=None, backup=True):
    with open(inp, "r", encoding="utf-8") as f:
        src = f.read()
    t0 = time.time()
    loader = obfuscate_source(src, profile, seed=seed)
    if backup and os.path.exists(outp):
        shutil.copy2(outp, outp + ".bak")
    with open(outp, "w", encoding="utf-8") as f:
        f.write(loader)
    return dict(input=os.path.abspath(inp), output=os.path.abspath(outp),
                layers=profile["layers"], seconds=round(time.time() - t0, 3),
                out_bytes=len(loader.encode()))


def load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    base = dict(PROFILES[data.get("base", "balanced")])
    base.update({k: v for k, v in data.items() if k != "base"})
    return base


def save_config(path, profile):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(profile, f, indent=2)


def _run_file(path, timeout=30):
    import subprocess
    return subprocess.run([sys.executable, path], capture_output=True,
                          timeout=timeout)


# --------------------------------------------------------------------------
# 10. Built-in self-test
# --------------------------------------------------------------------------

_SELFTEST_SCRIPTS = [
    # f-strings, decorators, closures, generators, kwargs
    '''import functools
def deco(f):
    @functools.wraps(f)
    def w(*a, **k):
        return f(*a, **k) + 1
    return w
@deco
def calc(a, b=10, *args, **kw):
    tot = a + b + sum(args) + sum(kw.values())
    return tot
def gen(n):
    for i in range(n):
        yield i * i
msg = f"res={calc(5, 2, 3, 4, x=7):03d}"
print(msg)
print(list(gen(4)))
def outer():
    c = 0
    def inc():
        nonlocal c
        c += 5
        return c
    return inc() + inc()
print("outer", outer())
''',
    # classes, exceptions, ctx manager, match, dataclass
    '''from dataclasses import dataclass
class Err(Exception): pass
class Ctx:
    def __enter__(self): return self
    def __exit__(self, *a): return False
@dataclass
class Pt:
    x: int
    y: int = 3
def classify(v):
    match v:
        case 0: return "zero"
        case [a, b]: return f"pair {a} {b}"
        case Pt(x=0): return "origin-x"
        case str() as s: return s.upper()
        case _: return "other"
with Ctx():
    print(classify(0), classify([1, 2]), classify(Pt(0)), classify("hi"), classify(9.5))
try:
    raise Err("boom")
except Err as e:
    print("caught", e)
''',
    # numbers, strings, slices, big ints, globals, main guard
    '''import sys
TOTAL = 0
def bump(n):
    global TOTAL
    TOTAL += n
    return TOTAL
def slices():
    data = list(range(20))
    return data[2:15:3], data[::-1][:4], data[-5:]
def big():
    a = 12345678901234567890
    b = -98765432109876543210
    return (a ^ b) % 1000000, a * 3 + b
if __name__ == "__main__":
    bump(41); bump(1)
    print(TOTAL, slices(), big())
    print("hex", hex(255), "argv-len", len(sys.argv))
''',
]


def run_selftest(verbose=True):
    import tempfile
    ok = fail = 0
    for profile_name in ("fast", "balanced", "strong", "paranoid"):
        profile = dict(PROFILES[profile_name])
        for i, src in enumerate(_SELFTEST_SCRIPTS):
            with tempfile.TemporaryDirectory() as td:
                inp = os.path.join(td, "in.py")
                outp = os.path.join(td, "out.py")
                with open(inp, "w") as f:
                    f.write(src)
                try:
                    obfuscate_file(inp, outp, profile, backup=False)
                    r1 = _run_file(inp)
                    r2 = _run_file(outp)
                    same = (r1.returncode == r2.returncode == 0
                            and r1.stdout == r2.stdout)
                    if same:
                        ok += 1
                        if verbose:
                            print(f"  PASS  {profile_name:8s} script{i}")
                    else:
                        fail += 1
                        print(f"  FAIL  {profile_name:8s} script{i} "
                              f"rc={r1.returncode}/{r2.returncode}")
                        print("   orig:", r1.stdout[:200], r1.stderr[-200:])
                        print("   obf :", r2.stdout[:200], r2.stderr[-200:])
                except Exception as e:
                    fail += 1
                    print(f"  ERROR {profile_name:8s} script{i}: {e!r}")
    print(f"\nself-test: {ok} passed, {fail} failed")
    return fail == 0


# --------------------------------------------------------------------------
# 11. CLI + interactive TUI
# --------------------------------------------------------------------------

def _build_arg_parser():
    ap = argparse.ArgumentParser(
        prog="Lilfuscator",
        description="Python source obfuscator: layered packing, AST "
                    "transforms, decoys, polymorphic loaders.")
    ap.add_argument("input", nargs="?", help="input .py file")
    ap.add_argument("output", nargs="?", help="output .py file")
    ap.add_argument("layers", nargs="?", type=int, default=None,
                    help="pack layers 1-12 (default: profile value)")
    ap.add_argument("--profile", choices=list(PROFILES), default=None)
    ap.add_argument("--seed", type=int, default=None,
                    help="reproducible build seed")
    ap.add_argument("--style", choices=["random", "confusable", "hex"],
                    default=None, help="rename style override")
    ap.add_argument("--bind", action="store_true",
                    help="bind outer layer to this machine")
    ap.add_argument("--config", help="load profile from JSON config")
    ap.add_argument("--save-config", metavar="PATH",
                    help="save effective profile as JSON")
    ap.add_argument("--no-backup", action="store_true")
    ap.add_argument("--smoke", action="store_true",
                    help="run output once to verify behavior")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--version", action="version",
                    version=f"Lilfuscator {VERSION}")
    return ap


DEFAULT_PRESERVE = ["__init__", "__main__", "main", "app", "cli"]


class _Session:
    """Holds the interactive-session state (mirrors the 2.x menu spec)."""

    def __init__(self):
        self.profile_name = "balanced"
        self.profile = dict(PROFILES["balanced"])
        self.profile["preserve"] = list(DEFAULT_PRESERVE)
        self.src_path = None
        self.src_text = None
        self.out_path = None

    def custom(self):
        self.profile_name = "custom"


_BANNER = r"""
 ___      _  __                        _
| |   __ | |/ _|__ _ _ __  _ __   ___| |_
| |  / _\| | |_ / _` | '_ \| '_ \ / _ \ __|
| |__| (_) | |  _| (_| | | | | | | |  __/ |_
|_____\___/|_|_|  \__,_|_| |_|_| |_|\___|\__|
"""


def _hr(title=""):
    line = "\u2500" * 58
    return f"\n\u2500\u2500 {title} ".ljust(61, "\u2500") if title else "\n" + line


def _show_state(s):
    p = s.profile
    src = s.src_path or ("<pasted code>" if s.src_text is not None else "<none>")
    out = s.out_path or "<ask at obfuscate time>"
    print(_hr("state"))
    print(f"  profile    : {s.profile_name}")
    print(f"  input      : {src}")
    print(f"  output     : {out}")
    print(f"  layers     : {p['layers']}   rename: {p['rename']} "
          f"({p.get('rename_style','random')})   strings: {p['strings']}")
    print(f"  numbers    : {p['numbers']}   junk: {p['junk']}   "
          f"decoys: {p['decoys']}   trash: {p['trash']}")
    print(f"  anti-debug : {p['antidebug']}   integrity: {p.get('integrity', False)}"
          f"   bind: {p.get('bind', False)}")
    print(f"  compress   : {p.get('comp_choice','auto')}   "
          f"encoding: {p.get('enc_choice','auto')}   "
          f"chunks: {p.get('chunks', 1)}")


def _menu_input():
    return input("key> ").strip()


def _settings_menu(s):
    while True:
        p = s.profile
        print(_hr("settings"))
        rows = [
            ("1",  "Profile",            s.profile_name),
            ("2",  "Layers",             p["layers"]),
            ("3",  "Rename names",       p["rename"]),
            ("4",  "Transform strings",  p["strings"]),
            ("5",  "Compression",        p.get("comp_choice", "auto")),
            ("6",  "Payload chunks",     "on" if p.get("chunks", 1) > 1 else "off"),
            ("7",  "Chunk count",        p.get("chunks", 1)),
            ("8",  "Backup",             p.get("backup_ts", True)),
            ("9",  "Smoke test",         p.get("smoke", False)),
            ("10", "Preserve names",     ",".join(p.get("preserve", []))),
            ("11", "Save config",        "-> lilfuscator.json"),
            ("12", "Load config",        "<- lilfuscator.json"),
            ("13", "Name style",         p.get("rename_style", "random")),
            ("14", "Numbers",            p["numbers"]),
            ("15", "Junk code",          p["junk"]),
            ("16", "Docstrings strip",   p["strip_docs"]),
            ("17", "Anti-debug",         p["antidebug"]),
            ("18", "Integrity check",    p.get("integrity", False)),
            ("19", "Encoding",           p.get("enc_choice", "auto")),
            ("20", "Decoy classes",      p["decoys"]),
            ("21", "Trash output",       p["trash"]),
            ("0",  "Back",               ""),
        ]
        for k, name, val in rows:
            print(f"  [{k:>2}] {name:<20} {val}")
        k = _menu_input()
        if k == "0":
            return
        try:
            if k == "1":
                name = input("profile fast/balanced/strong [balanced]: ").strip() or "balanced"
                s.profile = dict(PROFILES[name])
                s.profile["preserve"] = list(p.get("preserve", DEFAULT_PRESERVE))
                s.profile_name = name
            elif k == "2":
                s.profile["layers"] = max(1, min(12, int(input("layers 1-12: "))))
                s.custom()
            elif k == "3":
                s.profile["rename"] = not p["rename"]; s.custom()
            elif k == "4":
                s.profile["strings"] = not p["strings"]; s.custom()
            elif k == "5":
                c = input("compression auto/zlib/lzma/none [auto]: ").strip() or "auto"
                s.profile["comp_choice"] = {"zlib": "z", "lzma": "x"}.get(c, c)
                s.custom()
            elif k == "6":
                s.profile["chunks"] = 1 if p.get("chunks", 1) > 1 else max(2, p.get("chunks", 4))
                s.custom()
            elif k == "7":
                s.profile["chunks"] = max(2, min(40, int(input("chunks 2-40: "))))
                s.custom()
            elif k == "8":
                s.profile["backup_ts"] = not p.get("backup_ts", True); s.custom()
            elif k == "9":
                s.profile["smoke"] = not p.get("smoke", False); s.custom()
            elif k == "10":
                raw = input("comma-separated names (empty = defaults): ").strip()
                s.profile["preserve"] = ([x.strip() for x in raw.split(",") if x.strip()]
                                         or list(DEFAULT_PRESERVE))
                s.custom()
            elif k == "11":
                save_config("lilfuscator.json", dict(s.profile, base=s.profile_name))
                print("saved -> lilfuscator.json")
            elif k == "12":
                if os.path.exists("lilfuscator.json"):
                    s.profile = load_config("lilfuscator.json")
                    s.profile_name = "custom"
                    print("loaded lilfuscator.json")
                else:
                    print("lilfuscator.json not found")
            elif k == "13":
                st = input("style random/confusable/hex [random]: ").strip() or "random"
                s.profile["rename_style"] = st; s.custom()
            elif k == "14":
                s.profile["numbers"] = not p["numbers"]; s.custom()
            elif k == "15":
                d = int(input("junk density 0-10 [0=off]: ") or 0)
                s.profile["junk"] = max(0, min(10, d)); s.custom()
            elif k == "16":
                s.profile["strip_docs"] = not p["strip_docs"]; s.custom()
            elif k == "17":
                s.profile["antidebug"] = not p["antidebug"]; s.custom()
            elif k == "18":
                s.profile["integrity"] = not p.get("integrity", False); s.custom()
            elif k == "19":
                e = input("encoding auto/b85/b64/hx [auto]: ").strip() or "auto"
                s.profile["enc_choice"] = e; s.custom()
            elif k == "20":
                d = int(input("decoy count 0-10 [0=off]: ") or 0)
                s.profile["decoys"] = max(0, min(10, d)); s.custom()
            elif k == "21":
                d = int(input("trash density 0-10 [0=off]: ") or 0)
                s.profile["trash"] = max(0, min(10, d)); s.custom()
        except ValueError:
            print("invalid value")


def _select_input(s):
    print(_hr("select input"))
    path = input("path to .py file (empty = paste code): ").strip()
    if path:
        if not os.path.exists(path):
            print("file not found:", path)
            return
        s.src_path = path
        s.src_text = None
        if not s.out_path:
            s.out_path = path.rsplit(".py", 1)[0] + "_obf.py"
        print("loaded:", path)
        return
    print("paste code, finish with an empty line, then confirm")
    lines = []
    while True:
        line = input()
        if line == "":
            break
        lines.append(line)
    if input("use this code? [y/N]: ").strip().lower() == "y":
        s.src_text = "\n".join(lines) + "\n"
        s.src_path = None
        print(f"pasted {len(lines)} lines")
    else:
        print("discarded")


def _do_obfuscate(s):
    if s.src_path is None and s.src_text is None:
        print("no input loaded - use [1] first")
        return
    out = s.out_path
    if not out:
        out = input("output file: ").strip()
        if not out:
            print("no output given")
            return
        s.out_path = out
    try:
        if s.src_path:
            info = obfuscate_file(s.src_path, out, s.profile, backup=False)
        else:
            loader = obfuscate_source(s.src_text, s.profile)
            if s.profile.get("backup_ts", True) and os.path.exists(out):
                shutil.copy2(out, out + "." + time.strftime("%Y%m%d-%H%M%S") + ".bak")
            with open(out, "w", encoding="utf-8") as f:
                f.write(loader)
            info = dict(output=out, out_bytes=len(loader.encode()),
                        layers=s.profile["layers"], seconds=0)
        if s.profile.get("backup_ts", True) and s.src_path and os.path.exists(out):
            pass  # file mode wrote directly; backup handled below
        print(f"done: {info['out_bytes']} bytes, {info['layers']} layers -> {info['output']}")
        if s.profile.get("smoke", False):
            r = _run_file(out)
            print(f"smoke: rc={r.returncode}")
            if r.stdout:
                print(r.stdout.decode(errors="replace"))
    except Exception as e:
        print("obfuscate failed:", repr(e))


def tui():
    print(_BANNER)
    print(f"Lilfuscator {VERSION} - interactive mode")
    s = _Session()
    while True:
        _show_state(s)
        print(_hr("main menu"))
        for k, name, desc in [
            ("1", "Select input", "load a .py file or paste code directly"),
            ("2", "Settings",     "configuration menu"),
            ("3", "Obfuscate",    "run and write the output file"),
            ("4", "Save config",  "write settings to lilfuscator.json"),
            ("5", "Load config",  "read settings from lilfuscator.json"),
            ("0", "Exit",         "quit"),
        ]:
            print(f"  [{k}] {name:<14} {desc}")
        k = _menu_input()
        if k == "0":
            return 0
        if k == "1":
            _select_input(s)
        elif k == "2":
            _settings_menu(s)
        elif k == "3":
            _do_obfuscate(s)
        elif k == "4":
            save_config("lilfuscator.json", dict(s.profile, base=s.profile_name))
            print("saved -> lilfuscator.json")
        elif k == "5":
            if os.path.exists("lilfuscator.json"):
                s.profile = load_config("lilfuscator.json")
                s.profile_name = "custom"
                print("loaded lilfuscator.json")
            else:
                print("lilfuscator.json not found")


def main(argv=None):
    args = _build_arg_parser().parse_args(argv)
    if args.selftest:
        return 0 if run_selftest() else 1
    if args.input is None:
        return tui()
    if args.config:
        profile = load_config(args.config)
    else:
        profile = dict(PROFILES[args.profile or "balanced"])
    if args.layers is not None:
        profile["layers"] = max(1, min(12, args.layers))
    if args.style:
        profile["rename_style"] = args.style
    if args.bind:
        profile["bind"] = True
    info = obfuscate_file(args.input, args.output, profile, seed=args.seed,
                          backup=not args.no_backup)
    print(f"[+] {info['input']}")
    print(f"[+] -> {info['output']}  ({info['out_bytes']} bytes, "
          f"{info['layers']} layers, {info['seconds']}s)")
    if args.save_config:
        save_config(args.save_config, profile)
        print(f"[+] config saved -> {args.save_config}")
    if args.smoke:
        r = _run_file(args.output)
        print(f"[+] smoke run: rc={r.returncode}")
        if r.stdout:
            print(r.stdout.decode(errors="replace"))
        if r.returncode != 0:
            print(r.stderr.decode(errors="replace")[-800:])
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
