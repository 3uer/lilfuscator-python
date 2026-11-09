#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Lilfuscator v2.1.0
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

VERSION = "2.1.0"

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

    def __init__(self, rng, style="random"):
        self.rng = rng
        self.style = style

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

def pack_payload(code_bytes: bytes, layers: int, rng, bind_fp: bytes = b""):
    """Returns (final_blob, specs). Specs are outermost-first tuples
    (enc_op, comp_op, seed_hex, bind_flag). Layer keys derive from
    (seed, layer index, machine fingerprint) - there is intentionally NO
    separate integrity check: tampering with any byte produces garbage
    that crashes inside decompress/marshal. Nothing to NOP out."""
    blob = code_bytes
    specs = []
    for i in range(layers):
        comp_op = rng.choice(list(_COMPRESS))
        enc_op = rng.choice(list(_ENCODE))
        seed = rng.getrandbits(128).to_bytes(16, "big")
        fp = bind_fp if (bind_fp and i == 0) else b""
        key = hashlib.sha256(seed + fp).digest()[:16]
        blob = _ENCODE[enc_op][0](rc4(key, _COMPRESS[comp_op][0](blob)))
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


def build_loader(blob, specs, rng, profile):
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
        + dcpn + " = {'z': " + zlbn + ".decompress, 'x': " + lzmn + ".decompress}\n"
    )

    prelude = ""
    if profile.get("decoys"):
        prelude += gen_decoy_classes(rng, profile["decoys"], style)
    if profile.get("junk"):
        prelude += gen_junk(rng, style)

    body_core = (
        blobn + " = " + repr(blob) + "\n"
        + specn + " = " + repr([(e, c, s, b) for e, c, s, b in specs]) + "\n"
        + fpvn + " = ((str(" + pltn + ".node()) + '|' + str(" + uidn
        + ".getnode())).encode() if " + uidn + " is not None else b'')\n"
    )

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
    blob, specs = pack_payload(marshal.dumps(code), profile["layers"], rng,
                               bind_fp=bind_fp)
    loader = build_loader(blob, specs, rng, profile)
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


def tui():
    print(f"Lilfuscator {VERSION} - interactive mode")
    print("Empty input at any prompt keeps the default.\n")
    inp = input("input file: ").strip()
    if not inp:
        print("no input given, exiting")
        return 2
    outp = input(f"output file [{inp.rsplit('.py',1)[0]}_obf.py]: ").strip()
    if not outp:
        outp = inp.rsplit(".py", 1)[0] + "_obf.py"
    print("profiles: " + ", ".join(PROFILES))
    prof_name = input("profile [balanced]: ").strip() or "balanced"
    profile = dict(PROFILES.get(prof_name, PROFILES["balanced"]))
    lv = input(f"layers 1-12 [{profile['layers']}]: ").strip()
    if lv:
        profile["layers"] = max(1, min(12, int(lv)))
    seed_in = input("seed [random]: ").strip()
    seed = int(seed_in) if seed_in else None
    info = obfuscate_file(inp, outp, profile, seed=seed)
    print(f"\ndone: {info['out_bytes']} bytes, {info['layers']} layers, "
          f"{info['seconds']}s -> {info['output']}")
    return 0


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
