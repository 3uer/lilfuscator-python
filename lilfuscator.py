#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Lilfuscator — Super Duper Edition

Features:
- File or terminal input
- Fast / Balanced / Strong / Custom profiles
- Configurable packing layers
- Identifier renaming (random / confusable / hex styles)
- String transformation (chr-join, reverse, hex-escape)
- Number obfuscation
- Junk code injection with opaque predicates
- Docstring stripping
- Compression (zlib / lzma)
- Randomized payload chunking
- Multiple payload encodings (base85 / base64 / hex)
- Anti-debug stub
- Integrity check (sha256)
- Preserve-name list
- Output backup
- Syntax validation
- Optional smoke test
- JSON configuration save/load
- CLI mode
"""

from __future__ import annotations

import ast
import base64
import hashlib
import importlib.util
import json
import keyword
import lzma
import marshal
import os
from pathlib import Path
import random
import shutil
import string
import subprocess
import sys
import time
import zlib

# ═════════════════════════════════════════════════════════════════════════════
# THEME
# ═════════════════════════════════════════════════════════════════════════════

R = "\033[0m"
B = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
YELLOW = "\033[93m"
WHITE = "\033[97m"
GRAY = "\033[90m"

def c(text: str, color: str) -> str:
    return f"{color}{text}{R}"

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def pause():
    try:
        input(c("\nPress Enter to continue...", YELLOW))
    except (EOFError, KeyboardInterrupt):
        pass

def banner():
    print(c("╔══════════════════════════════════════════════════════════════╗", RED))
    print(c("║", RED) + c("                      LILFUSCATOR", YELLOW) + c("                      ║", RED))
    print(c("║", RED) + c("        AST • PACKING • STRINGS • CONFIG • VALIDATION", WHITE) + c("        ║", RED))
    print(c("╚══════════════════════════════════════════════════════════════╝", RED))

# ═════════════════════════════════════════════════════════════════════════════
# OPTIONAL DEPENDENCY BOOTSTRAP
# ═════════════════════════════════════════════════════════════════════════════

OPTIONAL_PACKAGES: list[str] = []

def ensure_packages():
    missing = []
    for package in OPTIONAL_PACKAGES:
        module = package.replace("-", "_")
        if importlib.util.find_spec(module) is None:
            missing.append(package)

    if not missing:
        return True

    print(c("\nMissing optional packages:", YELLOW), ", ".join(missing))
    ans = input(c("Install automatically with pip? [Y/n]: ", YELLOW)).strip().lower()
    if ans not in ("", "y", "yes"):
        print(c("Installation skipped.", RED))
        return False

    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", *missing])
        print(c("✓ Packages installed.", YELLOW))
        return True
    except subprocess.CalledProcessError as exc:
        print(c(f"✗ pip failed: {exc}", RED))
        return False

# ═════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

DEFAULTS = {
    "profile": "balanced",
    "layers": 3,
    "rename_identifiers": True,
    "name_style": "random",          # random / confusable / hex
    "transform_strings": True,
    "obfuscate_numbers": True,
    "junk_code": True,
    "junk_density": 3,               # junk blocks per body, approx
    "junk_classes": True,            # dead decoy classes with unicode/中文 text
    "junk_class_count": 3,
    "strip_docstrings": True,
    "compress": True,
    "compressor": "zlib",            # zlib / lzma
    "chunk_payload": True,
    "chunk_count": 12,
    "encoding": "auto",              # auto / b85 / b64 / hex
    "anti_debug": False,
    "integrity_check": True,
    "trash_output": True,
    "trash_density": 5,              # junk lines per real line, percent x10
    "random_seed": True,
    "backup": True,
    "smoke_test": True,
    "preserve": [
        "__init__", "__main__", "__version__", "__all__",
        "main", "app", "cli"
    ],
}

PROFILES = {
    "fast": {
        "layers": 1,
        "rename_identifiers": False,
        "transform_strings": False,
        "obfuscate_numbers": False,
        "junk_code": False,
        "junk_classes": False,
        "compress": True,
        "chunk_payload": False,
        "chunk_count": 6,
        "anti_debug": False,
        "integrity_check": False,
        "trash_output": False,
    },
    "balanced": {
        "layers": 3,
        "rename_identifiers": True,
        "transform_strings": True,
        "obfuscate_numbers": True,
        "junk_code": True,
        "junk_density": 3,
        "junk_classes": True,
        "junk_class_count": 2,
        "compress": True,
        "chunk_payload": True,
        "chunk_count": 12,
        "anti_debug": False,
        "integrity_check": True,
        "trash_output": True,
        "trash_density": 3,
    },
    "strong": {
        "layers": 5,
        "rename_identifiers": True,
        "name_style": "confusable",
        "transform_strings": True,
        "obfuscate_numbers": True,
        "junk_code": True,
        "junk_density": 6,
        "junk_classes": True,
        "junk_class_count": 5,
        "compress": True,
        "compressor": "lzma",
        "chunk_payload": True,
        "chunk_count": 18,
        "anti_debug": True,
        "integrity_check": True,
        "trash_output": True,
        "trash_density": 6,
    },
}

def new_config():
    cfg = dict(DEFAULTS)
    cfg["preserve"] = list(DEFAULTS["preserve"])
    return cfg

def apply_profile(cfg, profile):
    if profile not in PROFILES:
        raise ValueError("Unknown profile")
    cfg["profile"] = profile
    cfg.update(PROFILES[profile])

def save_config(cfg, path="lilfuscator.json"):
    clean = {k: v for k, v in cfg.items() if not k.startswith("_")}
    Path(path).write_text(json.dumps(clean, indent=2, ensure_ascii=False), encoding="utf-8")

def load_config(path="lilfuscator.json"):
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(path)
    cfg = new_config()
    cfg.update(json.loads(p.read_text(encoding="utf-8")))
    return cfg

# ═════════════════════════════════════════════════════════════════════════════
# OBFUSCATION ENGINE
# ═════════════════════════════════════════════════════════════════════════════

RESERVED = set(keyword.kwlist) | {
    "self", "cls", "__name__", "__file__", "__package__", "__loader__",
    "__spec__", "__builtins__", "__cached__", "__annotations__"
}

import builtins as _builtins_mod
BUILTIN_NAMES = set(dir(_builtins_mod))

def rand_name(n=12, style="random"):
    if style == "confusable":
        alphabet = "O0Il1"
        return "_" + "".join(random.choice(alphabet) for _ in range(n))
    if style == "hex":
        return "_x" + "".join(random.choice("0123456789abcdef") for _ in range(n))
    return "_" + "".join(random.choice(string.ascii_letters) for _ in range(n))

def xor_bytes(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

class ConservativeRenamer(ast.NodeTransformer):
    """Renames local names AND their definitions consistently.

    Fixes the 5.1 bug where call sites were renamed but function/class
    definitions were not, producing broken output.
    """
    def __init__(self, preserve, style="random"):
        self.preserve = set(preserve)
        self.style = style
        self.mapping = {}
        self._class_depth = 0
        self.local_funcs = set()   # names of functions defined in this module

    def collect_local_funcs(self, tree):
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and self.allowed(n.name):
                self.local_funcs.add(n.name)

    def allowed(self, name):
        return (
            isinstance(name, str)
            and name not in RESERVED
            and name not in BUILTIN_NAMES
            and name not in self.preserve
            and not name.startswith("_")
        )

    def rename(self, name):
        if not self.allowed(name):
            return name
        if name not in self.mapping:
            self.mapping[name] = rand_name(random.randint(8, 15), self.style)
        return self.mapping[name]

    def visit_Name(self, node):
        node.id = self.rename(node.id)
        return node

    def visit_arg(self, node):
        node.arg = self.rename(node.arg)
        return node

    def _visit_func(self, node):
        is_method = self._class_depth > 0
        if not is_method:
            node.name = self.rename(node.name)
        if is_method:
            # Method params may be used as kwargs via attribute calls we cannot
            # resolve (obj.method(param=...)), so keep param names AND their
            # use sites intact while visiting this method.
            params = [a.arg for a in node.args.posonlyargs + node.args.args
                      + node.args.kwonlyargs]
            params += [a.arg for a in (node.args.vararg, node.args.kwarg) if a]
            self.preserve.update(params)
            self.generic_visit(node)
            for p in params:
                self.preserve.discard(p)
            return node
        return self.generic_visit(node)

    def visit_FunctionDef(self, node):
        return self._visit_func(node)

    def visit_AsyncFunctionDef(self, node):
        return self._visit_func(node)

    def visit_ClassDef(self, node):
        node.name = self.rename(node.name)
        self._class_depth += 1
        self.generic_visit(node)
        self._class_depth -= 1
        return node

    def visit_ExceptHandler(self, node):
        if node.name:
            node.name = self.rename(node.name)
        return self.generic_visit(node)

    def visit_Global(self, node):
        node.names = [self.rename(n) for n in node.names]
        return node

    def visit_Nonlocal(self, node):
        node.names = [self.rename(n) for n in node.names]
        return node

    def visit_keyword(self, node):
        # Do not rename bare keyword args here; handled in visit_Call.
        node.value = self.visit(node.value)
        return node

    def visit_Call(self, node):
        node.func = self.visit(node.func)
        for a in node.args:
            self.visit(a)
        # Only rename kwargs when calling a function defined in this module —
        # renaming kwargs of library/builtin calls would break them.
        rename_kwargs = (
            isinstance(node.func, ast.Name)
            and node.func.id in {self.mapping.get(f, f) for f in self.local_funcs}
        )
        for kw in node.keywords:
            if rename_kwargs and kw.arg is not None:
                kw.arg = self.rename(kw.arg)
            kw.value = self.visit(kw.value)
        return node

    def visit_Attribute(self, node):
        node.value = self.visit(node.value)
        return node

    def visit_alias(self, node):
        return node

class DocstringStripper(ast.NodeTransformer):
    def _strip(self, node):
        self.generic_visit(node)
        body = getattr(node, "body", None)
        if (body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            node.body = node.body[1:] or [ast.Pass()]
        return node

    visit_Module = _strip
    visit_FunctionDef = _strip
    visit_AsyncFunctionDef = _strip
    visit_ClassDef = _strip

class NumberObfuscator(ast.NodeTransformer):
    """Rewrites int constants (>= 10) as (a ^ b) with a ^ b == value."""
    def __init__(self, enabled=True, probability=0.65):
        self.enabled = enabled
        self.probability = probability

    def visit_Constant(self, node):
        if (not self.enabled or not isinstance(node.value, int)
                or isinstance(node.value, bool)):
            return node
        v = node.value
        if abs(v) < 10 or random.random() > self.probability:
            return node
        mask = random.randint(1, 0xFFFFFFFF)
        expr = ast.BinOp(
            left=ast.Constant(value=v ^ mask),
            op=ast.BitXor(),
            right=ast.Constant(value=mask),
        )
        return ast.copy_location(expr, node)

class StringTransformer(ast.NodeTransformer):
    def __init__(self, enabled=True, probability=0.70):
        self.enabled = enabled
        self.probability = probability

    def _chr_join(self, value):
        chars = [
            ast.Call(
                func=ast.Name(id="chr", ctx=ast.Load()),
                args=[ast.Constant(value=ord(ch))],
                keywords=[]
            )
            for ch in value
        ]
        return ast.Call(
            func=ast.Attribute(
                value=ast.Constant(value=""),
                attr="join",
                ctx=ast.Load(),
            ),
            args=[ast.List(elts=chars, ctx=ast.Load())],
            keywords=[],
        )

    def _reversed(self, value):
        return ast.Subscript(
            value=ast.Constant(value=value[::-1]),
            slice=ast.Slice(lower=None, upper=None,
                            step=ast.Constant(value=-1)),
            ctx=ast.Load(),
        )

    def visit_JoinedStr(self, node):
        # f-string literal segments must stay plain constants; only visit
        # the interpolated expressions.
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                self.visit(value)
        return node

    def _hex_escapes(self, value):
        return ast.Call(
            func=ast.Attribute(
                value=ast.Call(
                    func=ast.Attribute(
                        value=ast.Name(id="bytes", ctx=ast.Load()),
                        attr="fromhex",
                        ctx=ast.Load(),
                    ),
                    args=[ast.Constant(value=value.encode("utf-8").hex())],
                    keywords=[],
                ),
                attr="decode",
                ctx=ast.Load(),
            ),
            args=[],
            keywords=[],
        )

    def visit_Constant(self, node):
        if not self.enabled or not isinstance(node.value, str):
            return node
        if not node.value or random.random() > self.probability:
            return node
        try:
            node.value.encode("ascii")
            ascii_only = True
        except UnicodeEncodeError:
            ascii_only = False

        choices = ["chr_join", "reversed", "hex"]
        mode = random.choice(choices)

        if mode == "reversed":
            expr = self._reversed(node.value)
        elif mode == "hex":
            expr = self._hex_escapes(node.value)
        else:
            expr = self._chr_join(node.value)
        return ast.copy_location(expr, node)

class JunkInjector(ast.NodeTransformer):
    """Inserts dead code guarded by opaque predicates that never trigger."""
    def __init__(self, density=3):
        self.density = max(0, int(density))

    def _false_predicate(self):
        n = rand_name(6, "hex")
        v = random.randint(2, 999)
        # (v ^ v) != 0  → always False, but not obvious statically
        return ast.Compare(
            left=ast.BinOp(left=ast.Constant(value=v), op=ast.BitXor(),
                           right=ast.Constant(value=v)),
            ops=[ast.NotEq()],
            comparators=[ast.Constant(value=0)],
        )

    def _junk_stmt(self):
        name = rand_name(random.randint(8, 14))
        kind = random.randint(0, 2)
        if kind == 0:
            return ast.Assign(
                targets=[ast.Name(id=name, ctx=ast.Store())],
                value=ast.Constant(value=rand_name(16)),
            )
        if kind == 1:
            return ast.Assign(
                targets=[ast.Name(id=name, ctx=ast.Store())],
                value=ast.BinOp(
                    left=ast.Constant(value=random.randint(1, 10**6)),
                    op=ast.Mult(),
                    right=ast.Constant(value=random.randint(1, 10**6)),
                ),
            )
        return ast.Expr(value=ast.Call(
            func=ast.Name(id="print", ctx=ast.Load()),
            args=[ast.Constant(value=rand_name(20))],
            keywords=[],
        ))

    def _inject(self, body):
        if not body or self.density <= 0:
            return body
        out = list(body)
        for _ in range(min(self.density, max(1, len(body)))):
            idx = random.randint(0, len(out))
            dead = ast.If(
                test=self._false_predicate(),
                body=[self._junk_stmt() for _ in range(random.randint(1, 3))],
                orelse=[],
            )
            out.insert(idx, dead)
        return out

    def visit_Module(self, node):
        self.generic_visit(node)
        node.body = self._inject(node.body)
        return node

    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        node.body = self._inject(node.body)
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

# ── Decoy (junk) class generator ─────────────────────────────────────────────
# Dead, never-referenced classes that look like a real part of the program:
# Chinese docstrings/comments-as-strings, unicode identifiers, fake caching /
# validation / pipeline logic. Built as source and parsed back into the AST.

_CN_WORDS = (
    "数据", "处理", "缓存", "验证", "配置", "加载", "模块", "管理", "任务",
    "队列", "状态", "同步", "解析", "编码", "加密", "压缩", "日志", "监控",
    "网络", "请求", "响应", "用户", "权限", "数据库", "索引", "事务", "备份",
)

_CN_PHRASES = (
    "初始化内部缓存管理器，请勿直接调用",
    "该模块由构建系统自动生成，修改可能导致不可预知的行为",
    "数据完整性校验失败，回滚到上一个稳定状态",
    "异步任务队列已就绪，等待调度器信号",
    "配置项缺失，使用默认值继续执行",
    "警告：检测到未注册的回调函数",
    "性能分析：当前批次处理耗时超过阈值",
    "内部状态已同步，版本号递增",
    "安全策略要求每24小时轮换一次密钥",
    "加载插件描述符……完成",
)

_CLASS_FLAVORS = ["Cache", "Validator", "Pipeline", "Registry", "Manager",
                  "Scheduler", "Serializer", "Coordinator", "Monitor", "Handler"]

def _cn_text(min_words=2, max_words=5):
    return "，".join(random.choice(_CN_WORDS + _CN_PHRASES)
                     for _ in range(random.randint(min_words, max_words)))

def _cn_ident():
    return random.choice(_CN_WORDS) + str(random.randint(1, 99))

def gen_decoy_class(idx):
    flavor = random.choice(_CLASS_FLAVORS)
    cls = f"_{flavor}{rand_name(6)}"
    cache = _cn_ident()
    param = _cn_ident()
    key = _cn_ident()
    n1, n2 = random.randint(100, 9999), random.randint(2, 97)
    methods = []

    # __init__ with fake state
    methods.append(
        f'    def __init__(self):\n'
        f'        self.{cache} = {{}}\n'
        f'        self._version = {n1}\n'
        f'        self._标记 = "{_cn_text()}"'
    )
    # fake getter with unicode param + validation-looking logic
    methods.append(
        f'    def _读取(self, {param}):\n'
        f'        """{_cn_text(1, 2)}。"""\n'
        f'        if {param} in self.{cache}:\n'
        f'            return self.{cache}[{param}]\n'
        f'        {key} = (hash(str({param})) ^ {n1}) % {n2}\n'
        f'        self.{cache}[{param}] = {key}\n'
        f'        return {key}'
    )
    # fake batch processor
    methods.append(
        f'    def _批量处理(self, 条目):\n'
        f'        """{_cn_text(1, 2)}。"""\n'
        f'        结果 = []\n'
        f'        for 项 in 条目:\n'
        f'            try:\n'
        f'                结果.append(self._读取(项) * {random.randint(2, 9)})\n'
        f'            except Exception:\n'
        f'                结果.append(None)  # {_cn_text(1, 1)}\n'
        f'        return 结果'
    )
    # fake report method
    methods.append(
        f'    def _报告(self):\n'
        f'        return {{"状态": "{random.choice(_CN_WORDS)}", '
        f'"数量": len(self.{cache}), "版本": self._version}}'
    )

    body = "\n\n".join(methods)
    return (
        f'class {cls}:\n'
        f'    """{_cn_text(2, 3)}。"""\n\n'
        f'{body}\n\n\n'
        f'{cls.lower()}_实例 = {cls}()  # {_cn_text(1, 1)}\n'
    )

class DecoyClassInjector:
    """Injects never-referenced decoy classes into the module body."""
    def __init__(self, count=3):
        self.count = max(0, int(count))

    def inject(self, tree):
        if self.count <= 0:
            return tree
        src = "\n".join(gen_decoy_class(i) for i in range(self.count))
        decoys = ast.parse(src).body
        # keep each class paired with its instance assignment (class first)
        pairs = [(decoys[i], decoys[i + 1])
                 for i in range(0, len(decoys) - 1, 2)]
        for cls_node, inst_node in pairs:
            idx = random.randint(1, len(tree.body))  # keep position 0 for __future__/imports
            tree.body.insert(idx, cls_node)
            tree.body.insert(idx + 1, inst_node)
        return tree

def transform_source(source, cfg):
    tree = ast.parse(source, filename="<input>", mode="exec")

    if cfg.get("strip_docstrings", True):
        tree = DocstringStripper().visit(tree)

    if cfg["rename_identifiers"]:
        # Names bound by imports must never be renamed (the import statement
        # itself stays intact), so preserve them.
        preserve = set(cfg["preserve"])
        for n in ast.walk(tree):
            if isinstance(n, (ast.Import, ast.ImportFrom)):
                for alias in n.names:
                    preserve.add(alias.asname or alias.name.split(".")[0])
        renamer = ConservativeRenamer(list(preserve), cfg.get("name_style", "random"))
        renamer.collect_local_funcs(tree)
        tree = renamer.visit(tree)

    tree = NumberObfuscator(enabled=cfg.get("obfuscate_numbers", False)).visit(tree)

    tree = StringTransformer(enabled=cfg["transform_strings"]).visit(tree)

    if cfg.get("junk_code", False):
        tree = JunkInjector(cfg.get("junk_density", 3)).visit(tree)

    if cfg.get("junk_classes", False):
        tree = DecoyClassInjector(cfg.get("junk_class_count", 3)).inject(tree)

    ast.fix_missing_locations(tree)
    return ast.unparse(tree)

# ── Payload encoding ─────────────────────────────────────────────────────────

def pick_encoding(cfg):
    enc = cfg.get("encoding", "auto")
    if enc == "auto":
        enc = random.choice(["b85", "b64", "hex"])
    return enc if enc in ("b85", "b64", "hex") else "b85"

def encode_raw(data, enc):
    if enc == "hex":
        return data.hex()
    if enc == "b64":
        return base64.b64encode(data).decode("ascii")
    return base64.b85encode(data).decode("ascii")

def decode_expr(var, enc):
    if enc == "hex":
        return f"bytes.fromhex({var})"
    if enc == "b64":
        return f"_ob_b64.b64decode({var})"
    return f"_ob_b64.b85decode({var})"

def compress_data(data, cfg):
    if not cfg["compress"]:
        return data
    if cfg.get("compressor") == "lzma":
        return lzma.compress(data, preset=9)
    return zlib.compress(data, 9)

def encode_payload(data, key, cfg):
    enc = pick_encoding(cfg)
    return encode_raw(xor_bytes(compress_data(data, cfg), key), enc), enc

def chunk_string(text, count):
    if not text or count <= 1:
        return [text]
    count = min(count, len(text))
    if count <= 1:
        return [text]
    cuts = sorted(random.sample(range(1, len(text)), count - 1))
    parts = []
    start = 0
    for cut in cuts:
        parts.append(text[start:cut])
        start = cut
    parts.append(text[start:])
    return parts

def loader(payload, enc, key_b85, layer, total, cfg):
    # Re-encode under the chosen encoding so decoder matches.
    # payload/key arrive b85-encoded; normalize.
    data_parts = (
        chunk_string(payload, max(2, cfg["chunk_count"]))
        if cfg["chunk_payload"]
        else [payload]
    )
    data_vars = [rand_name(style=cfg.get("name_style", "random")) for _ in data_parts]

    key_parts = chunk_string(key_b85, 4 if cfg["chunk_payload"] else 1)
    key_vars = [rand_name(10, cfg.get("name_style", "random")) for _ in key_parts]

    a, b, d, e = [rand_name(style=cfg.get("name_style", "random")) for _ in range(4)]

    lines = [
        f"# protected layer {layer}/{total}",
        "import base64 as _ob_b64",
        "import zlib as _ob_zlib",
        "import lzma as _ob_lzma",
        "import marshal as _ob_marshal",
        "import hashlib as _ob_hash",
        "",
    ]

    if cfg.get("anti_debug"):
        lines += [
            "import sys as _ob_sys",
            "if _ob_sys.gettrace() is not None:",
            "    raise SystemExit('debugging detected')",
            "",
        ]

    for name, value in zip(data_vars, data_parts):
        lines.append(f"{name} = {value!r}")

    for name, value in zip(key_vars, key_parts):
        lines.append(f"{name} = {value!r}")

    lines += [
        "",
        f"{a} = ''.join([{', '.join(data_vars)}])",
        f"{b} = {decode_expr(a, enc)}",
        f"{d} = ''.join([{', '.join(key_vars)}])",
        f"{e} = _ob_b64.b85decode({d})",
        f"_ob_data = bytes(x ^ {e}[i % len({e})] for i, x in enumerate({b}))",
    ]

    if cfg["compress"]:
        if cfg.get("compressor") == "lzma":
            lines.append("_ob_data = _ob_lzma.decompress(_ob_data)")
        else:
            lines.append("_ob_data = _ob_zlib.decompress(_ob_data)")

    lines += [
        "_ob_code = _ob_marshal.loads(_ob_data)",
        "exec(_ob_code, globals(), globals())",
    ]
    return "\n".join(lines)


# ── Output trasher ───────────────────────────────────────────────────────────
# Trashes the FINAL packed file: Chinese comments, dead assignments, fake
# configs and decoy classes interleaved between loader lines, so the visible
# file itself looks like pure garbage.

_TRASH_STRINGS = [
    "临时文件，请勿删除", "系统自动生成", "内部测试版本", "调试信息",
    "deprecated since 2.3", "TODO: refactor later", "legacy compat shim",
    "do not touch", "autogenerated by build pipeline", "内部缓存句柄",
    "権限チェック", "모듈 초기화", "zwischenstand", "временный буфер",
]

def _trash_line():
    kind = random.randint(0, 4)
    name = rand_name(random.randint(8, 16))
    if kind == 0:
        return f"# {random.choice(_TRASH_STRINGS)} | {_cn_text(1, 2)}"
    if kind == 1:
        junk = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789+/=_-", k=random.randint(40, 120)))
        return f"{name} = '{junk}'"
    if kind == 2:
        return (f"{name} = {{'模式': '{random.choice(_CN_WORDS)}', 'flags': "
                f"[{', '.join(str(random.randint(0, 255)) for _ in range(random.randint(3, 7)))}], "
                f"'enabled': {random.choice(['True', 'False'])}}}")
    if kind == 3:
        return f"# {'=' * random.randint(20, 55)}"
    return f"{name} = ({random.randint(1000, 999999)} ^ {random.randint(1000, 999999)})"

def trashify(source, cfg):
    if not cfg.get("trash_output", False):
        return source
    density = max(1, int(cfg.get("trash_density", 5)))
    lines = source.splitlines()
    out = []
    prev_indented = False
    for i, line in enumerate(lines):
        indented = line[:1] in (" ", "\t")
        # keep shebang/header first; never insert between a block opener and its body
        if i >= 2 and not indented and not prev_indented:
            for _ in range(random.randint(0, density)):
                out.append(_trash_line())
            if random.random() < 0.06:
                out.append(gen_decoy_class(0).rstrip())
        out.append(line)
        prev_indented = indented
    for _ in range(random.randint(3, 8)):
        out.append(_trash_line())
    if random.random() < 0.5:
        out.append(gen_decoy_class(0).rstrip())
    return "\n".join(out) + "\n"

def obfuscate(source, cfg):
    if not source.strip():
        raise ValueError("Input source is empty.")

    compile(source, "<input>", "exec")
    transformed = transform_source(source, cfg)
    compile(transformed, "<transformed>", "exec")

    current = marshal.dumps(compile(transformed, "<protected>", "exec"))
    total = int(cfg["layers"])

    for layer in range(total, 0, -1):
        key = os.urandom(48 if layer == 1 else 32)
        encoded, enc = encode_payload(current, key, cfg)
        layer_source = loader(
            encoded,
            enc,
            base64.b85encode(key).decode("ascii"),
            layer,
            total,
            cfg,
        )
        compile(layer_source, f"<layer{layer}>", "exec")
        if layer > 1:
            # deeper layers expect a marshalled code object as payload
            current = marshal.dumps(compile(layer_source, f"<layer{layer}>", "exec"))
        else:
            current = layer_source.encode("utf-8")

    # Optional integrity wrapper: verify the final source hash before exec.
    if cfg.get("integrity_check"):
        digest = hashlib.sha256(current).hexdigest()
        current = (
            "import hashlib as _ob_h\n"
            f"_ob_src = {current.decode('utf-8')!r}\n"
            f"assert _ob_h.sha256(_ob_src.encode()).hexdigest() == {digest!r}, 'tampered'\n"
            "exec(_ob_src)\n"
        ).encode("utf-8")

    result = "#!/usr/bin/env python3\n# LILFUSCATOR OUTPUT\n" + current.decode()
    result = trashify(result, cfg)
    compile(result, "<generated>", "exec")
    return result

# ═════════════════════════════════════════════════════════════════════════════
# FILE OPERATIONS
# ═════════════════════════════════════════════════════════════════════════════

def smoke_test(path):
    try:
        source = Path(path).read_text(encoding="utf-8")
        compile(source, str(path), "exec")
        return True, "syntax OK"
    except Exception as exc:
        return False, str(exc)

def runtime_test(path, timeout=15):
    """Actually execute the obfuscated file and check it exits cleanly."""
    try:
        proc = subprocess.run(
            [sys.executable, str(path)],
            capture_output=True, timeout=timeout,
        )
        if proc.returncode == 0:
            return True, "runtime OK"
        return False, proc.stderr.decode("utf-8", "replace")[-400:]
    except subprocess.TimeoutExpired:
        return True, "runtime OK (timeout, likely interactive)"
    except Exception as exc:
        return False, str(exc)

def write_output(source, output, backup=True):
    output = Path(output).expanduser()

    if backup and output.exists():
        stamp = time.strftime("%Y%m%d_%H%M%S")
        backup_path = output.with_name(output.name + f".{stamp}.bak")
        shutil.copy2(output, backup_path)

    output.write_text(source, encoding="utf-8")
    return output

# ═════════════════════════════════════════════════════════════════════════════
# INTERACTIVE UI
# ═════════════════════════════════════════════════════════════════════════════

def toggle(cfg, key, title):
    cfg[key] = not bool(cfg[key])
    print(c(f"{title}: {'ON' if cfg[key] else 'OFF'}", YELLOW))

def settings_menu(cfg):
    while True:
        clear()
        banner()
        print(c("\nCONFIGURATION\n", YELLOW))
        print(f"{c('[1]', YELLOW)} Profile          : {cfg['profile']}")
        print(f"{c('[2]', YELLOW)} Layers           : {cfg['layers']}")
        print(f"{c('[3]', YELLOW)} Rename names     : {cfg['rename_identifiers']}")
        print(f"{c('[4]', YELLOW)} Transform strings: {cfg['transform_strings']}")
        print(f"{c('[5]', YELLOW)} Compression      : {cfg['compress']} ({cfg.get('compressor', 'zlib')})")
        print(f"{c('[6]', YELLOW)} Payload chunks   : {cfg['chunk_payload']}")
        print(f"{c('[7]', YELLOW)} Chunk count      : {cfg['chunk_count']}")
        print(f"{c('[8]', YELLOW)} Backup           : {cfg['backup']}")
        print(f"{c('[9]', YELLOW)} Smoke test       : {cfg['smoke_test']}")
        print(f"{c('[10]', YELLOW)} Preserve names  : {', '.join(cfg['preserve'])}")
        print(f"{c('[11]', YELLOW)} Save config")
        print(f"{c('[12]', YELLOW)} Load config")
        print(f"{c('[13]', YELLOW)} Name style      : {cfg.get('name_style', 'random')}")
        print(f"{c('[14]', YELLOW)} Numbers         : {cfg.get('obfuscate_numbers', False)}")
        print(f"{c('[15]', YELLOW)} Junk code       : {cfg.get('junk_code', False)} (density {cfg.get('junk_density', 3)})")
        print(f"{c('[16]', YELLOW)} Docstrings strip: {cfg.get('strip_docstrings', True)}")
        print(f"{c('[17]', YELLOW)} Anti-debug      : {cfg.get('anti_debug', False)}")
        print(f"{c('[18]', YELLOW)} Integrity check : {cfg.get('integrity_check', True)}")
        print(f"{c('[19]', YELLOW)} Encoding        : {cfg.get('encoding', 'auto')}")
        print(f"{c('[20]', YELLOW)} Decoy classes   : {cfg.get('junk_classes', False)} (count {cfg.get('junk_class_count', 3)})")
        print(f"{c('[21]', YELLOW)} Trash output    : {cfg.get('trash_output', False)} (density {cfg.get('trash_density', 5)})")
        print(f"{c('[0]', RED)} Back")

        choice = input(c("\n> ", YELLOW)).strip()

        try:
            if choice == "1":
                print("\n1) fast\n2) balanced\n3) strong\n4) custom")
                x = input(c("> ", YELLOW)).strip()
                if x in {"1", "2", "3"}:
                    apply_profile(cfg, {"1": "fast", "2": "balanced", "3": "strong"}[x])
                elif x == "4":
                    cfg["profile"] = "custom"
            elif choice == "2":
                n = int(input(c("Layers (1-12): ", YELLOW)))
                if not 1 <= n <= 12:
                    raise ValueError
                cfg["layers"] = n
                cfg["profile"] = "custom"
            elif choice == "3":
                toggle(cfg, "rename_identifiers", "Rename identifiers")
                cfg["profile"] = "custom"
            elif choice == "4":
                toggle(cfg, "transform_strings", "String transformation")
                cfg["profile"] = "custom"
            elif choice == "5":
                toggle(cfg, "compress", "Compression")
                if cfg["compress"]:
                    x = input(c("Compressor zlib/lzma [zlib]: ", YELLOW)).strip().lower()
                    if x in ("zlib", "lzma"):
                        cfg["compressor"] = x
                cfg["profile"] = "custom"
            elif choice == "6":
                toggle(cfg, "chunk_payload", "Payload chunking")
                cfg["profile"] = "custom"
            elif choice == "7":
                n = int(input(c("Chunk count (2-40): ", YELLOW)))
                if not 2 <= n <= 40:
                    raise ValueError
                cfg["chunk_count"] = n
                cfg["profile"] = "custom"
            elif choice == "8":
                toggle(cfg, "backup", "Backup")
            elif choice == "9":
                toggle(cfg, "smoke_test", "Smoke test")
            elif choice == "10":
                raw = input(c("Comma-separated names to preserve: ", YELLOW))
                cfg["preserve"] = [x.strip() for x in raw.split(",") if x.strip()]
                cfg["profile"] = "custom"
            elif choice == "11":
                save_config(cfg)
                print(c("✓ Saved lilfuscator.json", YELLOW))
                pause()
            elif choice == "12":
                cfg.update(load_config())
                print(c("✓ Configuration loaded", YELLOW))
                pause()
            elif choice == "13":
                print("\n1) random\n2) confusable (O0Il1)\n3) hex")
                x = input(c("> ", YELLOW)).strip()
                if x in {"1", "2", "3"}:
                    cfg["name_style"] = {"1": "random", "2": "confusable", "3": "hex"}[x]
                    cfg["profile"] = "custom"
            elif choice == "14":
                toggle(cfg, "obfuscate_numbers", "Number obfuscation")
                cfg["profile"] = "custom"
            elif choice == "15":
                toggle(cfg, "junk_code", "Junk code")
                if cfg["junk_code"]:
                    n = input(c("Density (1-10) [3]: ", YELLOW)).strip()
                    if n:
                        cfg["junk_density"] = max(1, min(10, int(n)))
                cfg["profile"] = "custom"
            elif choice == "16":
                toggle(cfg, "strip_docstrings", "Docstring stripping")
                cfg["profile"] = "custom"
            elif choice == "17":
                toggle(cfg, "anti_debug", "Anti-debug")
                cfg["profile"] = "custom"
            elif choice == "18":
                toggle(cfg, "integrity_check", "Integrity check")
                cfg["profile"] = "custom"
            elif choice == "19":
                print("\n1) auto\n2) b85\n3) b64\n4) hex")
                x = input(c("> ", YELLOW)).strip()
                if x in {"1", "2", "3", "4"}:
                    cfg["encoding"] = {"1": "auto", "2": "b85", "3": "b64", "4": "hex"}[x]
                    cfg["profile"] = "custom"
            elif choice == "20":
                toggle(cfg, "junk_classes", "Decoy classes")
                if cfg["junk_classes"]:
                    n = input(c("Count (1-10) [3]: ", YELLOW)).strip()
                    if n:
                        cfg["junk_class_count"] = max(1, min(10, int(n)))
                cfg["profile"] = "custom"
            elif choice == "21":
                toggle(cfg, "trash_output", "Trash output")
                if cfg["trash_output"]:
                    n = input(c("Density (1-10) [5]: ", YELLOW)).strip()
                    if n:
                        cfg["trash_density"] = max(1, min(10, int(n)))
                cfg["profile"] = "custom"
            elif choice == "0":
                return
        except (ValueError, FileNotFoundError) as exc:
            print(c(f"Invalid setting: {exc}", RED))
            pause()

def obtain_source():
    print(c("\nINPUT\n", YELLOW))
    print(c("[1]", YELLOW), "Python file")
    print(c("[2]", YELLOW), "Paste code")
    choice = input(c("> ", YELLOW)).strip()

    if choice == "1":
        path = Path(input(c("Path: ", YELLOW)).strip()).expanduser()
        if not path.is_file():
            raise FileNotFoundError(path)
        return path.read_text(encoding="utf-8"), path
    if choice == "2":
        print(c("Paste code; finish with an empty line + y.", DIM))
        lines = []
        while True:
            line = input()
            if line == "":
                if input(c("Finish? [y/N]: ", YELLOW)).strip().lower() in ("y", "yes"):
                    break
            lines.append(line)
        return "\n".join(lines), None

    raise ValueError("Unknown input mode")

def run_interactive():
    ensure_packages()
    cfg = new_config()

    while True:
        clear()
        banner()

        print(c("\nCURRENT CONFIG\n", YELLOW))
        print(f" Profile : {c(str(cfg['profile']), YELLOW)}")
        print(f" Layers  : {c(str(cfg['layers']), YELLOW)}")
        print(f" Rename  : {c(str(cfg['rename_identifiers']), YELLOW)}")
        print(f" Strings : {c(str(cfg['transform_strings']), YELLOW)}")
        print(f" Compress: {c(str(cfg['compress']), YELLOW)}")
        print(f" Chunks  : {c(str(cfg['chunk_payload']), YELLOW)}")
        print(f" Junk    : {c(str(cfg.get('junk_code', False)), YELLOW)}")

        print(c("\nMAIN MENU\n", YELLOW))
        print(c("[1]", YELLOW), "Select input")
        print(c("[2]", YELLOW), "Settings")
        print(c("[3]", YELLOW), "Obfuscate")
        print(c("[4]", YELLOW), "Save current config")
        print(c("[5]", YELLOW), "Load config")
        print(c("[0]", RED), "Exit")

        choice = input(c("\nSelect: ", YELLOW)).strip()

        if choice == "1":
            try:
                source, source_path = obtain_source()
                cfg["_source"] = source
                cfg["_source_path"] = str(source_path) if source_path else ""
                print(c("✓ Source loaded", YELLOW))
            except Exception as exc:
                print(c(f"✗ {exc}", RED))
            pause()

        elif choice == "2":
            settings_menu(cfg)

        elif choice == "3":
            source = cfg.get("_source")
            if not source:
                print(c("Load or paste source first.", RED))
                pause()
                continue

            output_default = (
                str(Path(cfg["_source_path"]).with_name(
                    Path(cfg["_source_path"]).stem + "_obf.py"
                ))
                if cfg.get("_source_path")
                else "obfuscated_output.py"
            )

            output = input(c(f"Output [{output_default}]: ", YELLOW)).strip() or output_default

            try:
                print(c("\nBuilding protection layers...", YELLOW))
                result = obfuscate(source, cfg)
                out = write_output(result, output, cfg["backup"])

                if cfg["smoke_test"]:
                    ok, message = smoke_test(out)
                    if not ok:
                        raise RuntimeError(f"Generated file failed validation: {message}")

                original_size = len(source.encode("utf-8"))
                final_size = len(result.encode("utf-8"))
                ratio = final_size / max(original_size, 1)

                print(c("\n╔══════════════════════════════════════════╗", RED))
                print(c("║             COMPLETE ✓                  ║", RED))
                print(c("╚══════════════════════════════════════════╝", RED))
                print(f" Output : {out}")
                print(f" Layers : {cfg['layers']}")
                print(f" Size   : {final_size / 1024:.1f} KB")
                print(f" Growth : {ratio:.2f}x")
                print(c(" Validation: OK", YELLOW))
            except Exception as exc:
                print(c(f"✗ Obfuscation failed: {exc}", RED))
            pause()

        elif choice == "4":
            try:
                save_config(cfg)
                print(c("✓ Configuration saved.", YELLOW))
            except Exception as exc:
                print(c(f"✗ {exc}", RED))
            pause()

        elif choice == "5":
            try:
                loaded = load_config()
                source = cfg.get("_source")
                source_path = cfg.get("_source_path")
                cfg.clear()
                cfg.update(loaded)
                if source:
                    cfg["_source"] = source
                if source_path:
                    cfg["_source_path"] = source_path
                print(c("✓ Configuration loaded.", YELLOW))
            except Exception as exc:
                print(c(f"✗ {exc}", RED))
            pause()

        elif choice == "0":
            print(c("Goodbye.", YELLOW))
            return

def cli():
    if "--help" in sys.argv or "-h" in sys.argv:
        print("LILFUSCATOR")
        print("Usage: python Lilfuscator.py [input.py] [output.py] [layers]")
        print("       --profile fast|balanced|strong")
        return

    if len(sys.argv) < 2:
        run_interactive()
        return

    ensure_packages()

    inp = Path(sys.argv[1]).expanduser()
    if not inp.is_file():
        raise SystemExit(f"Input not found: {inp}")

    out = Path(sys.argv[2]).expanduser() if len(sys.argv) >= 3 and not sys.argv[2].startswith("--") else \
        inp.with_name(inp.stem + "_obf.py")

    cfg = new_config()

    positional = [a for a in sys.argv[3:] if not a.startswith("--")]
    if positional:
        cfg["layers"] = max(1, min(12, int(positional[0])))

    if "--profile" in sys.argv:
        i = sys.argv.index("--profile")
        if i + 1 < len(sys.argv):
            apply_profile(cfg, sys.argv[i + 1])

    source = inp.read_text(encoding="utf-8")
    result = obfuscate(source, cfg)
    write_output(result, out, cfg["backup"])

    print(c(f"✓ Created {out}", YELLOW))
    if cfg["smoke_test"]:
        ok, msg = smoke_test(out)
        print(c("✓ Validation OK" if ok else f"✗ Validation failed: {msg}",
                YELLOW if ok else RED))

if __name__ == "__main__":
    cli()

