Lilfuscator

A Python source-code obfuscator with an interactive terminal UI and a CLI.
It protects your scripts with layered packing, AST-level transformations,
decoy classes, junk code, and output trashing — while keeping the program's
behavior byte-identical to the original.

> ⚠️ Disclaimer: Use only on code you own or have explicit rights to
protect. Obfuscation is not encryption — determined reverse engineers can
still unpack it. Don't use it to hide malicious behavior.

---

Features

- Layered packing (1–12 layers) — the compiled bytecode is marshalled,
  compressed, XOR-encrypted, encoded (base85 / base64 / hex) and wrapped in
  multiple loader shells
- Identifier renaming — three styles: random, confusable (`_O0Il1lOI`),
  hex (`_xa3f9...`)
- String transformation — `chr()`-join, reversed slicing, and
  `bytes.fromhex().decode()`, chosen randomly per string
- Number obfuscation — integers rewritten as XOR expressions
  (`1500` → `1011471512 ^ 1011472240`)
- Junk code injection — dead code behind opaque predicates
  (`if (v ^ v) != 0:` — always false, but not obviously so)
- Decoy classes — fake, never-used classes with Chinese docstrings,
  Unicode identifiers (`self.队列67`) and realistic-looking fake logic
  (caching, validation, batch processing) injected between your real code
- Trash output — the final file itself is flooded with garbage comments
  (中文 / 日本語 / 한국어 / Deutsch / Русский), dead variables, fake configs,
  and decoy classes between loader lines
- Anti-debug stub — exits if a debugger trace is detected
- Integrity check — SHA-256 hash verification; refuses to run if tampered
- Docstring stripping, zlib / lzma compression
- Config save/load (JSON), backups, syntax validation

Requirements

- Python 3.9+ (uses `ast.unparse`)
- No third-party dependencies — standard library only

Installation

```bash
git clone https://github.com/3uer/lilfuscator-python.git
cd lilfuscator-python
```

Usage

CLI mode

```bash
# Basic: input, output, number of layers (1-12)
python Lilfuscator.py myscript.py myscript_obf.py 5

# With a profile
python Lilfuscator.py myscript.py myscript_obf.py 5 --profile strong

# Help
python Lilfuscator.py --help
```

Interactive mode

Run without arguments:

```bash
python Lilfuscator.py
```

Profiles

Profile	Layers	Renaming	Strings	Junk	Decoys	Trash	Anti-debug	
`fast`	1	—	—	—	—	—	—	
`balanced`	3	✓	✓	✓	✓ (2)	✓ (3)	—	
`strong`	5	✓ (confusable)	✓	✓	✓ (5)	✓ (6)	✓	

Any manual change in Settings switches the profile to `custom`.

---

Main menu

Key	Action	What it does	
`1`	Select input	Load a `.py` file from disk, or paste code directly into the terminal (finish with an empty line + `y`)	
`2`	Settings	Open the configuration menu (see below)	
`3`	Obfuscate	Run the obfuscator with the current config, write the output file, back up any existing output, and syntax-validate the result	
`4`	Save current config	Write the current settings to `lilfuscator.json`	
`5`	Load config	Read settings back from `lilfuscator.json` (keeps the currently loaded source)	
`0`	Exit	Quit	

Settings menu

Key	Setting	What it means	
`1`	Profile	Pick `fast` / `balanced` / `strong`, or mark as `custom`	
`2`	Layers	How many packing shells wrap the payload (1–12). More = slower startup, bigger file, harder to read	
`3`	Rename names	Toggle identifier renaming (functions, classes, variables). Imports, builtins, methods and dunder names are never touched	
`4`	Transform strings	Toggle string obfuscation (chr-join / reverse / hex-decode, 70% of strings)	
`5`	Compression	Toggle payload compression; when ON, asks for `zlib` or `lzma` (lzma = smaller, slightly slower)	
`6`	Payload chunks	Toggle splitting the encoded payload into randomized chunks	
`7`	Chunk count	How many chunks (2–40)	
`8`	Backup	If the output file already exists, keep a timestamped `.bak` copy	
`9`	Smoke test	Syntax-validate the generated file after writing	
`10`	Preserve names	Comma-separated list of names the renamer must never touch (default: `__init__`, `__main__`, `main`, `app`, `cli`, ...)	
`11`	Save config	Write settings to `lilfuscator.json`	
`12`	Load config	Load settings from `lilfuscator.json`	
`13`	Name style	Renaming style: `random` letters / `confusable` (`O0Il1`) / `hex`	
`14`	Numbers	Toggle integer obfuscation (`N` → `a ^ b`)	
`15`	Junk code	Toggle dead-code injection behind opaque predicates; when ON, asks for density (1–10)	
`16`	Docstrings strip	Remove module/class/function docstrings	
`17`	Anti-debug	Insert a stub that aborts execution when a debugger trace is active	
`18`	Integrity check	Wrap the output in a SHA-256 self-check; modified files refuse to run	
`19`	Encoding	Payload encoding: `auto` (random per layer) / `b85` / `b64` / `hex`	
`20`	Decoy classes	Toggle fake Chinese-documented classes injected between your real code; when ON, asks for count (1–10)	
`21`	Trash output	Flood the final file with garbage comments, dead variables, fake configs and decoy classes between loader lines; when ON, asks for density (1–10)	
`0`	Back	Return to the main menu	

---

Example

```bash
python Lilfuscator.py taskforge.py taskforge_obf.py 5 --profile strong
python taskforge_obf.py        # behaves exactly like the original
```

How it works (short)

1. Your source is parsed into an AST.
2. Transformations: docstrings stripped → identifiers renamed → numbers
   XOR-ified → strings encoded → junk code injected → decoy classes inserted.
3. The result is compiled to bytecode and marshalled.
4. The blob is compressed, XOR-encrypted with a random key, encoded and
   split into chunks — wrapped in a loader shell. Repeated per layer.
5. The outermost file gets an integrity wrapper and (optionally) the trash
   treatment.

Limitations

- Entry point must be guarded by `if __name__ == "__main__":` if you rely on it —
  it keeps working, just note the whole file runs at import time.
- Code that introspects its own source (`inspect.getsource`, `__file__`-relative
  reads of itself) or relies on exact function/variable names (e.g. `getattr`
  with string literals) may need those names added to Preserve names.
- Keyword arguments of library functions are never renamed (safe), but
  method parameters are kept as-is for the same reason.

License

MIT
