# Changelog

All notable changes to Lilfuscator. Versioning: `MAJOR.MINOR.PATCH`.

## [2.2.0] - 2026-11-09

### Added
- **Full 2.0-style interactive TUI**: ASCII banner, live state panel,
  main menu (1 select input / 2 settings / 3 obfuscate / 4 save config /
  5 load config / 0 exit) and a 21-item settings menu exactly like the
  2.0 spec. Paste code directly into the terminal (empty line + `y`).
- **Preserve-names list**: renamer never touches configurable names
  (default `__init__`, `__main__`, `main`, `app`, `cli`) - settings `10`.
- **Payload chunks**: split the blob into 2-40 randomized chunks
  (settings `6`/`7`).
- **Integrity check option** (settings `18`): SHA-256 of the marshalled
  payload, verified inside the loader before exec.
- **Fixed compression / encoding choices** per layer (settings `5`/`19`):
  `auto` (random per layer), `zlib`, `lzma`, `none` / `b85`, `b64`, `hx`.
- **Timestamped backups** (settings `8`) and **smoke test toggle**
  (settings `9`) in the TUI.
- Manual changes in Settings switch the profile display to `custom`.

### Changed
- `pack_payload` accepts `comp_choice` / `enc_choice`; identity
  decompressor (`'n'`) added to loader dispatch.
- `LocalRenamer` takes an optional `preserve` set.
- `build_loader` accepts `code_hash` and emits the pre-exec digest check.

## [2.1.0] - 2026-11-09

### Added
- **Full implementation restored**: the source (`Lilfuscator.py`, ~1000
  lines, zero dependencies) is back in the repo after being absent since 2.0.
- **RC4 pack layers** replacing single-key XOR: each of the 1-12 layers is
  compress (zlib/lzma) -> RC4 -> encode (base85/base64/hex).
- **Polymorphic loaders**: 3 structural driver variants, per-build random
  naming, decoy classes, junk code, multilingual trash comments. Same input
  + different seed = different bytes.
- **Machine binding** (`--bind`, `paranoid` profile): outer layer key mixed
  with machine fingerprint.
- **Control-flow flattening**: straight-line function bodies rewritten into
  a while-dispatch loop over block indices (conservative, opt-in via
  profile).
- **Scope-aware local renaming**: nested scopes keep their own bindings;
  `global`/`nonlocal` handled correctly; class bodies skipped at class
  level, methods followed.
- **Lazy string obfuscation**: chr-join / reversed slice / fromhex,
  decrypted per use site.
- **Anti-debug stub**: `sys.gettrace` (decoy), `IsDebuggerPresent` (Windows),
  `ptrace` TRACEME (Linux), timing checks.
- **Built-in self-test**: `--selftest` runs 4 profiles x 3 scripts and
  byte-compares stdout against originals (12/12 PASS).
- CLI flags: `--seed` (reproducible builds), `--style`, `--bind`,
  `--config`/`--save-config`, `--smoke`, `--no-backup`. Interactive TUI
  when run without arguments.

### Changed
- Integrity model: no separate check to NOP. Layer keys derive from
  per-layer seeds; any tamper crashes inside decompress/marshal.
- Renaming happens before flattening so flattened blocks share one
  consistent name per variable.

### Fixed
- Unpack order mismatch between packer and loader drivers.
- `bytes.fromhex` receiving bytes in the hex decode path.
- Multi-layer key derivation using an inconsistent layer index.
- Renamer breaking `nonlocal` bindings of nested closures.
- Flattener emitting `nonlocal` without a binding in the enclosing scope.
- Flattener self-excluding every function via `ast.walk(node)`.
- Self-test comparing output files whose scripts print their own argv[0].

### Known limits
- Marshalled bytecode is tied to the Python minor version used at build
  time (3.9+): run obfuscated files on the same minor version.
- Pure-Python packing cannot beat a patched interpreter; for high-value
  targets pair with Nuitka/Cython compilation.

## [2.0] - 2026-10
- Project polish: revamped README (badges, layout), `.gitignore`.
- Source file removed from the repo (README + LICENSE only).

## [1.0] - 2026-10
- First version.
