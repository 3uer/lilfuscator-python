# Lilfuscator v1.0.0

First full implementation. The repo previously shipped README + LICENSE only.

## What's inside

- **Layered packing (1-12)**: marshal -> zlib/lzma -> RC4 -> base85/base64/hex,
  wrapped in polymorphic loader shells (3 structural driver variants,
  per-build random naming). Same input + different seed = different bytes.
- **Chained-key integrity**: layer keys are derived from per-layer seeds;
  there is no check to NOP — any tamper crashes inside decompress/marshal.
- **AST renaming**: function-local names only, scope-aware (nested scopes
  keep their own bindings; global/nonlocal handled correctly).
- **Control-flow flattening**: straight-line function bodies become a
  while-dispatch loop over scrambled block indices.
- **String / number obfuscation**: lazy per-use-site decryption
  (chr-join / reversed slice / fromhex), ints as XOR pairs.
- **Anti-debug**: gettrace (decoy), IsDebuggerPresent (Windows),
  ptrace TRACEME (Linux), timing checks.
- **Decoy classes** with CJK identifiers/docstrings, junk dead code behind
  runtime opaque predicates, multilingual trash comments.
- **Machine binding** (`paranoid` profile / `--bind`): outer layer key
  mixed with machine fingerprint.
- Profiles: `fast`, `balanced`, `strong`, `paranoid`; JSON config
  save/load; backups; output syntax validation; `--smoke` run check.
- Interactive TUI (no args) + full CLI. Zero dependencies, stdlib only.

## Verification

- `python Lilfuscator.py --selftest` -> **12/12 PASS** (4 profiles x 3
  scripts: f-strings, decorators, closures, generators, match, dataclasses,
  ctx managers, exceptions, globals, big ints — stdout compared
  byte-for-byte against the originals).
- Tamper test: bit-flip in the blob -> non-zero exit (crash, no bypass).
- Seed reproducibility: same seed = identical output.

## Known limits

- Marshalled bytecode is tied to the Python minor version used at build
  time. Obfuscated files must run on the same 3.x minor version.
- Pure-Python packing cannot beat a patched interpreter; for high-value
  targets pair with Nuitka/Cython compilation.
