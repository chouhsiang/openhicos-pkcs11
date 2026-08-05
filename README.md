# openhicos

Unofficial PKCS#11 module for Taiwan **HiCOS** smart cards（自然人憑證生態）.

Drop-in style alternative to proprietary `libHicos_p11v1.dylib` for tools that
load a Cryptoki module (e.g. `pkcs11-tool`).

> **Not affiliated with** 內政部 or 中華電信. Clean-room work based on
> ISO 7816 / PKCS#15 and independent APDU notes (`ref/apdu.md`, `docs/apdu-notes.md`).

**AI / 開發交接**：請先讀 [`AGENTS.md`](AGENTS.md)（歷程、實卡發現、待辦）。

## Build

Requires [Rust](https://rustup.rs/) (1.70+).

### macOS / Linux

```bash
cd openhicos
make
# → build/openhicos-pkcs11-macos-arm64.so
# → build/openhicos-pkcs11-linux-x86_64.so
```

Or directly with Cargo:

```bash
cargo build --release
# macOS: target/release/libopenhicos_pkcs11.dylib
# Linux: target/release/libopenhicos_pkcs11.so
```

- macOS: system **PCSC.framework** (via `pcsc` crate)
- Linux: **pcsc-lite** (`libpcsclite-dev`)

### Legacy C build (optional)

Original C sources remain under `pkcs11/` for reference:

```bash
make -f Makefile.legacy
```

### Windows (native)

**MSVC**（Developer Command Prompt）:

```bat
build-windows.bat
REM → build\openhicos-pkcs11-windows-x86_64.so
```

**MSYS2 / MinGW**:

```bash
pacman -S mingw-w64-x86_64-gcc
make
# → build/openhicos-pkcs11-windows-x86_64.so
```

**CMake**（MSVC 或 MinGW）:

```bat
cmake -B build-win -A x64
cmake --build build-win --config Release
```

### Cross-compile Windows from macOS / Linux

```bash
# macOS: brew install mingw-w64
# Debian: apt install mingw-w64
make windows
# → build/openhicos-pkcs11-windows-x86_64.so
```

## Use with pkcs11-tool

```bash
MOD=./build/openhicos-pkcs11-macos-arm64.so   # adjust OS/arch

pkcs11-tool --module "$MOD" -I
pkcs11-tool --module "$MOD" -L
pkcs11-tool --module "$MOD" -O
pkcs11-tool --module "$MOD" --login -O
pkcs11-tool --module "$MOD" --login \
  --sign --mechanism SHA256-RSA-PKCS -i msg.bin -o sig.bin
pkcs11-tool --module "$MOD" --login \
  --decrypt --mechanism RSA-PKCS -i cipher.bin -o plain.bin
```

Windows example:

```bat
pkcs11-tool --module build\openhicos-pkcs11-windows-x86_64.so -L
```

## Implemented

| Feature | Notes |
|---------|--------|
| Slots / TokenInfo | PC/SC readers; label/serial from EF.TokenInfo when present |
| PKCS#15 bind | SELECT AID/`5015`, read ODF → PrKDF / CDF / AODF |
| Objects | Certificates, public keys, private keys (+ attributes) |
| Login | VERIFY PIN (tries TokenInfo/AODF ref, `00`, `01`, `8C`) |
| Sign | MSE + PSO CDS; `CKM_RSA_PKCS` / `SHA1-RSA-PKCS` / `SHA256-RSA-PKCS` |
| Decrypt | MSE + PSO Decipher; `CKM_RSA_PKCS` |

## Limits

- Card layouts differ across HiCOS generations; some FIDs/key refs may need tuning on real hardware.
- No GlobalPlatform SCP path yet.
- No host-side verify / encrypt.
- Must be validated with a physical card + reader.

## Layout

```text
openhicos/
  Cargo.toml
  Makefile           # Rust build (default)
  Makefile.legacy    # optional C build
  src/
    lib.rs           # C_GetFunctionList export
    pcsc.rs          # PC/SC transport
    apdu.rs          # HiCOS APDU (CLA 0x80)
    der.rs           # ASN.1/DER parser
    p15.rs           # PKCS#15 bind + objects
    pkcs11/          # Cryptoki types + C_* API
  pkcs11/            # legacy C sources (reference)
  ref/               # libHicos_p11v1.dylib + apdu.md（官方對照，勿公開散佈 dylib）
  build/             # final module: openhicos-pkcs11-<os>-<arch>.so
  docs/apdu-notes.md
  AGENTS.md          # AI handoff / 開發日誌
```

## License

LGPL-2.1-or-later. See `LICENSE`.
