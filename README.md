# openhicos

Repository: [github.com/chouhsiang/openhicos-pkcs11](https://github.com/chouhsiang/openhicos-pkcs11)

Unofficial PKCS#11 module for Taiwan **HiCOS** smart cards（自然人憑證生態）.

Drop-in style alternative to proprietary `libHicos_p11v1.dylib` for tools that
load a Cryptoki module (e.g. `pkcs11-tool`).

> **Not affiliated with** 內政部 or 中華電信. Clean-room work based on
> ISO 7816 / PKCS#15 and independent APDU notes (`ref/apdu.md`).

**AI / 開發交接**：請先讀 [`AGENTS.md`](AGENTS.md)（歷程、實卡發現、待辦）。

## Build

Requires [Rust](https://rustup.rs/) (1.85+).

```bash
make
# → build/openhicos-pkcs11-macos-arm64.so
# → build/openhicos-pkcs11-linux-x86_64.so
```

Or with Cargo:

```bash
cargo build --release
# macOS: target/release/libopenhicos_pkcs11.dylib
# Linux: target/release/libopenhicos_pkcs11.so
```

- macOS: system **PCSC.framework** (via `pcsc` crate)
- Linux: **pcsc-lite** (`libpcsclite-dev`)

## Use with pkcs11-tool

```bash
MOD=./build/openhicos-pkcs11-macos-arm64.so   # adjust OS/arch

pkcs11-tool --module "$MOD" -I
pkcs11-tool --module "$MOD" -L
pkcs11-tool --module "$MOD" -O
pkcs11-tool --module "$MOD" --login -O
pkcs11-tool --module "$MOD" --login \
  --sign --mechanism SHA256-RSA-PKCS --id 5349474e \
  -i msg.bin -o sig.bin
pkcs11-tool --module "$MOD" --login \
  --decrypt --mechanism RSA-PKCS -i cipher.bin -o plain.bin
```

官方對照（本機 `ref/`，勿散佈）:

```bash
pkcs11-tool --module ./ref/libHicos_p11v1.dylib -L
pkcs11-tool --module ./ref/libHicos_p11v1.dylib -O --type cert
```

## Implemented

| Feature | Notes |
|---------|--------|
| Slots / TokenInfo | PC/SC；label/serial/model 對齊官方（實卡 T7S 驗證） |
| Object discovery | HiCOS 專有 DF `5030`（PrKDF/PuKDF/CDF/DODF），`-O` 與官方逐行一致 |
| Certificates | 從共用 EF `08F2` 依 index/length 切片讀出，openssl 可完整解析 |
| Public keys | READ RECORD + 32-bit word 反序還原模數 |
| Data objects | DODF，含 application / OID |
| Login | T7S 安全 VERIFY PIN（3DES CBC + MAC），實卡驗證 |
| Sign | HiCOS V3 `EA` / `C1` RSA；RSA-PKCS / SHA1 / SHA256 均與官方逐位元組一致 |
| Decrypt | MSE + PSO Decipher；`CKM_RSA_PKCS` |

## Limits

- Decrypt 尚未在實卡端到端驗證
- 只取樣過 T7S（`CHT V32N`）+ 2048-bit 金鑰；其他 HiCOS 世代未驗
- T7S 登入／簽章流程不應直接套用到其他 HiCOS 世代

## Layout

```text
openhicos/
  Cargo.toml
  Makefile
  src/
    lib.rs           # C_GetFunctionList export
    pcsc.rs          # PC/SC transport
    apdu.rs          # HiCOS APDU (CLA 0x80)
    der.rs           # ASN.1/DER parser
    p15.rs           # HiCOS bind: TokenInfo + object discovery
    pkcs11/          # Cryptoki types + C_* API
  ref/               # 官方 dylib + apdu.md（對照用）
  build/             # openhicos-pkcs11-<os>-<arch>.so
  AGENTS.md          # AI handoff / 開發日誌
```

## License

LGPL-2.1-or-later. See `LICENSE`.
