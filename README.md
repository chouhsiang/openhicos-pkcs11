# openhicos

Repository: [github.com/chouhsiang/openhicos-pkcs11](https://github.com/chouhsiang/openhicos-pkcs11)

Unofficial PKCS#11 module for Taiwan **HiCOS** smart cards（工商／自然人憑證）.

Drop-in style alternative to proprietary `libHicos_p11v1.dylib` for tools that
load a Cryptoki module (e.g. `pkcs11-tool`).

> **Not affiliated with** 內政部 or 中華電信. Clean-room work based on
> ISO 7816 / PKCS#15 and independent APDU notes (`ref/apdu.md`).

**AI / 開發交接**：請先讀 [`AGENTS.md`](AGENTS.md)（歷程、實卡發現、待辦）。

## Build

Requires [Rust](https://rustup.rs/) (1.70+) and [OpenSC](https://github.com/OpenSC/OpenSC)（提供 `pkcs11-tool`）。

```bash
make
# → build/openhicos-pkcs11-macos-arm64.so
# → build/openhicos-pkcs11-linux-x86_64.so
```

- macOS: system **PCSC.framework**
- Linux: **pcsc-lite** (`libpcsclite-dev`)

下文以 macOS arm64 產物為例；請依實際路徑替換 `$MOD`。

```bash
MOD=./build/openhicos-pkcs11-macos-arm64.so
# 官方對照（本機 ref/，勿散佈）:
OFF=./ref/libHicos_p11v1.dylib
```

## 查看 Token

```bash
pkcs11-tool --module "$MOD" -L
pkcs11-tool --module "$OFF" -L
```

會顯示 slot、label、model、serial、PIN 長度等。

## 列出物件／憑證清單

列出全部物件（公鑰、憑證、data object；未登入時沒有私鑰）：

```bash
pkcs11-tool --module "$MOD" -O
pkcs11-tool --module "$OFF" -O
```

只列憑證：

```bash
pkcs11-tool --module "$MOD" --list-objects --type cert
pkcs11-tool --module "$OFF" --list-objects --type cert
```

常見憑證 ID：

| ID (hex) | 用途 |
|----------|------|
| `5349474e` | 簽章憑證（ASCII `SIGN`） |
| `4b455958` | 加密憑證（ASCII `KEYX`） |
| `434143657274` | CA Cert |
| `524f4f54434143657274` | ROOT CA Cert |

## 讀出憑證 PEM

`pkcs11-tool` 讀出的是 DER；用 openssl 轉成 PEM：

```bash
# 簽章憑證 → PEM（印到終端）
pkcs11-tool \
  --module "$MOD" \
  --read-object \
  --type cert \
  --id 5349474e \
  --output-file /dev/stdout \
| openssl x509 -inform DER -outform PEM

# 存成檔案
pkcs11-tool \
  --module "$MOD" \
  --read-object \
  --type cert \
  --id 5349474e \
  --output-file sign-cert.der

openssl x509 -inform DER -in sign-cert.der -out sign-cert.pem
openssl x509 -in sign-cert.pem -noout -subject -issuer -dates
```

## 數位簽章

準備要簽署的訊息，登入後用 `SHA256-RSA-PKCS`（也可 `SHA1-RSA-PKCS` / `RSA-PKCS`）：

```bash
echo 'hello openhicos' > msg.txt

pkcs11-tool \
  --module "$MOD" \
  --login --pin "$PIN" \
  --sign --mechanism SHA256-RSA-PKCS \
  --id 5349474e \
  --input-file msg.txt \
  --output-file sig.bin
```

與官方模組比對（同一訊息、同一 PIN）：

```bash
pkcs11-tool \
  --module "$OFF" \
  --login --pin "$PIN" \
  --sign --mechanism SHA256-RSA-PKCS \
  --id 5349474e \
  --input-file msg.txt \
  --output-file sig-official.bin

pkcs11-tool \
  --module "$MOD" \
  --login --pin "$PIN" \
  --sign --mechanism SHA256-RSA-PKCS \
  --id 5349474e \
  --input-file msg.txt \
  --output-file sig-openhicos.bin

cmp sig-official.bin sig-openhicos.bin && echo 'signatures match'
```

用憑證公鑰驗證簽章：

```bash
openssl x509 -inform DER -in sign-cert.der -pubkey -noout > sign-pub.pem
openssl dgst -sha256 -verify sign-pub.pem -signature sig.bin msg.txt
# → Verified OK
```

> PIN 錯誤會扣除重試次數；請勿連續亂試。一代與二代卡都支援上述流程。

## Implemented

| Feature | Notes |
|---------|--------|
| Slots / TokenInfo | PC/SC；label/serial/model 對齊官方 |
| Object discovery | HiCOS DF `5030`（PrKDF/PuKDF/CDF/DODF） |
| Certificates | 共用 EF `08F2` 切片讀出 |
| Public keys | gen1：word-reverse；gen2：直讀兩半 |
| Login | gen1：`8C 20` 3DES；gen2：Diverse + SCP03 |
| Sign | gen1：`80 EA`/`C1`；gen2：`84 EA`/`C1`；與官方逐位元組一致 |
| Decrypt | 程式碼已有，實卡需再驗 |

## Limits

- Decrypt 尚未在實卡端到端驗證
- 主要驗證環境為 T7S 系列 + 2048-bit RSA
- 分檔依**卡世代**（`gen1` / `gen2`），不依機關名稱

## Layout

```text
openhicos/
  Cargo.toml
  Makefile
  src/
    lib.rs              # C_GetFunctionList
    pcsc.rs
    apdu/
      mod.rs            # profile 偵測、共用 SELECT/READ
      gen1.rs           # 一代卡（CLA 0x80）
      gen2.rs           # 二代卡（GPPKI + SCP03）
    der.rs
    p15.rs
    pkcs11/
  ref/                  # 官方 dylib + apdu.md（對照用，勿散佈）
  build/                # openhicos-pkcs11-<os>-<arch>.so
  AGENTS.md
```

## License

LGPL-2.1-or-later. See `LICENSE`.
