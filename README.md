# open-gpki-pkcs11

獨立實作的台灣 **GPKI** 智慧卡 **PKCS#11** 模組，可用 `pkcs11-tool --module …` 直接操作台灣的**工商憑證**與**自然人憑證**卡片。

**不依賴 OpenSC 驅動**；僅用 OpenSC 附帶的 `pkcs11-tool` 當測試工具亦可。

### 支援的作業系統

三個平台皆提供預先建置的模組；實卡驗證狀態如下：

| 平台 | 提供 | 實卡測試 | 產物 |
|------|:----:|:--------:|------|
| **macOS** | ✓ | ✓ | `open-gpki-pkcs11-macos-*.dylib` |
| **Windows** | ✓ | ✓ | `open-gpki-pkcs11-windows-x86_64.dll` |
| **Linux** | ✓ | 尚未 | `open-gpki-pkcs11-linux-*.so` |

### `build/` 預建產物（五個檔案）

| 檔案 | 說明 | 何時使用 |
|------|------|----------|
| `open-gpki-pkcs11-macos-arm64.dylib` | macOS **Apple Silicon（arm64）** 原生模組 | Apple Silicon Mac 上的原生 app／`pkcs11-tool` |
| `open-gpki-pkcs11-macos-universal.dylib` | macOS **universal（x86_64 + arm64）** | 給需 x86_64／Rosetta 的工具使用 |
| `open-gpki-pkcs11-windows-x86_64.dll` | Windows **x86_64** | 給可自行指定 PKCS#11 模組路徑的程式（如 `pkcs11-tool`） |
| `open-gpki-pkcs11-linux-x86_64.so` | Linux **x86_64** | Linux x86_64（實卡尚未測） |
| `open-gpki-pkcs11-linux-arm64.so` | Linux **aarch64／arm64** | ARM Linux（如部分 SBC／ARM 伺服器；實卡尚未測） |

- 專案：https://github.com/chouhsiang/open-gpki-pkcs11

> **非**政府官方軟體。依 ISO 7816／PKCS#15 與實卡行為實作。

---

## 能做什麼

### 支援的 `pkcs11-tool` 操作

「✓」＝支援；「—」＝不支援。

| `pkcs11-tool` | 說明 | open-gpki |
|---------------|------|:---------:|
| `-I` | 模組／庫資訊 | ✓ |
| `-L`／`-T` | 列出 slot／Token | ✓ |
| `-M` | 列出機制 | ✓ |
| `-O` | 列出物件 | ✓ |
| `-r`／`--read-object` | 讀憑證／公鑰等 | ✓ |
| `--login`／`-l` | PIN 登入 | ✓ |
| `--sign`／`-s` | 數位簽章 | ✓ |
| `--verify` | 驗證簽章 | ✓ |
| `--decrypt` | 私鑰解密 | ✓ |
| `--generate-random` | 產生亂數 | ✓ |
| `--encrypt` | 公鑰加密 | ✓ |
| `--hash`／`-h` | 摘要（Digest） | ✓ |
| `--wrap`／`--unwrap` | 金鑰包裝 | — |
| `--derive` | 金鑰衍生（如 ECDH） | — |
| `-k`／`--keygen` | 產金鑰／金鑰對 | — |
| `-c`／`--change-pin` | 變更 PIN | — |
| `--init-pin`／`--unlock-pin`／`--init-token` | PIN／Token 初始化 | — |
| `-w`／`-b` | 寫入／刪除物件 | — |
| `--list-interfaces` | PKCS#11 3.0 介面 | — |

### 演算法／機制（`-M`）

`pkcs11-tool -M` 的機制清單；一代與二代卡相同。  
RSA 欄位寫實際操作能力（簽章／驗簽／加密／解密）；「—」＝不支援該機制。

#### RSA（簽章／驗簽／加密／解密）

| 機制 | open-gpki |
|------|-----------|
| `RSA-PKCS` | 簽章、驗簽、加密、解密 |
| `RSA-X-509` | 簽章、驗簽、加密、解密 |
| `SHA1-RSA-PKCS` | 簽章、驗簽 |
| `SHA256-RSA-PKCS` | 簽章、驗簽 |
| `SHA384-RSA-PKCS` | 簽章、驗簽 |
| `SHA512-RSA-PKCS` | 簽章、驗簽 |
| `MD5-RSA-PKCS` | 簽章、驗簽 |
| `RSA-PKCS-OAEP` | 加密、解密 |
| `RSA-PKCS-PSS` | — |
| `SHA1-RSA-PKCS-PSS` | — |
| `SHA256-RSA-PKCS-PSS` | — |
| `SHA384-RSA-PKCS-PSS` | — |
| `SHA512-RSA-PKCS-PSS` | — |
| `RSA-PKCS-KEY-PAIR-GEN` | — |

#### 摘要（Digest）

| 機制 | open-gpki |
|------|:---------:|
| `SHA-1` | ✓ |
| `SHA256` | ✓ |
| `SHA384` | ✓ |
| `SHA512` | ✓ |
| `MD5` | ✓ |

#### 目前未實作

HMAC、DES／3DES、AES、ECDSA／ECDH（含 keypair gen）等。

`--encrypt`：OpenSC 0.26+ 的 `pkcs11-tool` 只接受 `RSA-PKCS-OAEP`（不接受 `RSA-PKCS`／`RSA-X-509`）；open-gpki 的 OAEP／X.509 密文可用本模組或 openssl 正確解密。

### 功能摘要

| 功能 | 說明 |
|------|------|
| 查看卡片（Token） | 標籤、型號、序號、PIN 長度等 |
| 列出物件 | 憑證、公鑰、資料物件；登入後可見私鑰 |
| 讀出憑證 | DER／轉 PEM |
| 登入 | 輸入 PIN（錯誤會扣重試次數，請勿亂試） |
| 數位簽章 | `RSA-PKCS`／`RSA-X-509`、`MD5`／`SHA1`／`SHA256`／`SHA384`／`SHA512-RSA-PKCS` |
| 驗證簽章 | 同上；以公鑰在主機端驗證 |
| 資料解密 | `RSA-PKCS`／`RSA-X-509`／`RSA-PKCS-OAEP`（加密金鑰 KEYX） |
| 公鑰加密 | `RSA-PKCS`／`RSA-X-509`／`RSA-PKCS-OAEP`（host 端；KEYX 公鑰） |
| 摘要 | `MD5`／`SHA-1`／`SHA256`／`SHA384`／`SHA512`（host 端） |
| 產生亂數 | 使用作業系統 CSPRNG |

---

## 支援哪些卡

模組依**卡片世代**自動偵測，不依「工商／自然人」分檔：

| 世代 | 涵蓋 | 說明 |
|------|------|------|
| **一代（gen1）** | 一代自然人、工商憑證 | CLA `0x80`；登入用 3DES 保護 PIN |
| **二代（gen2）** | 二代自然人憑證 | GPPKI applet + SCP03 |

### 已實卡測過

讀卡機：`Generic USB2.0-CRW`。下列類型已實卡驗證：

| 憑證類型 | 世代 | 已驗證 |
|----------|------|--------|
| 工商憑證 | 一代 | Token／物件／登入／簽章／解密 |
| 自然人憑證 | 一代 | Token／物件／登入／簽章／解密 |
| 自然人憑證 | 二代 | Token／物件／登入／簽章／解密 |

主要環境：T7S 系列、2048-bit RSA。

常見物件 ID（hex）：

| ID | 意義 |
|----|------|
| `5349474e` | 簽章（ASCII `SIGN`） |
| `4b455958` | 加解密（ASCII `KEYX`） |
| `434143657274` | CA 憑證 |
| `524f4f54434143657274` | Root CA 憑證 |

---

## 建置

需要：

- [Rust](https://rustup.rs/)（建議 1.70+）
- macOS：系統 **PCSC.framework**
- Linux：**pcsc-lite**（如 `libpcsclite-dev`）
- Windows：見下方「Windows 本機建置」
- 測試用：[OpenSC](https://github.com/OpenSC/OpenSC) 的 `pkcs11-tool`、以及 `openssl`
- 交叉編譯 Linux `.so`（可選）：本機 [Docker](https://www.docker.com/)

```bash
make
# 產出例如：
#   build/open-gpki-pkcs11-macos-arm64.dylib
```

### Windows 本機建置

請在 **Windows 主機**上編譯（不再提供 Docker 交叉編譯 `.dll`）。執行時使用系統 WinSCard。

擇一工具鏈：

| 工具鏈 | 需求 |
|--------|------|
| **MSVC**（優先） | `rustup` 的 `stable-x86_64-pc-windows-msvc` + [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)（含 C++／`link.exe`） |
| **GNU／MinGW** | `rustup toolchain install stable-x86_64-pc-windows-gnu`，並安裝 MinGW-w64（需有 `x86_64-w64-mingw32\lib\libwinscard.a`） |

```powershell
# 在 repo 根目錄
.\scripts\build-windows.ps1
# 或
scripts\build-windows.cmd

# MinGW 不在預設路徑時：
.\scripts\build-windows.ps1 -MingwRoot C:\path\to\mingw64
# 或設定環境變數 OPEN_GPKI_MINGW

# 強制指定工具鏈：
.\scripts\build-windows.ps1 -Toolchain msvc
.\scripts\build-windows.ps1 -Toolchain gnu
```

產出：`build/open-gpki-pkcs11-windows-x86_64.dll`。

腳本會自動：偵測 MSVC／MinGW、以 `rust-lld` 連結（避開 MinGW `ld` 在含中文使用者路徑下失敗）、複製產物到 `build/`。

### Docker 交叉編譯（僅 Linux）

在 macOS／Linux 上可用 Docker 產出 Linux `.so`（執行時需該平台的 `pcscd`／`libpcsclite`）：

```bash
make linux-arm64      # build/open-gpki-pkcs11-linux-arm64.so
make linux-amd64      # build/open-gpki-pkcs11-linux-x86_64.so（QEMU，較慢）
make docker-linux     # 以上兩者
```

對應 Dockerfile：`docker/Dockerfile.linux`。

### macOS universal（給 x86_64 程式用）

部分舊版工具本身是 **x86_64 only**，在 Apple Silicon 上透過 Rosetta 執行，因此只能載入含 x86_64 slice 的模組；單純的 `…-macos-arm64.dylib` 會 `dlopen` 失敗。
需先安裝 x86_64 target，再合併：

```bash
rustup target add x86_64-apple-darwin

cargo build --release
cargo build --release --target x86_64-apple-darwin

lipo -create \
  target/release/libopen_gpki_pkcs11.dylib \
  target/x86_64-apple-darwin/release/libopen_gpki_pkcs11.dylib \
  -output build/open-gpki-pkcs11-macos-universal.dylib
```

| 模組架構 | Rosetta（x86_64）程式 | 原生 arm64 程式 |
|----------|:---------------------:|:---------------:|
| arm64 only | ✗ | ✓ |
| universal（x86_64 + arm64） | ✓ | ✓ |

下文假設：

```bash
MOD=./build/open-gpki-pkcs11-macos-arm64.dylib

# 請自行設定，勿把真實 PIN 寫進腳本或提交到 git
PIN='你的PIN'
```

---

## 使用方式

### 1. 看卡片資訊

```bash
pkcs11-tool --module "$MOD" -L

# 列出支援的密碼機制、金鑰長度與操作 flags
pkcs11-tool --module "$MOD" -M
```

### 2. 列物件／憑證

未登入時看不到私鑰。

```bash
# 全部物件
pkcs11-tool --module "$MOD" -O

# 只列憑證
pkcs11-tool --module "$MOD" --list-objects --type cert
```

### 3. 讀出憑證（轉 PEM）

`pkcs11-tool` 讀出的是 DER：

```bash
pkcs11-tool \
  --module "$MOD" \
  --read-object --type cert --id 5349474e \
  --output-file sign-cert.der

openssl x509 -inform DER -in sign-cert.der -out sign-cert.pem
openssl x509 -in sign-cert.pem -noout -subject -issuer -dates
```

或直接印到終端：

```bash
pkcs11-tool \
  --module "$MOD" \
  --read-object --type cert --id 5349474e \
  --output-file /dev/stdout \
| openssl x509 -inform DER -outform PEM
```

### 4. 數位簽章

```bash
echo 'hello open-gpki' > msg.txt

pkcs11-tool \
  --module "$MOD" \
  --login --pin "$PIN" \
  --sign --mechanism SHA256-RSA-PKCS \
  --id 5349474e \
  --input-file msg.txt \
  --output-file sig.bin
```

用憑證公鑰驗證：

```bash
openssl x509 -inform DER -in sign-cert.der -pubkey -noout > sign-pub.pem
openssl dgst -sha256 -verify sign-pub.pem -signature sig.bin msg.txt
# → Verified OK
```

### 5. 資料解密

先用 KEYX 憑證的**公鑰**加密，再用卡片**私鑰**解密：

```bash
pkcs11-tool --module "$MOD" \
  --read-object --type cert --id 4b455958 -o keyx-cert.der
openssl x509 -inform DER -in keyx-cert.der -pubkey -noout > keyx-pub.pem

printf 'hello open-gpki decrypt' > plain.txt
openssl pkeyutl -encrypt -pubin -inkey keyx-pub.pem \
  -in plain.txt -out cipher.bin

pkcs11-tool \
  --module "$MOD" \
  --login --pin "$PIN" \
  --decrypt --mechanism RSA-PKCS \
  --id 4b455958 \
  --input-file cipher.bin \
  --output-file plain-out.bin

cmp plain.txt plain-out.bin && echo '解密正確'
```

### 6. 驗證簽章

驗簽只需要公鑰，不必登入：

```bash
pkcs11-tool \
  --module "$MOD" \
  --verify --mechanism SHA256-RSA-PKCS \
  --id 5349474e \
  --input-file msg.txt \
  --signature-file sig.bin
# → Signature is valid
```

`RSA-PKCS`、`RSA-X-509`、`MD5-RSA-PKCS`、`SHA1`／`SHA256`／`SHA384`／`SHA512-RSA-PKCS` 均支援
`C_Verify` 與 `C_VerifyUpdate`／`C_VerifyFinal`。

### 7. 產生安全亂數

```bash
pkcs11-tool --module "$MOD" --generate-random 32 --output-file random.bin
wc -c random.bin
# → 32
```

此功能使用主機端安全亂數來源，不會向卡片送 APDU。

---

## 注意事項

- **PIN 錯誤會扣除重試次數**，請勿連續亂試。
- 一代 T7S 不可送明文 VERIFY；模組內部使用 3DES 保護格式送出 PIN。
- 目前主要驗證：T7S 系列、2048-bit RSA。其他世代／金鑰長度尚未取樣。
- Windows x86_64 已實卡驗證（讀憑證／登入／簽章／加解密／摘要／亂數）。
- `pkcs11-tool --encrypt`：token 宣告 `login required` 時，非互動環境請加 `--pin`（否則會停在等 PIN）；公鑰加密本身不需登入。

---

## 目錄結構

```text
open-gpki-pkcs11/
  Cargo.toml
  Makefile
  src/
    lib.rs              # 匯出 C_GetFunctionList
    pcsc.rs             # PC/SC
    apdu/
      mod.rs            # 卡世代偵測、共用 SELECT／READ
      gen1.rs           # 一代卡
      gen2.rs           # 二代卡（GPPKI + SCP03）
    der.rs / p15.rs     # DER、PKCS#15 物件
    pkcs11/             # Cryptoki 實作
  scripts/
    build-windows.ps1   # Windows 本機建置
    build-windows.cmd
  docker/               # Linux 交叉編譯 Dockerfile
  build/                # open-gpki-pkcs11-<os>-<arch>.dylib／.so／.dll
```

---

## 授權

LGPL-2.1-or-later。詳見 `LICENSE`。
