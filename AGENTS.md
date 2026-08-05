# openhicos — AI / 開發者交接筆記

Repository: https://github.com/chouhsiang/openhicos-pkcs11

> 給下次啟動的 AI 或新協作者：先讀本檔，再讀 `ref/apdu.md`。
> 最後更新：2026-08-05

## 專案目標

獨立實作 **HiCOS** PKCS#11 模組，可直接給 `pkcs11-tool --module ...` 使用，**不依賴 OpenSC**，目標行為對齊官方 `libHicos_p11v1.dylib`（參考用，放在 `ref/`）。

**非** 內政部／中華電信官方軟體；clean-room，依 ISO 7816 / PKCS#15 與逆向 APDU 筆記。

語言：**Rust only**（舊 C 實作已移除）。

> **命名**：APDU 分檔依**卡世代**，不依機關（工商／自然人）。
> - `gen1`＝一代卡（CLA `0x80`、`8C 20`、`80 EA`/`C1`）— 含工商與一代自然人
> - `gen2`＝二代卡（GPPKI AID + SCP03）

---

## 目前狀態（2026-08-05）

| 項目 | 一代卡（gen1） | 二代卡（gen2 / GPPKI） |
|------|----------------|------------------------|
| 語言 | **Rust** | 同左 |
| 建置 | `make` → `build/openhicos-pkcs11-<os>-<arch>.so` | 同左 |
| 偵測 | CLA `0x80` SELECT MF | SELECT GPPKI AID 優先 |
| `C_GetTokenInfo` / `-L` | ✅ | ✅ 與官方一致（含 model `T7S…`） |
| 物件列舉 `-O` | ✅ | ✅ 與官方逐行一致（未登入無 privkey） |
| 憑證讀出 | ✅ | ✅ |
| 公鑰讀出 | ✅ word-reverse records | ✅ `80 B2 keyRef 03/04` 直讀兩半 |
| Login | ✅ `8C 20` 3DES | ✅ Diverse + SCP03 + SM VERIFY |
| Sign | ✅ `80 EA` / `80 C1` | ✅ `84 EA` / `84 C1`（簽前重開 SCP） |
| Decrypt | ✅ `80 EA`/`C1` + type-2 unpad；OAEP 則 raw + host unpad | ✅ 同左（`84 EA`/`C1`） |
| Encrypt | ✅ host RSA-PKCS／OAEP（公鑰） | 同左 |
| Digest / `--hash` | ✅ host MD5／SHA-1/256/384/512 | 同左 |
| Verify | ✅ host RSA（one-shot／multipart） | 同左 |
| GenerateRandom | ✅ OS CSPRNG（無卡片 APDU） | 同左 |
| MechanismInfo | ✅ 含 digest／OAEP flags | 同左 |

### 實卡驗證環境（使用者機器）

- Reader: `Generic USB2.0-CRW`
- **一代／工商**：model `T7S`；Login／Sign／Decrypt 與官方一致
- **一代／自然人**：model `T7S`；走 gen1；憑證／簽章／解密與官方一致
- **二代／自然人**：model `T7S…`；Login／Sign／Decrypt 與官方一致
- （serial 等識別資訊不寫入公開文件）

### Host 端功能

- `C_Sign*`／`C_Verify*`：`RSA-PKCS`、`RSA-X-509`、`MD5`／`SHA1`／`SHA256`／`SHA384`／`SHA512-RSA-PKCS`。
  Hash 機制在 host 組 DigestInfo 後走卡片 PKCS#1 type-1；`RSA-X-509` 為 raw 256-byte。
- `C_Encrypt*`／`C_Decrypt*`：`RSA-PKCS`、`RSA-X-509`、`RSA-PKCS-OAEP`。X.509 為 raw（無 padding）。
  OpenSC 0.26+ `pkcs11-tool --encrypt` 僅接受 OAEP（不接受 `RSA-PKCS`／`RSA-X-509`）。
- `C_GenerateRandom`：使用 OS CSPRNG。攔截官方模組確認其 GenerateRandom 也未送亂數 APDU。
- `C_GetMechanismInfo`：RSA／OAEP／digest 依實作宣告 flags。

---

## 關鍵發現（摘要）

### 雙卡 profile（`apdu::CardProfile`）

1. 先試 SELECT AID `A0000002830000062201696400010101`（P2=`0C`）→ **Gen2**
2. 否則 CLA 探測 SELECT MF → **Gen1**

APDU 實作分檔：`src/apdu/gen1.rs`、`src/apdu/gen2.rs`。

### TokenInfo（勿再踩坑）

- **不要**把 EF.DIR（2F00）的 PKCS#15 應用 label（`中華電信研究所`）當 token label
- TokenInfo 在 **5030/5032**（gen1：MF 下；gen2：ADF 下，路徑可含 `7FFF`）
- 序號在 **0900/0903**（16 位元 ASCII）；gen2 的 TokenInfo DER 內也有相同 octet string
- gen1 model：`CHT V32N` → `T7S`
- gen2 model：`T7` + (`S` if V32 else `U`) + `convertBinarySerialNumberToASCII(0903[0..8])` 取 12 位
- flags 含 `CKF_RNG`；pin min/max 6/8

### APDU / 卡結構

**一代（gen1 / HiCOS V3 style）**
- **CLA 0x00 全拒**（6E00）；必須 **CLA 0x80**
- EF.DIR 可讀；標準 PKCS#15 FID 在 MF 下 **6A82**；官方從不讀 ODF
- Login：`8C 20` 3DES；Sign／Decrypt：`80 EA` / `80 C1`

**二代（gen2 / GPPKI）**
- 必須先 SELECT GPPKI applet AID；其後 CLA `00` 的 SELECT/READ BINARY
- PKCS#15 目錄仍在 `5030` 下（`4100`/`4101`/`4104`/…），CDF path 形如 `7FFF503008F2`
- 公鑰：SELECT `0810`→`0811` 後 `80 B2 <keyRef> 03/04 00`（CLA 仍為 **0x80**），兩段 128-byte 直接串成模數，**不**做 32-bit word 反序；指數固定 65537
- Login：`Diverse` 自卡片 GET DATA 衍生 ENC/MAC/DEK → SCP03 → `04 20` SM VERIFY
- Sign／Decrypt 前官方會重開 SCP、再 VERIFY，並 SM SELECT `5030`/`0810`，再 `84 EA`/`84 C1`
- **不要**對 gen2 送 gen1 的 `8C 20`

### 物件配置（已用 APDU 攔截驗證）

PKCS#15 目錄檔在 **`5030`** 下，FID 對應 ODF 的 context tag：

| FID | 內容 |
|-----|------|
| `4100` | PrKDF |
| `4101` | PuKDF |
| `4104` | CDF |
| `4107` | DODF |
| `4108` | AODF（由編號規則推得，未實卡驗證） |
| `5032` | TokenInfo |
| `08F2` | 憑證資料（**全部憑證同一個 EF**，用 CDF 的 index/length 切片） |
| `0810/0811` | 公鑰 record EF |
| `0870` | Data object 資料 |

gen1 公鑰用 **READ RECORD**（`80 B2 <rec> 00 81`）：
`keyRef+0` 是指數、`keyRef+2`/`+3` 是模數兩半，且模數以 **32-bit word 反序**存放。

詳細 APDU 表與電文見 `ref/apdu.md`。

### Gen1 安全登入與簽章

- PIN VERIFY 不是明文 `80 20`，而是 `8C 20 00 01 20`：
  - 固定 2-key 3DES key：`CHTTL8f0HiCardV2`
  - 8-byte host random 當 IV
  - PIN 補 `FF` 到 10 bytes
  - CBC-MAC 與 CBC encryption 都使用 PKCS#7 padding
- RSA 簽章由 host 建立 256-byte PKCS#1 v1.5 block，再送：
  - `80 EA 82 <keyRef> 80 <前半>`
  - `80 EA 02 <keyRef> 80 <後半>`
  - `80 C1 00 80 80` 讀回後半簽章

### 逆向手法（可重複）

用 `DYLD_INSERT_LIBRARIES` 攔截 `SCardTransmit` 抓官方模組的真實電文，比純靜態
反組譯可靠得多。`pkcs11-tool` 只有 adhoc 簽名、無 hardened runtime，可直接插入：

```bash
DYLD_INSERT_LIBRARIES=/path/apdutrace.dylib \
  pkcs11-tool --module ref/libHicos_p11v1.dylib -O
```

攔截器用 `__DATA,__interpose` section 取代 `SCardTransmit`，把 `>>`/`<<` 十六進位
電文寫到檔案，再和自家模組的 trace 對 diff。

---

## 目錄結構

```text
openhicos/
  AGENTS.md          ← 本檔
  README.md
  Cargo.toml
  Makefile
  .cargo/config.toml # macOS -Wl,-fixup_chains
  src/
    lib.rs           # 匯出 C_GetFunctionList
    pcsc.rs          # pcsc crate
    apdu/
      mod.rs         # 共用 SELECT/READ、profile 偵測、dispatch
      gen1.rs        # 一代卡 VERIFY/Sign（CLA 0x80）
      gen2.rs        # 二代卡 AID / SCP03 / pubkey record
    der.rs           # 最小 DER 解析
    p15.rs           # bind、TokenInfo、物件
    pkcs11/
      types.rs       # Cryptoki 型別（子集 2.40）
      module.rs      # 全部 C_* 實作
  ref/
    libHicos_p11v1.dylib  # 官方對照（勿公開提交）
    apdu.md               # APDU 逆向筆記
  build/             # 產物
```

依賴：`pcsc`、`sha1`、`sha2`、`des`、`aes`、`cmac`、`cipher`、`getrandom`

---

## 建置與測試

```bash
make clean && make

pkcs11-tool --module ./build/openhicos-pkcs11-macos-arm64.so -L
pkcs11-tool --module ./ref/libHicos_p11v1.dylib -L
pkcs11-tool --module ./build/openhicos-pkcs11-macos-arm64.so -O --type cert
pkcs11-tool --module ./build/openhicos-pkcs11-macos-arm64.so --login \
  --sign --mechanism SHA256-RSA-PKCS --id 5349474e -i msg.bin -o sig.bin
```

---

## 待辦（優先序）

1. AODF `4108` 的 pin_ref 解析仍待驗（T7S 登入實際固定使用 P2=`01`）
2. Windows Rust 建置（未驗）
3. 非 2048-bit 金鑰、其他 HiCOS 世代的 record 配置未取樣
4. gen2 Diverse 目前僅實作 16-byte master blob 路徑
---

## 設計決策備忘

- **thread_local profile／CLA**（`apdu/mod.rs`）：`detect_and_select()` 鎖定 `Gen1` 或 `Gen2`
- **全域狀態**（`module.rs`）：`Mutex<State>`，非 thread-safe PKCS#11
- **不整合 OpenSC**
- **commit**：使用者未要求時不要自動 git commit

---

## 常見陷阱（給 AI）

1. 不要把 EF.DIR 的 `0x50` label 當 `CK_TOKEN_INFO.label`
2. TokenInfo EF 路徑是 **5030/5032**（gen2 在 AID 之下，不是裸 MF）
3. serial 在 **0903**；gen1 不要用 TokenInfo DER 裡的 `M-EEEE...` octet string
4. macOS release `.dylib` 沒有 `-fixup_chains` 會無法 `dlopen`
5. `CKR_ATTRIBUTE_TYPE_INVALID` 是 **0x12**（0x13 是 `CKR_ATTRIBUTE_VALUE_INVALID`）；
   寫錯會讓 `pkcs11-tool` 對每個物件噴 warning
6. `CKA_OBJECT_ID` 給 **OID 內容**（`40`），不是完整 DER TLV（`06 01 40`），
   否則 `app_id` 會印成 `0.6.1.64` 而非 `1.24`
7. gen1 公鑰模數的 32-bit word 反序容易漏；gen2 **不要**反轉
8. 官方 `-L`／uri 的 model 尾端有一個 tab、manufacturer 尾端有空白，是官方沒修剪；
   我們有 trim，故 uri 字串會有差異，屬預期
9. gen1 T7S 不可送明文 PIN；官方用 `8C 20` 的 3DES 保護格式。錯誤時也只能驗一次，
   不可依序嘗試多個 pin_ref，否則會一次扣掉多次重試次數
10. gen2 登入走 SCP03，金鑰經 `Diverse` 自卡內資料衍生；**不要**對 gen2 送 `8C 20`
11. 分檔是 **gen1/gen2（卡世代）**，不是機關名稱；一代自然人與工商都走 gen1
