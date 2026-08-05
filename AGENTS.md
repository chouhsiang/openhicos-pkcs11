# openhicos — AI / 開發者交接筆記

Repository: https://github.com/chouhsiang/openhicos-pkcs11

> 給下次啟動的 AI 或新協作者：先讀本檔，再讀 `ref/apdu.md`。
> 最後更新：2026-08-05

## 專案目標

獨立實作 **HiCOS 自然人憑證** 的 PKCS#11 模組，可直接給 `pkcs11-tool --module ...` 使用，**不依賴 OpenSC**，目標行為對齊官方 `libHicos_p11v1.dylib`（參考用，放在 `ref/`）。

**非** 內政部／中華電信官方軟體；clean-room，依 ISO 7816 / PKCS#15 與逆向 APDU 筆記。

語言：**Rust only**（舊 C 實作已移除）。

---

## 目前狀態（2026-08-05）

| 項目 | 狀態 |
|------|------|
| 語言 | **Rust** |
| 建置 | `make` → `build/openhicos-pkcs11-<os>-<arch>.so` |
| `C_GetTokenInfo` / `-L` | ✅ 與官方一致（實卡 T7S 驗證過） |
| 物件列舉 `-O` | ✅ **與官方逐行一致**（3 公鑰 + 4 憑證 + 2 data object） |
| 憑證讀出 `-r --type cert` | ✅ openssl 可完整解析 |
| 公鑰讀出 `-r --type pubkey` | ✅ 模數與憑證逐位元組相符 |
| Login | ✅ T7S 安全 VERIFY，實卡驗證 |
| Sign | ✅ RSA-PKCS / SHA1 / SHA256 均與官方逐位元組一致，openssl `Verified OK` |
| Decrypt | 程式碼已有，實卡需再驗 |

### 實卡驗證環境（使用者機器）

- Reader: `Generic USB2.0-CRW`
- ATR: `3b:b8:13:00:81:31:fa:52:43:48:54:4d:4f:49:43:41:a5`（含 `CHTMOICA`）
- 官方 `-L` 基準：
  - label: `HiCOS PKI Smart Card`
  - manufacturer: `Chunghwa TeleCom Co., Ltd.`
  - model: `T7S`
  - serial: `MT00000002872688`
  - pin: `6/8`
  - flags: `login required, rng, token initialized, PIN initialized`

---

## 關鍵發現（摘要）

### TokenInfo（勿再踩坑）

- **不要**把 EF.DIR（2F00）的 PKCS#15 應用 label（`中華電信研究所`）當 token label
- TokenInfo 在 **MF/5030/5032**（不是 DF 5015 下的 5032）
- 序號在 **MF/0900/0903**（16 位元 ASCII）
- 型號由 **MF/0900/0905** 版本字串推得（`CHT V32N` → `T7S`）
- flags 含 `CKF_RNG`；pin min/max 6/8

實作：`src/p15.rs` 的 `read_hicos_tokeninfo_ef` / `read_hicos_card_number` / `read_hicos_model`

### APDU / 卡結構

- **CLA 0x00 全拒**（6E00）；必須 **CLA 0x80**
- EF.DIR 可讀，含 PKCS#15 AID 與 path `3F00/0800`
- 標準 PKCS#15 FID（5015、5031…）在 MF 下 **6A82**；**官方也從不讀 ODF**

### 物件配置（已用 APDU 攔截驗證）

PKCS#15 目錄檔在 **`MF/5030`** 下，FID 對應 ODF 的 context tag：

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

公鑰用 **READ RECORD**（`80 B2 <rec> 00 81`，非 ISO 的 P2=04）：
`keyRef+0` 是指數、`keyRef+2`/`+3` 是模數兩半，且模數以 **32-bit word 反序**存放。

詳細 APDU 表與電文見 `ref/apdu.md` 第 3a 節。

### T7S 安全登入與簽章

- PIN VERIFY 不是明文 `80 20`，而是 `8C 20 00 01 20`：
  - 固定 2-key 3DES key：`CHTTL8f0HiCardV2`
  - 8-byte host random 當 IV
  - PIN 補 `FF` 到 10 bytes
  - CBC-MAC 與 CBC encryption 都使用 PKCS#7 padding
- RSA 簽章由 host 建立 256-byte PKCS#1 v1.5 block，再送：
  - `80 EA 82 <keyRef> 80 <前半>`
  - `80 EA 02 <keyRef> 80 <後半>`
  - `80 C1 00 80 80` 讀回後半簽章
- 實卡以相同訊息比較官方與 openhicos，兩份 256-byte 簽章 SHA-256 都是
  `eafadf6111b922c61c1f16553eb2f64d03e89c44992c7b911ea35cf76742769b`。

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
    apdu.rs          # CLA 偵測、SELECT/READ/PIN/MSE/PSO
    der.rs           # 最小 DER 解析
    p15.rs           # bind、TokenInfo、物件（CDF 等仍不完整）
    pkcs11/
      types.rs       # Cryptoki 型別（子集 2.40）
      module.rs      # 全部 C_* 實作
  ref/
    libHicos_p11v1.dylib  # 官方對照（勿公開提交）
    apdu.md               # APDU 逆向筆記
  build/             # 產物
```

依賴：`pcsc`、`sha1`、`sha2`、`des`、`getrandom`

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

1. **實卡 Decrypt** 端到端測試
2. AODF `4108` 的 pin_ref 解析仍待驗（T7S 登入實際固定使用 P2=`01`）
3. Windows Rust 建置（未驗）
4. 非 2048-bit 金鑰、其他 HiCOS 世代（V2 / GPPKI）的 record 配置未取樣

---

## 設計決策備忘

- **thread_local CLA**（`apdu.rs`）：連線時 `reset_cla()`，首次 SELECT MF 試 0x80 再 0x00
- **全域狀態**（`module.rs`）：`Mutex<State>`，非 thread-safe PKCS#11
- **不整合 OpenSC**
- **commit**：使用者未要求時不要自動 git commit

---

## 常見陷阱（給 AI）

1. 不要把 EF.DIR 的 `0x50` label 當 `CK_TOKEN_INFO.label`
2. TokenInfo EF 路徑是 **MF/5030/5032**
3. serial 在 **0903**，不是 TokenInfo DER 裡的 `M-EEEE...` octet string
4. macOS release `.dylib` 沒有 `-fixup_chains` 會無法 `dlopen`
5. `CKR_ATTRIBUTE_TYPE_INVALID` 是 **0x12**（0x13 是 `CKR_ATTRIBUTE_VALUE_INVALID`）；
   寫錯會讓 `pkcs11-tool` 對每個物件噴 warning
6. `CKA_OBJECT_ID` 給 **OID 內容**（`40`），不是完整 DER TLV（`06 01 40`），
   否則 `app_id` 會印成 `0.6.1.64` 而非 `1.24`
7. 公鑰模數的 32-bit word 反序容易漏；沒反轉會得到看似合理但錯誤的模數
8. 官方 `-L`／uri 的 model 尾端有一個 tab、manufacturer 尾端有空白，是官方沒修剪；
   我們有 trim，故 uri 字串會有差異，屬預期
9. T7S 不可送明文 PIN；官方用 `8C 20` 的 3DES 保護格式。錯誤時也只能驗一次，
   不可依序嘗試多個 pin_ref，否則會一次扣掉多次重試次數
