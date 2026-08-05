# openhicos — AI / 開發者交接筆記

> 給下次啟動的 AI 或新協作者：先讀本檔，再讀 `ref/apdu.md`、`docs/apdu-notes.md`。
> 最後更新：2026-08-05

## 專案目標

獨立實作 **HiCOS 自然人憑證** 的 PKCS#11 模組，可直接給 `pkcs11-tool --module ...` 使用，**不依賴 OpenSC**，目標行為對齊官方 `libHicos_p11v1.dylib`（參考用，放在 `ref/`）。

**非** 內政部／中華電信官方軟體；clean-room，依 ISO 7816 / PKCS#15 與逆向 APDU 筆記。

---

## 目前狀態（2026-08-05）

| 項目 | 狀態 |
|------|------|
| 語言 | **Rust**（主線）；`pkcs11/*.c` 為舊 C 實作，僅供對照 |
| 建置 | `make` → `build/openhicos-pkcs11-<os>-<arch>.so` |
| `C_GetTokenInfo` / `-L` | ✅ 與官方一致（實卡 T7S 驗證過） |
| 憑證列舉 `-O --type cert` | ❌ 仍空（卡上非標準 PKCS#15 ODF 路徑） |
| Login / Sign / Decrypt | 程式碼已有，實卡需再驗 |

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

## 已完成工作（依時間序）

### 1. 初始 C 版 PKCS#11 模組

- `pkcs11/module.c` — 完整 `C_*` API skeleton
- `oh_pcsc.c` — PC/SC（macOS PCSC.framework）
- `oh_apdu.c` — APDU；後來發現 HiCOS 需 **CLA 0x80**
- `oh_p15.c` — PKCS#15 bind
- `oh_der.c`、`oh_sha.c`

### 2. 修正 TokenInfo（曾顯示錯誤資訊）

**問題**：`-L` 曾顯示 `中華電信研究所`、`openhicos`、`0000000000000000` 等——**不是幻覺**，是讀錯來源。

**原因**：
- 誤把 EF.DIR（2F00）的 **PKCS#15 應用 label**（`中華電信研究所`）當 token label
- TokenInfo 不在 PKCS#15 DF 下，而在 **MF/5030/5032**
- 序號在 **MF/0900/0903**（16 位元 ASCII）
- 型號由 **MF/0900/0905** 版本字串推得（`CHT V32N` → `T7S`）

**修正**（C 版 `oh_p15.c`，已移植到 Rust `src/p15.rs`）：
- `read_hicos_tokeninfo_ef()` — path `3F00/5030/5032`
- `read_hicos_card_number()` — path `3F00/0900/0903`
- `read_hicos_model()` — path `3F00/0900/0905`，含 `V32` → `T7S`
- 不再用 DIR label 覆寫 token label
- flags 加 `CKF_RNG`；pin min/max 6/8

### 3. APDU / 卡結構發現（逆向官方 dylib + opensc-tool 探測）

- **CLA 0x00 全拒**（6E00）；必須 **CLA 0x80**（對應 `HiCOS_SelFile`）
- EF.DIR 可讀，含 PKCS#15 AID 與 path `3F00/0800`
- 標準 PKCS#15 FID（5015、5031…）在 MF 下 **6A82**
- **DF 0900** 存在；0901–0910 可選；憑證非標準 ODF/CDF 解析
- 官方讀 cert 走 **`HiCOS_ReadCertData`** 等專有路徑，非純 PKCS#15

詳細 APDU 表見 `ref/apdu.md`（與 `docs/apdu-notes.md` 同源）。

### 4. 全專案改寫 Rust（2026-08-05）

```
src/
  lib.rs           # 匯出 C_GetFunctionList
  pcsc.rs          # pcsc crate
  apdu.rs          # CLA 偵測、SELECT/READ/PIN/MSE/PSO
  der.rs           # 最小 DER 解析
  p15.rs           # bind、TokenInfo、物件（CDF 等仍不完整）
  pkcs11/
    types.rs       # Cryptoki 型別（子集 2.40）
    module.rs      # 全部 C_* 實作
```

- 依賴：`pcsc`、`sha1`、`sha2`
- macOS release 需 `.cargo/config.toml` 的 `-Wl,-fixup_chains`，否則 dyld 報 `mis-aligned LINKEDIT`
- 舊 C 建置：`make -f Makefile.legacy`

### 5. 參考檔搬至 `ref/`

```
ref/
  libHicos_p11v1.dylib   # 官方 PKCS#11（約 5.9MB，僅供對照／測試）
  apdu.md                # 官方 dylib APDU 逆向筆記
```

---

## 目錄結構

```text
openhicos/
  AGENTS.md              ← 本檔（AI 交接）
  README.md              ← 使用者說明
  Cargo.toml
  Makefile               # Rust 預設建置
  Makefile.legacy        # C 版（可選）
  .cargo/config.toml     # macOS link fixup_chains
  src/                   # Rust 主線
  pkcs11/                # 舊 C 原始碼（reference）
  include/pkcs11.h       # 舊 C 用 Cryptoki 標頭
  ref/                   # 官方 dylib + apdu 筆記（勿提交 dylib 若 repo 公開）
  docs/apdu-notes.md     # 專案內 APDU 文件（與 ref/apdu.md 同內容）
  build/                 # 產物 openhicos-pkcs11-*.so
```

---

## 建置與測試

```bash
cd openhicos
make clean && make

# openhicos
pkcs11-tool --module ./build/openhicos-pkcs11-macos-arm64.so -L

# 官方對照
pkcs11-tool --module ./ref/libHicos_p11v1.dylib -L
pkcs11-tool --module ./ref/libHicos_p11v1.dylib -O --type cert

# openhicos（憑證仍可能為空）
pkcs11-tool --module ./build/openhicos-pkcs11-macos-arm64.so -O --type cert
```

---

## 待辦（優先序）

1. **憑證／金鑰列舉** — 逆向 `HiCOS_ReadCertData`、`HiCOS_Bind_CDF`、container 模型（cert1/cert2、k1/k3…）；非標準 PKCS#15 ODF
2. **實卡 Login / Sign / Decrypt** 端到端測試
3. hardware/firmware version（官方 1.0，openhicos 仍 0.0）— 找對應 EF
4. Windows Rust 建置（舊 C 有 `build-windows.bat` / CMake，Rust 未驗）
5. 若確認 Rust 穩定，可刪 `pkcs11/*.c` 或只留 `ref/`

---

## 設計決策備忘

- **thread_local CLA**（`apdu.rs`）：連線時 `reset_cla()`，首次 SELECT MF 試 0x80 再 0x00
- **全域狀態**（`module.rs`）：`Mutex<State>`，與 C 版 static 類似，非 thread-safe PKCS#11
- **不整合 OpenSC**：相關檔已移除（若 conversation 摘要提及）
- **commit**：使用者未要求時不要自動 git commit

---

## 常見陷阱（給 AI）

1. 不要把 EF.DIR 的 `0x50` label 當 `CK_TOKEN_INFO.label`
2. TokenInfo EF 路徑是 **MF/5030/5032**，不是 DF 5015 下的 5032
3. serial 在 **0903**，不是 TokenInfo DER 裡的 `M-EEEE...` octet string
4. macOS release `.dylib` 沒有 `-fixup_chains` 會無法 `dlopen`
5. `-O --type cert` 空 ≠ TokenInfo 錯；是物件發現路徑還沒實作完
