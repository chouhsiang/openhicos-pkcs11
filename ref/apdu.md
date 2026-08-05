# libHicos_p11v1.dylib — APDU 分析

> 來源檔：`libHicos_p11v1.dylib`（內政部簽署 HiCOS PKCS#11 中介庫，CHT PKCS#11 3.1.0.00009）  
> 分析方法：符號表、字串、常數區樣板、arm64 反組譯（`PCSC_SendAPDU` / `GpSelect` / `HiCOS_*` / `GpInitializeUpdate` 等）  
> 說明：多數 APDU 在執行期組裝，下列為**可從二進位還原的指令與樣板**；實際 `P1/P2/Lc/Data` 隨卡別與工作階段變動。

---

## 1. 傳輸路徑

```
應用 (C_Sign / C_Login …)
  → PKCS#11 實作
    → CardAPI / HiCOS_* / GPPKI_* / Star_*
      → Build_APDU / Build_APDU_02 / Build_APDU_03（可選：GP secure messaging wrap）
        → PCSC_SendAPDU / GPUtilSendAPDU / Star_SendAPDU
          → SCardTransmit (PCSC.framework)
            → 讀卡機 → HiCOS / GP 卡
```

### `PCSC_SendAPDU` 行為重點

- 真正送出呼叫：`SCardTransmit`
- 回傳處理會檢查 **SW1**：
  - `0x61`：尚有回應資料 → 後續發 **GET RESPONSE**
  - `0x6C`：Le 不正確 → 以 SW2 作為正確 Le 重送
- 成功狀態預期為 ISO 7816 的 `90 00`（函式以狀態字組判斷，非字串比對）

---

## 2. 已還原的核心 APDU

格式：`CLA INS P1 P2 [Lc Data] [Le]`

### 2.1 SELECT FILE / SELECT AID

| 用途 | APDU（典型） | 依據 |
|------|----------------|------|
| SELECT by AID | `CLA A4 04 P2 Lc AID` | `GpSelect`：`INS=0xA4`，`P1` 常為 `0x04`（by name/AID） |
| SELECT MF | `00 A4 00 00 02 3F 00` | `Card_SelectApplet` / `SelectPKIAPPLET` 路徑對 `FID=0x3F00` 呼叫 `Star_SelFile` |
| SELECT PKCS#15 DF | 先選 MF，再選 PKCS#15 applet/DF | 常數區含 PKCS#15 AID；另見 FID `5015` 等高頻常數 |

`GpSelect` 組包邏輯（arm64）：

1. `CLA` 取自卡物件欄位  
2. `INS P1` 以 `0x04A4` 半字寫入 → 位元組序為 **`A4 04`**  
3. `P2`、`Lc`、AID 資料由參數填入  
4. 透過函式指標送出（最終進 PC/SC）

#### 已嵌入的 AID

| AID (hex) | 意義 |
|-----------|------|
| `A0 00 00 00 63 50 4B 43 53 2D 31 35` | PKCS#15（ASCII 尾碼 `"PKCS-15"`） |
| `A0 00 00 02 83 00 00 06 22 01 00 01` | `SelectPKIAPPLET` 使用的 12-byte PKI Applet AID |
| `A0 00 00 01 51 …` | GlobalPlatform ISD 相關（庫內可見 `A000000151`） |

常數旁還可見卡／廠商標籤字串，例如：

- `TLETC812HiCOSV22`
- `CHTTL8f0HiCardV2`
- `CHTTLETC812HiCOS…`
- `EFTJCOP41v22s`

### 2.2 VERIFY PIN / CHANGE PIN

| 用途 | 典型 APDU | 說明 |
|------|-----------|------|
| VERIFY（一般） | `00 20 00 P2 Lc PIN` | `Card_VerifyPin`、`HiCOS_VerifyPin`、`GPPKI_VerifyPin` 等 |
| VERIFY（T7S） | `8C 20 00 01 20 IV(8) CIPHERTEXT(24)` | `HiCOSV3_VerifyPin`，安全訊息格式 |
| CHANGE REFERENCE DATA | `00 24 …` | `HiCOS_ChangeUserPin` / `HiCOS_ChangeSOPin` / `HiCOS_ChangeKey` |

觀察到的實作細節：

- 使用者 PIN 長度上限常見為 **10 bytes（`0x0A`）**
- T7S `HiCOSV3_VerifyPin` 會 SELECT `3F00/5030/0810`，再走 `HiCOS_VerifyKey`
- T7S 固定 2-key 3DES key 為 ASCII `CHTTL8f0HiCardV2`（16 bytes），ENC/MAC 相同
- PIN 以 `FF` 補到 10 bytes；host 產生 8-byte IV
- MAC = 3DES CBC-MAC（IV=host random、PKCS#7 padding）；再以同一 IV 對
  `PIN(10) || MAC(8)` 做 3DES CBC + PKCS#7，得到 24-byte ciphertext
- 若回 **`6A 88`**（referenced data not found），會改用另一組卡標籤字串重試（`CHTTL8f0HiCardV2` ↔ `TLETC812HiCOSV22`）
- PIN 緩衝會先以 `0xFF` 填滿再拷貝實際 PIN（常見智慧卡 padding 手法）

> 注意：庫內字串有 `HiCOS PKI Smart Card12345678` 這類樣貌字串，屬標籤／預設顯示材料，**不能當成正式 PIN**。

### 2.3 GET CHALLENGE / EXTERNAL AUTHENTICATE（HiCOS）

| 步驟 | APDU | 說明 |
|------|------|------|
| Get Challenge | `80 84 00 00 Le` | `HiCOS_GetChallenge` 將標頭存成 LE `0x8480` → 位元組 **`80 84`**，再附 `Le`（常見 8） |
| External Auth | （經 `doExternalAuth`） | `HiCOS_ExternAuth`：先 GetChallenge(8) → **3DES** 加密 host cryptogram → 送 External Auth；host cryptogram 長度需為 **16** |

這顯示 HiCOS 路徑對 Challenge 使用 **CLA=`80` 專有類**（非僅標準 `00 84`）。

### 2.4 GlobalPlatform Secure Channel（SCP）

用於 `HiGPPKIIDv1_SelectPKIAPPLET_SCP`、`HiGPPubCard_SelectPKIAPPLET_SCP`、`OpenSecureChannel` 等。

| 指令 | APDU 標頭（已還原） | 符號 |
|------|---------------------|------|
| INITIALIZE UPDATE | `80 50 P1 P2 08 <host challenge 8B> …` | `GpInitializeUpdate`（`strh 0x5080` → `80 50`） |
| EXTERNAL AUTHENTICATE | `84 82 …`（含 MAC） | `GpExternalAuth`（`strh 0x8284` → `84 82`） |

另有：

- `Build_APDU_02` → `wrap_command`（SCP 包裝）
- `Build_APDU_03` → `wrap_command_03`
- MAC：`calculate_MAC` / `calculate_MAC_des_3des`

### 2.5 MSE / PSO（簽章環境）

常數區可見固定樣板（ISO 7816-8 Manage Security Environment）：

```
00 22 41 A4 06 84 01 84 80 01 02
00 22 81 B8 06 84 01 82 80 01 02
00 22 41 B8 06 83 01 01 80 01 02
```

解讀（摘要）：

- `INS = 22`：MSE
- `P1/P2`：`41 A4` / `41 B8` / `81 B8` 等為 SET 變體
- 後續 TLV：`84`/`83` 指定金鑰參照，`80 01 02` 等為演算法／模式參數

PSO（Perform Security Operation，`INS=2A`）多半在執行期依機制組裝（RSA/ECDSA 簽章、加解密），對應上層：

- `CardAPI_PKCS1_V15_Sign` / `CardAPI_RSA_SignRaw` / `CardAPI_ECDSA_SIGN`
- `GPPKI_PKCS1_V15_Sign` / `HiCOSV3_PKCS1_V15_Sign`
- `Card_PKCS1_V1_5_Decrypt` 等

### 2.6 READ / UPDATE BINARY

| 操作 | 典型 INS | 實作 |
|------|----------|------|
| READ BINARY | `B0` | `HiCOSV2_ReadBinary` → `HiCOS_ReadB`；`CardAPI_Read_EF_*` |
| UPDATE BINARY | `D6` | `HiCOSV2_UpdateBinary` → `HiCOS_UpdateB`；`PKIUpdateBinary` |

分塊大小固定邏輯：**每塊最多 `0xC8`（200）bytes**，迴圈讀寫直到完成。

### 2.7 GET RESPONSE

當 `PCSC_SendAPDU` 看到 SW1=`61`，會再送：

```
00 C0 00 00 Le   （Le = SW2）
```

---

## 3. PKCS#15 檔案物件（經 APDU 讀取）

庫以 CardAPI / HiCOS_Bind_* 操作 PKCS#15 DF 內 EF（先 SELECT，再 READ BINARY）：

| EF／物件 | 相關符號 |
|----------|----------|
| PrKDF | `CardAPI_Read_EF_PrKDF` / `HiCOS_Bind_PrKDF` |
| PuKDF | `CardAPI_Read_EF_PuKDF` / `HiCOS_Bind_PuKDF` |
| CDF | `CardAPI_Read_EF_CDF` / `HiCOS_Bind_CDF` |
| DODF | `CardAPI_Read_EF_DODF` / `HiCOS_Bind_DODF` |
| AODF | `CardAPI_Read_EF_AODF` / `HiCOS_Bind_AODF` |
| TokenInfo | `CardAPI_Read_EF_TokenInfo` |
| UnusedSpace | `CardAPI_Read_EF_UnusedSpace` |
| 憑證資料 | `CardAPIReadCertData` / `CardAPIWriteCertData` |

---

## 3a. 實卡驗證的檔案配置（T7S / `CHT V32N`）

以 `SCardTransmit` 攔截官方模組 `pkcs11-tool -O` 取得的完整電文，還原出下列配置。
**沒有標準 PKCS#15 應用**：MF 下 `5015`／`5031` 一律回 `6A82`，官方也從不讀 ODF，
而是直接 SELECT 專有 DF 與固定 FID。

### DF 與目錄檔

所有存取都是 `SELECT 3F00` → `SELECT 5030` → `SELECT <FID>`，CLA 固定 `0x80`。

| FID | 內容 | 備註 |
|-----|------|------|
| `5030` | 專有 PKCS#15 DF | 取代標準 `5015` |
| `4100` | **PrKDF** | 物件帶 `authId`、commonObjectFlags 有 private 位元 |
| `4101` | **PuKDF** | 帶 `native=TRUE` |
| `4104` | **CDF** | |
| `4107` | **DODF** | |
| `4108` | **AODF**（推得，未實卡驗證） | |
| `5032` | TokenInfo | |
| `08F2` | 憑證資料 EF | 全部憑證串在同一檔，用 CDF 的 index/length 切片 |
| `0810`/`0811` | 公鑰 record EF | |
| `0870` | Data object 資料 EF | |

FID 編號規則：**對應 ODF 的 context tag**（PrKDF `[0]`→`4100`、PuKDF `[1]`→`4101`、
CDF `[4]`→`4104`、DODF `[7]`→`4107`），故 AODF `[8]` 推得為 `4108`。

目錄檔尾端 2 bytes 存內容長度（little-endian，官方以 `80 B0 <size_off> 02` 先讀），
但 SELECT 不回 FCP，官方是內建檔案大小表；改以「往後讀到 padding（`00`/`FF`）為止」
同樣可行。

### 憑證讀取

CDF 的 `X509CertificateAttributes` 內 Path 帶 index 與 length：

```
30 0F  04 06 3F00503008F2   -- path
       02 01 00             -- index（EF 內起始位移）
       80 02 06 08          -- [0] length
```

→ `SELECT 3F00/5030/08F2`，再 `80 B0 <index> C8` 分塊讀 `length` bytes。
實卡四張憑證位於 offset `0x0000`/`0x0700`/`0x0E00`/`0x1500`。

CDF 同時內含 subject / issuer / serialNumber，可不讀憑證本體就列出摘要；
但取 `CKA_VALUE` 仍需讀 `08F2`。

### 公鑰讀取（RSA）

公鑰在 `3F00/5030/0810/0811`，以 **READ RECORD** 取得，且 HiCOS 用非 ISO 的定址：

```
80 B2 <record> 00 81      -- P1=record 編號，P2=0x00，Le=129
```

每筆 record 129 bytes = `<record 編號 1 byte>` + `<128 bytes 資料>`。
以 PuKDF 的 `keyReference` 當基底：

| record | 內容 |
|--------|------|
| `ref + 0` | 公開指數，位於 offset 1..5（4 bytes big-endian，如 `00 01 00 01` = 65537） |
| `ref + 1` | 全零（未使用） |
| `ref + 2` | 模數高半 |
| `ref + 3` | 模數低半 |

**模數以 32-bit word 反序存放**：把 `rec[ref+2] || rec[ref+3]` 的 256 bytes
每 4 bytes 一組整組反轉，才會得到憑證裡的 big-endian 模數。實卡上
`keyReference` 為 `0x01` / `0x05` / `0x11`，已與憑證模數逐位元組核對一致。

---

## 4. 依卡別分流的 APDU 家族

`Card_SelectApplet` / `Card_VerifyPin` 依內部卡類型枚舉分流，至少包含：

| 家族 | 代表符號 | APDU 特徵 |
|------|----------|-----------|
| HiCOS V2 | `HiCOS_*`、`HiCOSV2_ReadBinary` | CLA `00`/`80` 混合；PIN／Binary／Challenge |
| HiCOS V3 | `HiCOSV3_VerifyPin`、`HiCOSV3_PKCS1_*` | V3 專用簽章／PIN |
| GPPKI ID v1 | `HiGPPKIIDv1_*`、`gpPKIidv1_Select*` | GP SELECT + SCP 後再 PKI |
| GP Pub Card | `HiGPPubCard_*`、`gpPubCA_Select*` | 同上，PubCA 變體 |
| StarCOS 路徑 | `Star_SendAPDU`、`Star_SelFile`、`Star_VerifyPin` | 另套 SELECT/VERIFY 實作 |
| 其他 | `EFTJCOP41v22s`、`StartCOS`、字串 `CHT V21N`–`V32N` | 多卡相容表 |

字串區可見中華電信／HiCOS 版本標籤：`CHT V21N`、`CHT V22N`、`CHT V31N`、`CHT V32N`。

---

## 5. 典型工作階段（邏輯順序）

### 5.1 開啟 token / 登入

1. `SCardConnect`  
2. SELECT MF：`… 3F00`  
3. SELECT PKI Applet（AID `A00000028300000622010001` 或 PKCS#15 AID）  
4. （若 GP 卡）`80 50` Initialize Update → `84 82` External Authenticate  
5. VERIFY PIN：依卡別使用明文 VERIFY 或 T7S `8C 20` 安全格式  
6. 讀 PrKDF／CDF／憑證 EF（SELECT + READ BINARY 分塊）

### 5.2 簽章

T7S / 2048-bit RSA 的實卡流程：

1. host 建立 `00 01 FF…FF 00 DigestInfo`（256 bytes）  
2. `80 EA 82 <keyRef> 80 <block[0..128]>`  
3. `80 EA 02 <keyRef> 80 <block[128..256]>`，回簽章前 128 bytes  
4. `80 C1 00 80 80`，回簽章後 128 bytes

此路徑不使用 MSE/PSO；官方與 openhicos 對同一訊息的 256-byte
SHA256-RSA-PKCS 簽章已逐位元組核對一致。

### 5.3 變更 PIN

1. 已登入狀態  
2. CHANGE REFERENCE DATA / HiCOS Change PIN 專有指令（`HiCOS_ChangeUserPin`）

---

## 6. 主要 APDU 相關符號清單（摘錄）

| 符號 | 角色 |
|------|------|
| `PCSC_SendAPDU` | PC/SC 傳送與 61/6C 處理 |
| `GPUtilSendAPDU` / `Star_SendAPDU` | 上層傳送封裝 |
| `Build_APDU` / `_02` / `_03` | 組 APDU；02/03 含 SCP wrap |
| `GpSelect` / `GPUtil_Select` | SELECT |
| `GpInitializeUpdate` / `GpExternalAuth` | GP SCP |
| `Card_SelectApplet` / `SelectPKIAPPLET` | 選 applet |
| `Card_VerifyPin` / `HiCOS_VerifyPin` / `HiCOSV3_VerifyPin` | 驗 PIN |
| `HiCOS_GetChallenge` / `HiCOS_ExternAuth` | 挑戰／外部認證 |
| `HiCOSV2_ReadBinary` / `HiCOSV2_UpdateBinary` | 二進位讀寫 |
| `PKISelectFile` / `PKISelectFileFCP` / `PKIUpdateBinary` | PKI 檔案選取／更新 |
| `CardAPI_Read_EF_*` / `CardAPI_*Sign*` | PKCS#15／密碼運算 |

---

## 7. 狀態字（從程式邏輯可見）

| SW | 意義（ISO 7816 / 程式處理） |
|----|------------------------------|
| `90 00` | 成功 |
| `61 XX` | 尚有 XX bytes → GET RESPONSE |
| `6C XX` | Le 錯，改用 XX 重送 |
| `6A 88` | Referenced data not found（`HiCOS_VerifyPin` 分支重試） |
| `67 10` | `HiCOS_ExternAuth` 在長度不為 16 時回傳的錯誤碼路徑 |

---

## 8. 限制與聲明

1. 本文件由**靜態分析**得出，不是官方 APDU 規格書全文。  
2. 許多指令的 `P1/P2/Data` 在執行期依 key container、機制、FCP 內容填入，無法在庫內做成單一固定 hex。  
3. GP `80/84` 與 HiCOS `80 84` 並存：同一 CLA 值在不同指令集意義不同，分析時需依呼叫堆疊區分。  
4. 若需完整「每一步實際電文」，應在真實讀卡環境用 PC/SC 嗅探（或 `pcsctool`／系統 log）對照本文件驗證。

---

## 9. 一句話結論

`libHicos_p11v1.dylib` 的 APDU 層是 **ISO 7816 檔案選取／PIN／Binary I/O + PKCS#15 物件讀取 +（可選）GlobalPlatform SCP + HiCOS 專有 Challenge/Auth/Sign** 的組合；對外統一收斂到 **`SCardTransmit`**，對上則服務完整 PKCS#11 `C_*` API。
