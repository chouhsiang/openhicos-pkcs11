# 官方 HiCOS 模組支援的機制（`-M`）

來源：

```bash
pkcs11-tool --module ref/libHicos_p11v1.dylib -M
```

擷取日期：2026-08-05（實卡插入時；一代／二代卡宣告相同）

---

## 原始輸出

```text
Supported mechanisms:
  RSA-PKCS-KEY-PAIR-GEN, keySize={2048,2048}, hw, generate_key_pair
  SHA1-RSA-PKCS, keySize={2048,2048}, hw, sign, verify
  RSA-X-509, keySize={2048,2048}, hw, encrypt, decrypt, sign, verify, wrap, unwrap
  RSA-PKCS, keySize={2048,2048}, hw, encrypt, decrypt, sign, verify, wrap, unwrap
  RSA-PKCS-OAEP, keySize={1024,2048}, hw, encrypt, decrypt
  MD5-RSA-PKCS, keySize={2048,2048}, hw, sign, verify
  SHA256-RSA-PKCS, keySize={2048,2048}, hw, sign, verify
  SHA384-RSA-PKCS, keySize={2048,2048}, hw, sign, verify
  SHA512-RSA-PKCS, keySize={2048,2048}, hw, sign, verify
  RSA-PKCS-PSS, keySize={2048,2048}, hw, sign
  SHA1-RSA-PKCS-PSS, keySize={2048,2048}, hw, sign
  SHA256-RSA-PKCS-PSS, keySize={2048,2048}, hw, sign
  SHA384-RSA-PKCS-PSS, keySize={2048,2048}, hw, sign
  SHA512-RSA-PKCS-PSS, keySize={2048,2048}, hw, sign
  MD5, digest
  SHA-1, digest
  SHA256, digest
  SHA384, digest
  SHA512, digest
  SHA-1-HMAC, sign
  SHA-1-HMAC-GENERAL, sign
  SHA256-HMAC, sign
  mechtype-0x252, sign
  SHA384-HMAC, sign
  mechtype-0x262, sign
  SHA512-HMAC, sign
  mechtype-0x272, sign
  DES-KEY-GEN, keySize={64,64}, generate
  DES2-KEY-GEN, keySize={128,128}, generate
  DES3-KEY-GEN, keySize={192,192}, generate
  DES-ECB, keySize={64,64}, encrypt
  DES3-ECB, keySize={128,192}, encrypt, decrypt
  DES-CBC, keySize={64,64}, encrypt
  DES-CBC-PAD, keySize={64,64}, encrypt
  DES3-CBC, keySize={128,192}, encrypt, decrypt
  DES3-CBC-PAD, keySize={128,192}, encrypt, decrypt
  AES-KEY-GEN, keySize={128,256}, generate
  AES-ECB, keySize={128,256}, encrypt, decrypt
  AES-CBC, keySize={128,256}, encrypt, decrypt
  AES-CBC-PAD, keySize={128,256}, encrypt, decrypt
  DES-MAC-GENERAL, keySize={64,64}, sign
  DES-MAC, keySize={64,64}, sign
  DES3-MAC-GENERAL, keySize={128,192}, sign
  DES3-MAC, keySize={128,192}, sign
  AES-MAC-GENERAL, keySize={128,256}, sign
  AES-MAC, keySize={128,256}, sign
  ECDSA-KEY-PAIR-GEN, keySize={256,521}, hw, generate_key_pair, EC F_P, EC OID
  ECDSA, keySize={256,521}, hw, sign, EC F_P, EC uncompressed
  ECDSA-SHA256, keySize={256,521}, hw, sign, EC F_P, EC uncompressed
  ECDSA-SHA384, keySize={256,521}, hw, sign, EC F_P, EC uncompressed
  ECDSA-SHA512, keySize={256,521}, hw, sign, EC F_P, EC uncompressed
  ECDH1-DERIVE, keySize={256,521}, hw, derive, EC F_P
```

---

## 分類整理

### RSA

| 機制 | keySize | flags |
|------|---------|-------|
| `RSA-PKCS-KEY-PAIR-GEN` | 2048–2048 | hw, generate_key_pair |
| `RSA-X-509` | 2048–2048 | hw, encrypt, decrypt, sign, verify, wrap, unwrap |
| `RSA-PKCS` | 2048–2048 | hw, encrypt, decrypt, sign, verify, wrap, unwrap |
| `RSA-PKCS-OAEP` | 1024–2048 | hw, encrypt, decrypt |
| `SHA1-RSA-PKCS` | 2048–2048 | hw, sign, verify |
| `MD5-RSA-PKCS` | 2048–2048 | hw, sign, verify |
| `SHA256-RSA-PKCS` | 2048–2048 | hw, sign, verify |
| `SHA384-RSA-PKCS` | 2048–2048 | hw, sign, verify |
| `SHA512-RSA-PKCS` | 2048–2048 | hw, sign, verify |
| `RSA-PKCS-PSS` | 2048–2048 | hw, sign |
| `SHA1-RSA-PKCS-PSS` | 2048–2048 | hw, sign |
| `SHA256-RSA-PKCS-PSS` | 2048–2048 | hw, sign |
| `SHA384-RSA-PKCS-PSS` | 2048–2048 | hw, sign |
| `SHA512-RSA-PKCS-PSS` | 2048–2048 | hw, sign |

### Digest

| 機制 | flags |
|------|-------|
| `MD5` | digest |
| `SHA-1` | digest |
| `SHA256` | digest |
| `SHA384` | digest |
| `SHA512` | digest |

### HMAC

| 機制 | flags | 備註 |
|------|-------|------|
| `SHA-1-HMAC` | sign | |
| `SHA-1-HMAC-GENERAL` | sign | |
| `SHA256-HMAC` | sign | |
| `mechtype-0x252` | sign | 即 `SHA256-HMAC-GENERAL`（`CKM_SHA256_HMAC_GENERAL` = `0x252`） |
| `SHA384-HMAC` | sign | |
| `mechtype-0x262` | sign | 即 `SHA384-HMAC-GENERAL`（`0x262`） |
| `SHA512-HMAC` | sign | |
| `mechtype-0x272` | sign | 即 `SHA512-HMAC-GENERAL`（`0x272`） |

### DES／3DES

| 機制 | keySize | flags |
|------|---------|-------|
| `DES-KEY-GEN` | 64–64 | generate |
| `DES2-KEY-GEN` | 128–128 | generate |
| `DES3-KEY-GEN` | 192–192 | generate |
| `DES-ECB` | 64–64 | encrypt |
| `DES-CBC` | 64–64 | encrypt |
| `DES-CBC-PAD` | 64–64 | encrypt |
| `DES-MAC` | 64–64 | sign |
| `DES-MAC-GENERAL` | 64–64 | sign |
| `DES3-ECB` | 128–192 | encrypt, decrypt |
| `DES3-CBC` | 128–192 | encrypt, decrypt |
| `DES3-CBC-PAD` | 128–192 | encrypt, decrypt |
| `DES3-MAC` | 128–192 | sign |
| `DES3-MAC-GENERAL` | 128–192 | sign |

### AES

| 機制 | keySize | flags |
|------|---------|-------|
| `AES-KEY-GEN` | 128–256 | generate |
| `AES-ECB` | 128–256 | encrypt, decrypt |
| `AES-CBC` | 128–256 | encrypt, decrypt |
| `AES-CBC-PAD` | 128–256 | encrypt, decrypt |
| `AES-MAC` | 128–256 | sign |
| `AES-MAC-GENERAL` | 128–256 | sign |

### 橢圓曲線

| 機制 | keySize | flags |
|------|---------|-------|
| `ECDSA-KEY-PAIR-GEN` | 256–521 | hw, generate_key_pair, EC F_P, EC OID |
| `ECDSA` | 256–521 | hw, sign, EC F_P, EC uncompressed |
| `ECDSA-SHA256` | 256–521 | hw, sign, EC F_P, EC uncompressed |
| `ECDSA-SHA384` | 256–521 | hw, sign, EC F_P, EC uncompressed |
| `ECDSA-SHA512` | 256–521 | hw, sign, EC F_P, EC uncompressed |
| `ECDH1-DERIVE` | 256–521 | hw, derive, EC F_P |

---

## 備註

- 此為官方模組**宣告**的機制清單，不代表每種機制在實卡上皆可成功操作。
- `mechtype-0x252`／`0x262`／`0x272` 是 `pkcs11-tool` 未辨識名稱時印出的 raw ID，對應各 SHA-*-HMAC-GENERAL。
