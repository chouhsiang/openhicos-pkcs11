/*
 * openhicos-pkcs11 — standalone PKCS#11 module
 * Clean-room. Not affiliated with MOI / CHT.
 */

#include "pkcs11.h"
#include "oh_pcsc.h"
#include "oh_apdu.h"
#include "oh_p15.h"
#include "oh_sha.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OH_MAX_SLOTS    8
#define OH_MAX_SESSIONS 16

typedef struct {
	int in_use;
	CK_SLOT_ID slot;
	CK_FLAGS flags;
	CK_STATE state;
	int logged_in;

	int find_active;
	CK_OBJECT_HANDLE find_handles[OH_MAX_OBJS];
	CK_ULONG find_count;
	CK_ULONG find_pos;

	int sign_active;
	CK_OBJECT_HANDLE sign_key;
	CK_MECHANISM_TYPE sign_mech;
	unsigned char sign_buf[8192];
	size_t sign_len;

	int decrypt_active;
	CK_OBJECT_HANDLE decrypt_key;
	CK_MECHANISM_TYPE decrypt_mech;
} oh_session_t;

typedef struct {
	int present;
	char reader[128];
	oh_pcsc_t pcsc;
	oh_token_t token;
} oh_slot_t;

static int g_initialized;
static oh_slot_t g_slots[OH_MAX_SLOTS];
static CK_ULONG g_nslots;
static oh_session_t g_sessions[OH_MAX_SESSIONS];

static void
fill_blank(CK_UTF8CHAR *dst, size_t n, const char *src)
{
	size_t i, sl = src ? strlen(src) : 0;
	for (i = 0; i < n; i++)
		dst[i] = (i < sl) ? (CK_UTF8CHAR)src[i] : (CK_UTF8CHAR)' ';
}

static oh_session_t *
session_get(CK_SESSION_HANDLE h)
{
	if (h == 0 || h > OH_MAX_SESSIONS)
		return NULL;
	if (!g_sessions[h - 1].in_use)
		return NULL;
	return &g_sessions[h - 1];
}

static CK_RV
ensure_card(CK_SLOT_ID slot)
{
	oh_slot_t *s;
	if (slot >= g_nslots)
		return CKR_SLOT_ID_INVALID;
	s = &g_slots[slot];
	if (!s->present)
		return CKR_TOKEN_NOT_PRESENT;
	if (!s->pcsc.connected) {
		oh_apdu_reset_cla();
		if (oh_pcsc_connect(&s->pcsc, s->reader) != 0)
			return CKR_DEVICE_ERROR;
		if (oh_p15_bind(&s->pcsc, &s->token) != 0) {
			/* Still allow session; token may be empty */
		}
	} else if (!s->token.bound) {
		(void)oh_p15_bind(&s->pcsc, &s->token);
	}
	return CKR_OK;
}

static int
attr_match(const oh_object_t *o, const CK_ATTRIBUTE *t, CK_ULONG n)
{
	CK_ULONG i;
	for (i = 0; i < n; i++) {
		if (t[i].type == CKA_CLASS && t[i].pValue && t[i].ulValueLen == sizeof(CK_ULONG)) {
			CK_ULONG cls = *(CK_ULONG *)t[i].pValue;
			CK_ULONG have = (o->cls == OH_CLS_PRIVKEY) ? CKO_PRIVATE_KEY :
					(o->cls == OH_CLS_PUBKEY) ? CKO_PUBLIC_KEY : CKO_CERTIFICATE;
			if (cls != have)
				return 0;
		} else if (t[i].type == CKA_ID && t[i].pValue) {
			if (t[i].ulValueLen != o->id_len ||
			    memcmp(t[i].pValue, o->id, o->id_len) != 0)
				return 0;
		} else if (t[i].type == CKA_LABEL && t[i].pValue) {
			if (strlen(o->label) != t[i].ulValueLen ||
			    memcmp(t[i].pValue, o->label, t[i].ulValueLen) != 0)
				return 0;
		} else if (t[i].type == CKA_SIGN && t[i].pValue && t[i].ulValueLen == 1) {
			if ((*(CK_BBOOL *)t[i].pValue) && !o->can_sign)
				return 0;
		} else if (t[i].type == CKA_DECRYPT && t[i].pValue && t[i].ulValueLen == 1) {
			if ((*(CK_BBOOL *)t[i].pValue) && !o->can_decrypt)
				return 0;
		}
	}
	return 1;
}

static CK_RV
set_attr(CK_ATTRIBUTE *a, const void *data, CK_ULONG len)
{
	if (!a->pValue) {
		a->ulValueLen = len;
		return CKR_OK;
	}
	if (a->ulValueLen < len) {
		a->ulValueLen = len;
		return CKR_BUFFER_TOO_SMALL;
	}
	memcpy(a->pValue, data, len);
	a->ulValueLen = len;
	return CKR_OK;
}

static size_t
build_digestinfo_sha1(const unsigned char *hash, unsigned char *out)
{
	static const unsigned char prefix[] = {
		0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
		0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
	};
	memcpy(out, prefix, sizeof(prefix));
	memcpy(out + sizeof(prefix), hash, 20);
	return sizeof(prefix) + 20;
}

static size_t
build_digestinfo_sha256(const unsigned char *hash, unsigned char *out)
{
	static const unsigned char prefix[] = {
		0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
		0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
		0x00, 0x04, 0x20
	};
	memcpy(out, prefix, sizeof(prefix));
	memcpy(out + sizeof(prefix), hash, 32);
	return sizeof(prefix) + 32;
}

/* ---------- PKCS#11 ---------- */

static CK_RV
OH_C_Initialize(CK_VOID_PTR pInitArgs)
{
	char readers[2048];
	char *p;
	(void)pInitArgs;

	if (g_initialized)
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;

	memset(g_slots, 0, sizeof(g_slots));
	memset(g_sessions, 0, sizeof(g_sessions));
	g_nslots = 0;

	if (oh_pcsc_init(&g_slots[0].pcsc) != 0)
		return CKR_DEVICE_ERROR;

	if (oh_pcsc_list_readers(&g_slots[0].pcsc, readers, sizeof(readers)) != 0) {
		g_initialized = 1;
		return CKR_OK;
	}

	for (p = readers; *p && g_nslots < OH_MAX_SLOTS; ) {
		oh_slot_t *s = &g_slots[g_nslots];
		if (g_nslots > 0)
			s->pcsc.ctx = g_slots[0].pcsc.ctx;
		strncpy(s->reader, p, sizeof(s->reader) - 1);
		s->present = 1;
		g_nslots++;
		p += strlen(p) + 1;
	}

	g_initialized = 1;
	return CKR_OK;
}

static CK_RV
OH_C_Finalize(CK_VOID_PTR pReserved)
{
	CK_ULONG i;
	(void)pReserved;
	if (!g_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	for (i = 0; i < OH_MAX_SESSIONS; i++)
		g_sessions[i].in_use = 0;
	for (i = 0; i < g_nslots; i++) {
		oh_p15_free(&g_slots[i].token);
		oh_pcsc_disconnect(&g_slots[i].pcsc);
		if (i > 0)
			g_slots[i].pcsc.ctx = 0;
	}
	oh_pcsc_fini(&g_slots[0].pcsc);
	g_nslots = 0;
	g_initialized = 0;
	return CKR_OK;
}

static CK_RV
OH_C_GetInfo(CK_INFO_PTR pInfo)
{
	if (!g_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!pInfo)
		return CKR_ARGUMENTS_BAD;
	memset(pInfo, 0, sizeof(*pInfo));
	pInfo->cryptokiVersion.major = 2;
	pInfo->cryptokiVersion.minor = 40;
	fill_blank(pInfo->manufacturerID, 32, "openhicos");
	fill_blank(pInfo->libraryDescription, 32, "openhicos PKCS#11");
	pInfo->libraryVersion.major = 0;
	pInfo->libraryVersion.minor = 2;
	return CKR_OK;
}

static CK_RV
OH_C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
	CK_ULONG i, n = 0;
	if (!g_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!pulCount)
		return CKR_ARGUMENTS_BAD;
	for (i = 0; i < g_nslots; i++) {
		if (tokenPresent && !g_slots[i].present)
			continue;
		if (pSlotList) {
			if (n >= *pulCount)
				return CKR_BUFFER_TOO_SMALL;
			pSlotList[n] = i;
		}
		n++;
	}
	*pulCount = n;
	return CKR_OK;
}

static CK_RV
OH_C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	oh_slot_t *s;
	if (!g_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (slotID >= g_nslots || !pInfo)
		return CKR_ARGUMENTS_BAD;
	s = &g_slots[slotID];
	memset(pInfo, 0, sizeof(*pInfo));
	fill_blank(pInfo->slotDescription, 64, s->reader);
	fill_blank(pInfo->manufacturerID, 32, "PC/SC");
	pInfo->flags = CKF_HW_SLOT | CKF_REMOVABLE_DEVICE;
	if (s->present)
		pInfo->flags |= CKF_TOKEN_PRESENT;
	return CKR_OK;
}

static CK_RV
OH_C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	oh_slot_t *s;
	CK_RV rv;
	if (!g_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (slotID >= g_nslots || !pInfo)
		return CKR_ARGUMENTS_BAD;
	s = &g_slots[slotID];
	if (!s->present)
		return CKR_TOKEN_NOT_PRESENT;
	rv = ensure_card(slotID);
	if (rv != CKR_OK)
		return rv;
	memset(pInfo, 0, sizeof(*pInfo));
	fill_blank(pInfo->label, 32, s->token.label);
	fill_blank(pInfo->manufacturerID, 32, s->token.manufacturer);
	fill_blank(pInfo->model, 16, s->token.model);
	fill_blank(pInfo->serialNumber, 16, s->token.serial);
	pInfo->flags = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED |
			CKF_TOKEN_INITIALIZED;
	pInfo->ulMaxPinLen = s->token.max_pin ? s->token.max_pin : OH_PIN_MAX;
	pInfo->ulMinPinLen = s->token.min_pin ? s->token.min_pin : 6;
	pInfo->ulMaxSessionCount = OH_MAX_SESSIONS;
	return CKR_OK;
}

static CK_RV
OH_C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
	static const CK_MECHANISM_TYPE mechs[] = {
		CKM_RSA_PKCS, CKM_SHA1_RSA_PKCS, CKM_SHA256_RSA_PKCS
	};
	(void)slotID;
	if (!g_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!pulCount)
		return CKR_ARGUMENTS_BAD;
	if (pMechanismList) {
		if (*pulCount < 3)
			return CKR_BUFFER_TOO_SMALL;
		memcpy(pMechanismList, mechs, sizeof(mechs));
	}
	*pulCount = 3;
	return CKR_OK;
}

static CK_RV OH_C_GetMechanismInfo(CK_SLOT_ID s, CK_MECHANISM_TYPE m, void *i)
{ (void)s;(void)m;(void)i; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_InitToken(CK_SLOT_ID s, CK_UTF8CHAR_PTR a, CK_ULONG b, CK_UTF8CHAR_PTR c)
{ (void)s;(void)a;(void)b;(void)c; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_InitPIN(CK_SESSION_HANDLE h, CK_UTF8CHAR_PTR p, CK_ULONG n)
{ (void)h;(void)p;(void)n; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_SetPIN(CK_SESSION_HANDLE h, CK_UTF8CHAR_PTR a, CK_ULONG b, CK_UTF8CHAR_PTR c, CK_ULONG d)
{ (void)h;(void)a;(void)b;(void)c;(void)d; return CKR_FUNCTION_NOT_SUPPORTED; }

static CK_RV
OH_C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
		void *Notify, CK_SESSION_HANDLE_PTR phSession)
{
	CK_ULONG i;
	CK_RV rv;
	(void)pApplication;
	(void)Notify;
	if (!g_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!phSession)
		return CKR_ARGUMENTS_BAD;
	if (!(flags & CKF_SERIAL_SESSION))
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
	rv = ensure_card(slotID);
	if (rv != CKR_OK)
		return rv;
	for (i = 0; i < OH_MAX_SESSIONS; i++) {
		if (!g_sessions[i].in_use) {
			memset(&g_sessions[i], 0, sizeof(g_sessions[i]));
			g_sessions[i].in_use = 1;
			g_sessions[i].slot = slotID;
			g_sessions[i].flags = flags;
			g_sessions[i].state = (flags & CKF_RW_SESSION)
					? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
			*phSession = i + 1;
			return CKR_OK;
		}
	}
	return CKR_SESSION_COUNT;
}

static CK_RV
OH_C_CloseSession(CK_SESSION_HANDLE hSession)
{
	oh_session_t *s = session_get(hSession);
	if (!g_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!s)
		return CKR_SESSION_HANDLE_INVALID;
	s->in_use = 0;
	return CKR_OK;
}

static CK_RV
OH_C_CloseAllSessions(CK_SLOT_ID slotID)
{
	CK_ULONG i;
	if (!g_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	for (i = 0; i < OH_MAX_SESSIONS; i++) {
		if (g_sessions[i].in_use && g_sessions[i].slot == slotID)
			g_sessions[i].in_use = 0;
	}
	return CKR_OK;
}

static CK_RV
OH_C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	oh_session_t *s = session_get(hSession);
	if (!s || !pInfo)
		return CKR_ARGUMENTS_BAD;
	pInfo->slotID = s->slot;
	pInfo->state = s->state;
	pInfo->flags = s->flags;
	pInfo->ulDeviceError = 0;
	return CKR_OK;
}

static CK_RV OH_C_GetOperationState(CK_SESSION_HANDLE h, CK_BYTE_PTR p, CK_ULONG_PTR n)
{ (void)h;(void)p;(void)n; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_SetOperationState(CK_SESSION_HANDLE h, CK_BYTE_PTR p, CK_ULONG n, CK_OBJECT_HANDLE a, CK_OBJECT_HANDLE b)
{ (void)h;(void)p;(void)n;(void)a;(void)b; return CKR_FUNCTION_NOT_SUPPORTED; }

static CK_RV
OH_C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
		CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	oh_session_t *s = session_get(hSession);
	oh_slot_t *slot;
	int refs[4];
	int nrefs = 0;
	int i, rc = -1;

	if (!s)
		return CKR_SESSION_HANDLE_INVALID;
	if (userType != CKU_USER)
		return CKR_USER_TYPE_INVALID;
	if (s->logged_in)
		return CKR_USER_ALREADY_LOGGED_IN;
	if (!pPin || ulPinLen == 0)
		return CKR_ARGUMENTS_BAD;

	slot = &g_slots[s->slot];
	refs[nrefs++] = slot->token.pin_ref;
	if (slot->token.pin_ref != 0x00)
		refs[nrefs++] = 0x00;
	if (slot->token.pin_ref != 0x01)
		refs[nrefs++] = 0x01;
	refs[nrefs++] = 0x8C;

	for (i = 0; i < nrefs; i++) {
		rc = oh_verify_pin(&slot->pcsc, refs[i], pPin, ulPinLen);
		if (rc == 0) {
			slot->token.pin_ref = refs[i];
			break;
		}
		if (rc == -2)
			return CKR_PIN_LOCKED;
	}
	if (rc == -3)
		return CKR_PIN_INCORRECT;
	if (rc != 0)
		return CKR_DEVICE_ERROR;

	s->logged_in = 1;
	s->state = (s->flags & CKF_RW_SESSION) ? CKS_RW_USER_FUNCTIONS : CKS_RO_USER_FUNCTIONS;
	return CKR_OK;
}

static CK_RV
OH_C_Logout(CK_SESSION_HANDLE hSession)
{
	oh_session_t *s = session_get(hSession);
	if (!s)
		return CKR_SESSION_HANDLE_INVALID;
	if (!s->logged_in)
		return CKR_USER_NOT_LOGGED_IN;
	s->logged_in = 0;
	s->state = (s->flags & CKF_RW_SESSION) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
	return CKR_OK;
}

static CK_RV OH_C_CreateObject(CK_SESSION_HANDLE h, CK_ATTRIBUTE_PTR a, CK_ULONG n, CK_OBJECT_HANDLE_PTR o)
{ (void)h;(void)a;(void)n;(void)o; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_CopyObject(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o, CK_ATTRIBUTE_PTR a, CK_ULONG n, CK_OBJECT_HANDLE_PTR p)
{ (void)h;(void)o;(void)a;(void)n;(void)p; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_DestroyObject(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o)
{ (void)h;(void)o; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_GetObjectSize(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o, CK_ULONG_PTR n)
{ (void)h;(void)o;(void)n; return CKR_FUNCTION_NOT_SUPPORTED; }

static CK_RV
OH_C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
		CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	oh_session_t *s = session_get(hSession);
	oh_slot_t *slot;
	oh_object_t *o;
	CK_ULONG i;
	CK_RV rv = CKR_OK;
	CK_BBOOL btrue = CK_TRUE, bfalse = CK_FALSE;
	CK_ULONG ul;
	CK_KEY_TYPE kt = CKK_RSA;
	CK_CERTIFICATE_TYPE ct = CKC_X_509;

	if (!s)
		return CKR_SESSION_HANDLE_INVALID;
	slot = &g_slots[s->slot];
	o = oh_p15_find(&slot->token, hObject);
	if (!o)
		return CKR_OBJECT_HANDLE_INVALID;

	for (i = 0; i < ulCount; i++) {
		CK_RV r = CKR_OK;
		switch (pTemplate[i].type) {
		case CKA_CLASS:
			ul = (o->cls == OH_CLS_PRIVKEY) ? CKO_PRIVATE_KEY :
			     (o->cls == OH_CLS_PUBKEY) ? CKO_PUBLIC_KEY : CKO_CERTIFICATE;
			r = set_attr(&pTemplate[i], &ul, sizeof(ul));
			break;
		case CKA_TOKEN:
			r = set_attr(&pTemplate[i], &btrue, 1);
			break;
		case CKA_PRIVATE:
			ul = (o->cls == OH_CLS_PRIVKEY) ? 1 : 0;
			{ CK_BBOOL b = ul ? CK_TRUE : CK_FALSE; r = set_attr(&pTemplate[i], &b, 1); }
			break;
		case CKA_LABEL:
			r = set_attr(&pTemplate[i], o->label, (CK_ULONG)strlen(o->label));
			break;
		case CKA_ID:
			r = set_attr(&pTemplate[i], o->id, (CK_ULONG)o->id_len);
			break;
		case CKA_KEY_TYPE:
			if (o->cls == OH_CLS_CERT) {
				pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
				r = CKR_ATTRIBUTE_TYPE_INVALID;
			} else
				r = set_attr(&pTemplate[i], &kt, sizeof(kt));
			break;
		case CKA_CERTIFICATE_TYPE:
			if (o->cls != OH_CLS_CERT) {
				pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
				r = CKR_ATTRIBUTE_TYPE_INVALID;
			} else
				r = set_attr(&pTemplate[i], &ct, sizeof(ct));
			break;
		case CKA_VALUE:
			if (o->cls != OH_CLS_CERT || !o->data) {
				pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
				r = CKR_ATTRIBUTE_TYPE_INVALID;
			} else
				r = set_attr(&pTemplate[i], o->data, (CK_ULONG)o->data_len);
			break;
		case CKA_MODULUS:
			if (!o->modulus) {
				pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
				r = CKR_ATTRIBUTE_TYPE_INVALID;
			} else
				r = set_attr(&pTemplate[i], o->modulus, (CK_ULONG)o->modulus_len);
			break;
		case CKA_MODULUS_BITS:
			if (!o->modulus_bits) {
				pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
				r = CKR_ATTRIBUTE_TYPE_INVALID;
			} else {
				ul = o->modulus_bits;
				r = set_attr(&pTemplate[i], &ul, sizeof(ul));
			}
			break;
		case CKA_PUBLIC_EXPONENT:
			if (!o->pubexp) {
				pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
				r = CKR_ATTRIBUTE_TYPE_INVALID;
			} else
				r = set_attr(&pTemplate[i], o->pubexp, (CK_ULONG)o->pubexp_len);
			break;
		case CKA_SIGN:
			{ CK_BBOOL b = o->can_sign ? CK_TRUE : CK_FALSE; r = set_attr(&pTemplate[i], &b, 1); }
			break;
		case CKA_DECRYPT:
			{ CK_BBOOL b = o->can_decrypt ? CK_TRUE : CK_FALSE; r = set_attr(&pTemplate[i], &b, 1); }
			break;
		case CKA_VERIFY:
			{ CK_BBOOL b = o->can_verify ? CK_TRUE : CK_FALSE; r = set_attr(&pTemplate[i], &b, 1); }
			break;
		case CKA_ENCRYPT:
		case CKA_SENSITIVE:
			r = set_attr(&pTemplate[i], (pTemplate[i].type == CKA_SENSITIVE) ? &btrue : &bfalse, 1);
			break;
		default:
			pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
			r = CKR_ATTRIBUTE_TYPE_INVALID;
			break;
		}
		if (r == CKR_BUFFER_TOO_SMALL)
			rv = CKR_BUFFER_TOO_SMALL;
		else if (r != CKR_OK && rv == CKR_OK)
			rv = r;
	}
	return rv;
}

static CK_RV OH_C_SetAttributeValue(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o, CK_ATTRIBUTE_PTR a, CK_ULONG n)
{ (void)h;(void)o;(void)a;(void)n; return CKR_FUNCTION_NOT_SUPPORTED; }

static CK_RV
OH_C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	oh_session_t *s = session_get(hSession);
	oh_slot_t *slot;
	int i;

	if (!s)
		return CKR_SESSION_HANDLE_INVALID;
	slot = &g_slots[s->slot];
	s->find_active = 1;
	s->find_pos = 0;
	s->find_count = 0;
	for (i = 0; i < slot->token.nobjs && s->find_count < OH_MAX_OBJS; i++) {
		oh_object_t *o = &slot->token.objs[i];
		if (o->cls == OH_CLS_PRIVKEY && !s->logged_in)
			continue;
		if (!attr_match(o, pTemplate, ulCount))
			continue;
		s->find_handles[s->find_count++] = o->handle;
	}
	return CKR_OK;
}

static CK_RV
OH_C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
		CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
	oh_session_t *s = session_get(hSession);
	CK_ULONG n = 0;
	if (!s || !s->find_active || !pulObjectCount)
		return CKR_ARGUMENTS_BAD;
	while (s->find_pos < s->find_count && n < ulMaxObjectCount)
		phObject[n++] = s->find_handles[s->find_pos++];
	*pulObjectCount = n;
	return CKR_OK;
}

static CK_RV
OH_C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
	oh_session_t *s = session_get(hSession);
	if (!s)
		return CKR_SESSION_HANDLE_INVALID;
	s->find_active = 0;
	return CKR_OK;
}

static CK_RV OH_C_EncryptInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE o)
{ (void)h;(void)m;(void)o; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_Encrypt(CK_SESSION_HANDLE h, CK_BYTE_PTR a, CK_ULONG b, CK_BYTE_PTR c, CK_ULONG_PTR d)
{ (void)h;(void)a;(void)b;(void)c;(void)d; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_EncryptUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR a, CK_ULONG b, CK_BYTE_PTR c, CK_ULONG_PTR d)
{ (void)h;(void)a;(void)b;(void)c;(void)d; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_EncryptFinal(CK_SESSION_HANDLE h, CK_BYTE_PTR a, CK_ULONG_PTR b)
{ (void)h;(void)a;(void)b; return CKR_FUNCTION_NOT_SUPPORTED; }

static CK_RV
OH_C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	oh_session_t *s = session_get(hSession);
	oh_slot_t *slot;
	oh_object_t *o;
	if (!s)
		return CKR_SESSION_HANDLE_INVALID;
	if (!s->logged_in)
		return CKR_USER_NOT_LOGGED_IN;
	if (!pMechanism)
		return CKR_ARGUMENTS_BAD;
	slot = &g_slots[s->slot];
	o = oh_p15_find(&slot->token, hKey);
	if (!o || o->cls != OH_CLS_PRIVKEY || !o->can_decrypt)
		return CKR_KEY_HANDLE_INVALID;
	if (pMechanism->mechanism != CKM_RSA_PKCS)
		return CKR_MECHANISM_INVALID;
	s->decrypt_active = 1;
	s->decrypt_key = hKey;
	s->decrypt_mech = pMechanism->mechanism;
	return CKR_OK;
}

static CK_RV
OH_C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
		CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	oh_session_t *s = session_get(hSession);
	oh_slot_t *slot;
	oh_object_t *o;
	unsigned char out[512];
	size_t out_len = sizeof(out);

	if (!s || !s->decrypt_active)
		return CKR_OPERATION_NOT_INITIALIZED;
	if (!pulDataLen)
		return CKR_ARGUMENTS_BAD;
	slot = &g_slots[s->slot];
	o = oh_p15_find(&slot->token, s->decrypt_key);
	if (!o)
		return CKR_KEY_HANDLE_INVALID;

	if (oh_mse_set_decipher(&slot->pcsc, (unsigned char)o->key_ref) != 0) {
		s->decrypt_active = 0;
		return CKR_DEVICE_ERROR;
	}
	if (oh_pso_decipher(&slot->pcsc, pEncryptedData, ulEncryptedDataLen, out, &out_len) != 0) {
		s->decrypt_active = 0;
		return CKR_FUNCTION_FAILED;
	}
	s->decrypt_active = 0;
	if (!pData) {
		*pulDataLen = (CK_ULONG)out_len;
		return CKR_OK;
	}
	if (*pulDataLen < out_len)
		return CKR_BUFFER_TOO_SMALL;
	memcpy(pData, out, out_len);
	*pulDataLen = (CK_ULONG)out_len;
	return CKR_OK;
}

static CK_RV OH_C_DecryptUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR a, CK_ULONG b, CK_BYTE_PTR c, CK_ULONG_PTR d)
{ (void)h;(void)a;(void)b;(void)c;(void)d; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_DecryptFinal(CK_SESSION_HANDLE h, CK_BYTE_PTR a, CK_ULONG_PTR b)
{ (void)h;(void)a;(void)b; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_DigestInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m)
{ (void)h;(void)m; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_Digest(CK_SESSION_HANDLE h, CK_BYTE_PTR a, CK_ULONG b, CK_BYTE_PTR c, CK_ULONG_PTR d)
{ (void)h;(void)a;(void)b;(void)c;(void)d; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_DigestUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR a, CK_ULONG b)
{ (void)h;(void)a;(void)b; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_DigestKey(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o)
{ (void)h;(void)o; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_DigestFinal(CK_SESSION_HANDLE h, CK_BYTE_PTR a, CK_ULONG_PTR b)
{ (void)h;(void)a;(void)b; return CKR_FUNCTION_NOT_SUPPORTED; }

static CK_RV
OH_C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	oh_session_t *s = session_get(hSession);
	oh_slot_t *slot;
	oh_object_t *o;
	if (!s)
		return CKR_SESSION_HANDLE_INVALID;
	if (!s->logged_in)
		return CKR_USER_NOT_LOGGED_IN;
	if (!pMechanism)
		return CKR_ARGUMENTS_BAD;
	slot = &g_slots[s->slot];
	o = oh_p15_find(&slot->token, hKey);
	if (!o || o->cls != OH_CLS_PRIVKEY || !o->can_sign)
		return CKR_KEY_HANDLE_INVALID;
	if (pMechanism->mechanism != CKM_RSA_PKCS &&
	    pMechanism->mechanism != CKM_SHA1_RSA_PKCS &&
	    pMechanism->mechanism != CKM_SHA256_RSA_PKCS)
		return CKR_MECHANISM_INVALID;
	s->sign_active = 1;
	s->sign_key = hKey;
	s->sign_mech = pMechanism->mechanism;
	s->sign_len = 0;
	return CKR_OK;
}

static CK_RV
do_sign(oh_session_t *s, const unsigned char *data, size_t data_len,
		CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	oh_slot_t *slot = &g_slots[s->slot];
	oh_object_t *o = oh_p15_find(&slot->token, s->sign_key);
	unsigned char diginfo[64];
	size_t dig_len = 0;
	const unsigned char *to_sign = data;
	size_t to_sign_len = data_len;
	unsigned char out[512];
	size_t out_len = sizeof(out);
	unsigned char hash[32];

	if (!o)
		return CKR_KEY_HANDLE_INVALID;

	if (s->sign_mech == CKM_SHA1_RSA_PKCS) {
		oh_sha1(data, data_len, hash);
		dig_len = build_digestinfo_sha1(hash, diginfo);
		to_sign = diginfo;
		to_sign_len = dig_len;
	} else if (s->sign_mech == CKM_SHA256_RSA_PKCS) {
		oh_sha256(data, data_len, hash);
		dig_len = build_digestinfo_sha256(hash, diginfo);
		to_sign = diginfo;
		to_sign_len = dig_len;
	}

	if (oh_mse_set_dst(&slot->pcsc, (unsigned char)o->key_ref) != 0)
		return CKR_DEVICE_ERROR;
	if (oh_pso_cds(&slot->pcsc, to_sign, to_sign_len, out, &out_len) != 0)
		return CKR_FUNCTION_FAILED;

	if (!pSignature) {
		*pulSignatureLen = (CK_ULONG)out_len;
		return CKR_OK;
	}
	if (*pulSignatureLen < out_len)
		return CKR_BUFFER_TOO_SMALL;
	memcpy(pSignature, out, out_len);
	*pulSignatureLen = (CK_ULONG)out_len;
	return CKR_OK;
}

static CK_RV
OH_C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
		CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	oh_session_t *s = session_get(hSession);
	CK_RV rv;
	if (!s || !s->sign_active)
		return CKR_OPERATION_NOT_INITIALIZED;
	if (!pulSignatureLen)
		return CKR_ARGUMENTS_BAD;
	rv = do_sign(s, pData, ulDataLen, pSignature, pulSignatureLen);
	/* Length probe (pSignature == NULL) keeps the operation active. */
	if (pSignature || rv != CKR_OK)
		s->sign_active = 0;
	return rv;
}

static CK_RV
OH_C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	oh_session_t *s = session_get(hSession);
	if (!s || !s->sign_active)
		return CKR_OPERATION_NOT_INITIALIZED;
	if (s->sign_len + ulPartLen > sizeof(s->sign_buf))
		return CKR_DATA_LEN_RANGE;
	memcpy(s->sign_buf + s->sign_len, pPart, ulPartLen);
	s->sign_len += ulPartLen;
	return CKR_OK;
}

static CK_RV
OH_C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	oh_session_t *s = session_get(hSession);
	CK_RV rv;
	if (!s || !s->sign_active)
		return CKR_OPERATION_NOT_INITIALIZED;
	rv = do_sign(s, s->sign_buf, s->sign_len, pSignature, pulSignatureLen);
	if (pSignature || rv != CKR_OK)
		s->sign_active = 0;
	return rv;
}

static CK_RV OH_C_SignRecoverInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE o)
{ (void)h;(void)m;(void)o; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_SignRecover(CK_SESSION_HANDLE h, CK_BYTE_PTR a, CK_ULONG b, CK_BYTE_PTR c, CK_ULONG_PTR d)
{ (void)h;(void)a;(void)b;(void)c;(void)d; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_VerifyInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE o)
{ (void)h;(void)m;(void)o; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_Verify(CK_SESSION_HANDLE h, CK_BYTE_PTR a, CK_ULONG b, CK_BYTE_PTR c, CK_ULONG d)
{ (void)h;(void)a;(void)b;(void)c;(void)d; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_VerifyUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR a, CK_ULONG b)
{ (void)h;(void)a;(void)b; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_VerifyFinal(CK_SESSION_HANDLE h, CK_BYTE_PTR a, CK_ULONG b)
{ (void)h;(void)a;(void)b; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_VerifyRecoverInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE o)
{ (void)h;(void)m;(void)o; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_VerifyRecover(CK_SESSION_HANDLE h, CK_BYTE_PTR a, CK_ULONG b, CK_BYTE_PTR c, CK_ULONG_PTR d)
{ (void)h;(void)a;(void)b;(void)c;(void)d; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_DigestEncryptUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR a, CK_ULONG b, CK_BYTE_PTR c, CK_ULONG_PTR d)
{ (void)h;(void)a;(void)b;(void)c;(void)d; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_DecryptDigestUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR a, CK_ULONG b, CK_BYTE_PTR c, CK_ULONG_PTR d)
{ (void)h;(void)a;(void)b;(void)c;(void)d; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_SignEncryptUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR a, CK_ULONG b, CK_BYTE_PTR c, CK_ULONG_PTR d)
{ (void)h;(void)a;(void)b;(void)c;(void)d; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_DecryptVerifyUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR a, CK_ULONG b, CK_BYTE_PTR c, CK_ULONG_PTR d)
{ (void)h;(void)a;(void)b;(void)c;(void)d; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_GenerateKey(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m, CK_ATTRIBUTE_PTR a, CK_ULONG n, CK_OBJECT_HANDLE_PTR o)
{ (void)h;(void)m;(void)a;(void)n;(void)o; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_GenerateKeyPair(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m, CK_ATTRIBUTE_PTR a, CK_ULONG b, CK_ATTRIBUTE_PTR c, CK_ULONG d, CK_OBJECT_HANDLE_PTR e, CK_OBJECT_HANDLE_PTR f)
{ (void)h;(void)m;(void)a;(void)b;(void)c;(void)d;(void)e;(void)f; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_WrapKey(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE a, CK_OBJECT_HANDLE b, CK_BYTE_PTR c, CK_ULONG_PTR d)
{ (void)h;(void)m;(void)a;(void)b;(void)c;(void)d; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_UnwrapKey(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_ATTRIBUTE_PTR d, CK_ULONG e, CK_OBJECT_HANDLE_PTR f)
{ (void)h;(void)m;(void)a;(void)b;(void)c;(void)d;(void)e;(void)f; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_DeriveKey(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE a, CK_ATTRIBUTE_PTR b, CK_ULONG c, CK_OBJECT_HANDLE_PTR d)
{ (void)h;(void)m;(void)a;(void)b;(void)c;(void)d; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_SeedRandom(CK_SESSION_HANDLE h, CK_BYTE_PTR a, CK_ULONG b)
{ (void)h;(void)a;(void)b; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_GenerateRandom(CK_SESSION_HANDLE h, CK_BYTE_PTR a, CK_ULONG b)
{ (void)h;(void)a;(void)b; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_GetFunctionStatus(CK_SESSION_HANDLE h)
{ (void)h; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_CancelFunction(CK_SESSION_HANDLE h)
{ (void)h; return CKR_FUNCTION_NOT_SUPPORTED; }
static CK_RV OH_C_WaitForSlotEvent(CK_FLAGS f, CK_SLOT_ID_PTR s, CK_VOID_PTR p)
{ (void)f;(void)s;(void)p; return CKR_FUNCTION_NOT_SUPPORTED; }

static CK_FUNCTION_LIST g_function_list = {
	{ 2, 40 },
	OH_C_Initialize,
	OH_C_Finalize,
	OH_C_GetInfo,
	C_GetFunctionList,
	OH_C_GetSlotList,
	OH_C_GetSlotInfo,
	OH_C_GetTokenInfo,
	OH_C_GetMechanismList,
	OH_C_GetMechanismInfo,
	OH_C_InitToken,
	OH_C_InitPIN,
	OH_C_SetPIN,
	OH_C_OpenSession,
	OH_C_CloseSession,
	OH_C_CloseAllSessions,
	OH_C_GetSessionInfo,
	OH_C_GetOperationState,
	OH_C_SetOperationState,
	OH_C_Login,
	OH_C_Logout,
	OH_C_CreateObject,
	OH_C_CopyObject,
	OH_C_DestroyObject,
	OH_C_GetObjectSize,
	OH_C_GetAttributeValue,
	OH_C_SetAttributeValue,
	OH_C_FindObjectsInit,
	OH_C_FindObjects,
	OH_C_FindObjectsFinal,
	OH_C_EncryptInit,
	OH_C_Encrypt,
	OH_C_EncryptUpdate,
	OH_C_EncryptFinal,
	OH_C_DecryptInit,
	OH_C_Decrypt,
	OH_C_DecryptUpdate,
	OH_C_DecryptFinal,
	OH_C_DigestInit,
	OH_C_Digest,
	OH_C_DigestUpdate,
	OH_C_DigestKey,
	OH_C_DigestFinal,
	OH_C_SignInit,
	OH_C_Sign,
	OH_C_SignUpdate,
	OH_C_SignFinal,
	OH_C_SignRecoverInit,
	OH_C_SignRecover,
	OH_C_VerifyInit,
	OH_C_Verify,
	OH_C_VerifyUpdate,
	OH_C_VerifyFinal,
	OH_C_VerifyRecoverInit,
	OH_C_VerifyRecover,
	OH_C_DigestEncryptUpdate,
	OH_C_DecryptDigestUpdate,
	OH_C_SignEncryptUpdate,
	OH_C_DecryptVerifyUpdate,
	OH_C_GenerateKey,
	OH_C_GenerateKeyPair,
	OH_C_WrapKey,
	OH_C_UnwrapKey,
	OH_C_DeriveKey,
	OH_C_SeedRandom,
	OH_C_GenerateRandom,
	OH_C_GetFunctionStatus,
	OH_C_CancelFunction,
	OH_C_WaitForSlotEvent
};

#if defined(_WIN32)
__declspec(dllexport)
#elif defined(__GNUC__)
__attribute__((visibility("default")))
#endif
CK_RV
C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	if (!ppFunctionList)
		return CKR_ARGUMENTS_BAD;
	*ppFunctionList = &g_function_list;
	return CKR_OK;
}
