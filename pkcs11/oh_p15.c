#include "oh_p15.h"
#include "oh_apdu.h"
#include "oh_der.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Default PKCS#15 FIDs (ISO 7816-15 / OpenSC profile) */
#define FID_PKCS15_DF  0x5015
#define FID_ODF        0x5031
#define FID_TOKENINFO  0x5032

typedef struct {
	unsigned char path[OH_MAX_PATH];
	size_t path_len;
} oh_path_t;

static void
trim_ff(unsigned char *buf, size_t *len)
{
	while (*len > 0 && buf[*len - 1] == 0xFF)
		(*len)--;
}

static int
select_ef(oh_pcsc_t *p, const oh_path_t *path)
{
	if (!path || path->path_len == 0)
		return -1;
	/* Prefer path from MF if absolute (starts with 3F00) */
	if (path->path_len >= 2 && path->path[0] == 0x3F && path->path[1] == 0x00)
		return oh_select_path(p, path->path, path->path_len, 1);
	if (path->path_len == 2)
		return oh_select_fid(p, (unsigned short)((path->path[0] << 8) | path->path[1]));
	return oh_select_path(p, path->path, path->path_len, 0);
}

static int
read_ef_path(oh_pcsc_t *p, const oh_path_t *path, unsigned char **out, size_t *out_len)
{
	if (select_ef(p, path) != 0)
		return -1;
	return oh_read_ef(p, out, out_len);
}

static int
parse_path_tlv(const oh_der_t *t, oh_path_t *path)
{
	const unsigned char *c, *cend;
	oh_der_t os;

	memset(path, 0, sizeof(*path));
	if (t->tag == 0x04) {
		if (t->len == 0 || t->len > OH_MAX_PATH)
			return -1;
		memcpy(path->path, t->val, t->len);
		path->path_len = t->len;
		return 0;
	}
	if (t->tag != 0x30)
		return -1;
	if (oh_der_enter(t, &c, &cend) != 0)
		return -1;
	if (oh_der_next(&c, cend, &os) != 0 || os.tag != 0x04)
		return -1;
	if (os.len == 0 || os.len > OH_MAX_PATH)
		return -1;
	memcpy(path->path, os.val, os.len);
	path->path_len = os.len;
	return 0;
}

static int
parse_odf(const unsigned char *buf, size_t len,
		oh_path_t *prkdf, oh_path_t *pukdf, oh_path_t *cdf,
		oh_path_t *aodf, oh_path_t *tokeninfo)
{
	const unsigned char *p = buf;
	const unsigned char *end = buf + len;

	memset(prkdf, 0, sizeof(*prkdf));
	memset(pukdf, 0, sizeof(*pukdf));
	memset(cdf, 0, sizeof(*cdf));
	memset(aodf, 0, sizeof(*aodf));
	memset(tokeninfo, 0, sizeof(*tokeninfo));

	while (p < end) {
		oh_der_t t, inner;
		const unsigned char *c, *cend;
		oh_path_t path;

		if (*p == 0x00 || *p == 0xFF)
			break;
		if (oh_der_next(&p, end, &t) != 0)
			break;
		/* Context-specific constructed tags in ODF */
		if (!(t.tag & 0xA0) && t.tag != 0xA0 && t.tag < 0xA0)
			continue;
		if (oh_der_enter(&t, &c, &cend) != 0)
			continue;
		/* Choice: path or url — take first SEQUENCE/OCTET */
		if (oh_der_next(&c, cend, &inner) != 0)
			continue;
		if (parse_path_tlv(&inner, &path) != 0)
			continue;

		switch (t.tag) {
		case 0xA0: /* privateKeys */
			*prkdf = path;
			break;
		case 0xA1: /* publicKeys */
			*pukdf = path;
			break;
		case 0xA4: /* certificates */
		case 0xA5: /* trustedCertificates */
		case 0xA6: /* usefulCertificates */
			if (cdf->path_len == 0)
				*cdf = path;
			break;
		case 0xA8: /* authObjects */
			*aodf = path;
			break;
		default:
			break;
		}
	}
	(void)tokeninfo;
	return (prkdf->path_len || cdf->path_len) ? 0 : -1;
}

static void
copy_label(char *dst, size_t dstsz, const unsigned char *s, size_t n)
{
	size_t i, j = 0;
	if (!dst || dstsz == 0)
		return;
	for (i = 0; i < n && j + 1 < dstsz; i++) {
		unsigned char c = s[i];
		/* Allow printable ASCII and UTF-8 continuation bytes */
		if (c >= 0x20 || (c & 0x80))
			dst[j++] = (char)c;
	}
	dst[j] = '\0';
}

/* Extract OCTET STRING iD and INTEGER keyReference / keyUsage from type attrs */
static void
scan_key_attrs(const unsigned char *p, const unsigned char *end,
		unsigned char *id, size_t *id_len, int *key_ref,
		int *can_sign, int *can_decrypt)
{
	while (p < end) {
		oh_der_t t;
		if (oh_der_next(&p, end, &t) != 0)
			break;
		if (t.tag == 0x30) {
			const unsigned char *c = t.val;
			scan_key_attrs(c, t.end, id, id_len, key_ref, can_sign, can_decrypt);
		} else if (t.tag == 0x04 && id && id_len && t.len > 0 && t.len <= OH_MAX_ID && *id_len == 0) {
			memcpy(id, t.val, t.len);
			*id_len = t.len;
		} else if (t.tag == 0x02 && key_ref && t.len >= 1 && *key_ref < 0) {
			/* candidate keyReference — last small INTEGER often is ref */
			int v = 0;
			size_t i;
			for (i = 0; i < t.len; i++)
				v = (v << 8) | t.val[i];
			if (v >= 0 && v <= 0xFF)
				*key_ref = v;
		} else if (t.tag == 0x03 && t.len >= 2 && can_sign) {
			/* usage bits — best-effort: if any bits set, allow sign+decrypt for RSA */
			*can_sign = 1;
			if (can_decrypt)
				*can_decrypt = 1;
		}
	}
}

static int
add_object(oh_token_t *tok, oh_obj_class_t cls)
{
	oh_object_t *o;
	if (tok->nobjs >= OH_MAX_OBJS)
		return -1;
	o = &tok->objs[tok->nobjs];
	memset(o, 0, sizeof(*o));
	o->cls = cls;
	o->handle = (unsigned long)(tok->nobjs + 1);
	o->key_ref = -1;
	tok->nobjs++;
	return tok->nobjs - 1;
}

static int
extract_rsa_from_spki(const unsigned char *spki, size_t spki_len,
		unsigned char **mod, size_t *mod_len,
		unsigned char **exp, size_t *exp_len)
{
	oh_der_t seq, alg, bits, rsa, n, e;
	const unsigned char *p, *end, *bp;
	size_t blen;

	p = spki;
	end = spki + spki_len;
	if (oh_der_next(&p, end, &seq) != 0 || seq.tag != 0x30)
		return -1;
	p = seq.val;
	end = seq.end;
	if (oh_der_next(&p, end, &alg) != 0)
		return -1;
	if (oh_der_next(&p, end, &bits) != 0 || bits.tag != 0x03)
		return -1;
	if (oh_der_get_bytes(&bits, &bp, &blen) != 0)
		return -1;
	p = bp;
	end = bp + blen;
	if (oh_der_next(&p, end, &rsa) != 0 || rsa.tag != 0x30)
		return -1;
	p = rsa.val;
	end = rsa.end;
	if (oh_der_next(&p, end, &n) != 0 || n.tag != 0x02)
		return -1;
	if (oh_der_next(&p, end, &e) != 0 || e.tag != 0x02)
		return -1;
	*mod = malloc(n.len);
	*exp = malloc(e.len);
	if (!*mod || !*exp) {
		free(*mod);
		free(*exp);
		return -1;
	}
	memcpy(*mod, n.val, n.len);
	memcpy(*exp, e.val, e.len);
	*mod_len = n.len;
	*exp_len = e.len;
	return 0;
}

static unsigned long
modulus_bit_len(const unsigned char *m, size_t n)
{
	unsigned long bits;
	unsigned char b;
	while (n > 0 && *m == 0) {
		m++;
		n--;
	}
	if (n == 0)
		return 0;
	bits = (unsigned long)(n * 8);
	b = m[0];
	while (bits > 0 && (b & 0x80) == 0) {
		bits--;
		b = (unsigned char)(b << 1);
	}
	return bits;
}

static int
cert_get_rsa(const unsigned char *cert, size_t cert_len, oh_object_t *o)
{
	oh_der_t top, tbs, t;
	const unsigned char *p, *end, *c;
	int idx = 0;
	int has_ver = 0;

	p = cert;
	end = cert + cert_len;
	if (oh_der_next(&p, end, &top) != 0 || top.tag != 0x30)
		return -1;
	p = top.val;
	if (oh_der_next(&p, top.end, &tbs) != 0 || tbs.tag != 0x30)
		return -1;
	c = tbs.val;
	end = tbs.end;
	if (c < end && *c == 0xA0)
		has_ver = 1;
	while (c < end) {
		if (oh_der_next(&c, end, &t) != 0)
			return -1;
		if ((!has_ver && idx == 5) || (has_ver && idx == 6)) {
			unsigned char *mod = NULL, *exp = NULL;
			size_t ml = 0, el = 0;
			const unsigned char *sp = t.val - t.hdr_len;
			if (extract_rsa_from_spki(sp, t.hdr_len + t.len, &mod, &ml, &exp, &el) != 0)
				return -1;
			o->modulus = mod;
			o->modulus_len = ml;
			o->pubexp = exp;
			o->pubexp_len = el;
			o->modulus_bits = modulus_bit_len(mod, ml);
			return 0;
		}
		idx++;
	}
	return -1;
}

static int
load_cert_value(oh_pcsc_t *pcsc, const oh_path_t *path, oh_object_t *o)
{
	unsigned char *raw = NULL;
	size_t raw_len = 0;
	oh_der_t cert;

	if (read_ef_path(pcsc, path, &raw, &raw_len) != 0)
		return -1;
	trim_ff(raw, &raw_len);
	/* Value may be raw X.509 or PKCS15 wrapped */
	{
		const unsigned char *p = raw;
		if (oh_der_next(&p, raw + raw_len, &cert) == 0 && cert.tag == 0x30) {
			o->data = malloc(cert.hdr_len + cert.len);
			if (!o->data) {
				free(raw);
				return -1;
			}
			memcpy(o->data, cert.val - cert.hdr_len, cert.hdr_len + cert.len);
			o->data_len = cert.hdr_len + cert.len;
		} else {
			o->data = raw;
			o->data_len = raw_len;
			raw = NULL;
		}
	}
	free(raw);
	(void)cert_get_rsa(o->data, o->data_len, o);
	return 0;
}

static int
parse_prkdf(oh_pcsc_t *pcsc, oh_token_t *tok, const unsigned char *buf, size_t len)
{
	const unsigned char *p = buf;
	const unsigned char *end = buf + len;

	while (p < end) {
		oh_der_t choice, seq;
		const unsigned char *c, *cend;
		int idx;
		oh_object_t *o;

		if (*p == 0x00 || *p == 0xFF)
			break;
		if (oh_der_next(&p, end, &choice) != 0)
			break;
		/* privateRSAKey [1] or privateKey [0] etc. */
		if (oh_der_enter(&choice, &c, &cend) != 0)
			continue;
		if (oh_der_next(&c, cend, &seq) != 0 || seq.tag != 0x30)
			continue;

		idx = add_object(tok, OH_CLS_PRIVKEY);
		if (idx < 0)
			return -1;
		o = &tok->objs[idx];
		o->can_sign = 1;
		o->can_decrypt = 1;
		snprintf(o->label, sizeof(o->label), "Private Key %d", idx + 1);

		{
			const unsigned char *q = seq.val;
			const unsigned char *qend = seq.end;
			oh_der_t common, mid, typeattrs;
			/* commonObjectAttributes */
			if (oh_der_next(&q, qend, &common) == 0 && common.tag == 0x30) {
				const unsigned char *cc = common.val;
				oh_der_t lab;
				while (cc < common.end) {
					if (oh_der_next(&cc, common.end, &lab) != 0)
						break;
					if (lab.tag == 0x0C || lab.tag == 0x13 || lab.tag == 0x16)
						copy_label(o->label, sizeof(o->label), lab.val, lab.len);
				}
			}
			/* classAttributes: CommonKeyAttributes */
			if (oh_der_next(&q, qend, &mid) == 0) {
				scan_key_attrs(mid.val - mid.hdr_len,
						mid.end,
						o->id, &o->id_len, &o->key_ref,
						&o->can_sign, &o->can_decrypt);
			}
			/* typeAttributes */
			if (oh_der_next(&q, qend, &typeattrs) == 0) {
				scan_key_attrs(typeattrs.val, typeattrs.end,
						o->id, &o->id_len, &o->key_ref,
						&o->can_sign, &o->can_decrypt);
			}
		}
		if (o->key_ref < 0)
			o->key_ref = (idx == 0) ? 0x01 : (0x01 + idx);
		(void)pcsc;
	}
	return 0;
}

static int
parse_cdf(oh_pcsc_t *pcsc, oh_token_t *tok, const unsigned char *buf, size_t len)
{
	const unsigned char *p = buf;
	const unsigned char *end = buf + len;

	while (p < end) {
		oh_der_t choice, seq, t;
		const unsigned char *c, *cend, *q, *qend;
		int idx;
		oh_object_t *o;
		oh_path_t path;
		int have_path = 0;

		if (*p == 0x00 || *p == 0xFF)
			break;
		if (oh_der_next(&p, end, &choice) != 0)
			break;
		if (oh_der_enter(&choice, &c, &cend) != 0)
			continue;
		if (oh_der_next(&c, cend, &seq) != 0 || seq.tag != 0x30)
			continue;

		idx = add_object(tok, OH_CLS_CERT);
		if (idx < 0)
			return -1;
		o = &tok->objs[idx];
		o->can_verify = 1;
		snprintf(o->label, sizeof(o->label), "Certificate %d", idx + 1);

		q = seq.val;
		qend = seq.end;
		/* commonObjectAttributes */
		if (oh_der_next(&q, qend, &t) == 0 && t.tag == 0x30) {
			const unsigned char *cc = t.val;
			oh_der_t lab;
			while (cc < t.end) {
				if (oh_der_next(&cc, t.end, &lab) != 0)
					break;
				if (lab.tag == 0x0C || lab.tag == 0x13 || lab.tag == 0x16)
					copy_label(o->label, sizeof(o->label), lab.val, lab.len);
			}
		}
		/* classAttributes CommonCertificateAttributes — iD */
		if (oh_der_next(&q, qend, &t) == 0) {
			scan_key_attrs(t.val, t.end, o->id, &o->id_len, NULL, NULL, NULL);
		}
		/* typeAttributes: value choice path / direct */
		if (oh_der_next(&q, qend, &t) == 0) {
			const unsigned char *u = t.val;
			oh_der_t v;
			/* may be SEQUENCE with value [0] path or [1] direct */
			while (u < t.end) {
				if (oh_der_next(&u, t.end, &v) != 0)
					break;
				if (v.tag == 0xA1 || v.tag == 0xA0) {
					oh_der_t inner;
					const unsigned char *x = v.val;
					if (oh_der_next(&x, v.end, &inner) == 0 &&
					    parse_path_tlv(&inner, &path) == 0)
						have_path = 1;
				} else if (v.tag == 0x30 || v.tag == 0x04) {
					if (parse_path_tlv(&v, &path) == 0)
						have_path = 1;
				} else if (v.tag == 0xA1) {
					/* direct certificate */
				}
			}
			/* Also try: typeAttributes is Path directly */
			if (!have_path && parse_path_tlv(&t, &path) == 0)
				have_path = 1;
		}

		if (have_path)
			(void)load_cert_value(pcsc, &path, o);

		/* Create matching public key object from cert */
		if (o->modulus && o->modulus_len) {
			int pki = add_object(tok, OH_CLS_PUBKEY);
			if (pki >= 0) {
				oh_object_t *pk = &tok->objs[pki];
				pk->can_verify = 1;
				memcpy(pk->id, o->id, o->id_len);
				pk->id_len = o->id_len;
				snprintf(pk->label, sizeof(pk->label), "%s (Public Key)", o->label);
				pk->modulus = malloc(o->modulus_len);
				pk->pubexp = malloc(o->pubexp_len);
				if (pk->modulus && pk->pubexp) {
					memcpy(pk->modulus, o->modulus, o->modulus_len);
					memcpy(pk->pubexp, o->pubexp, o->pubexp_len);
					pk->modulus_len = o->modulus_len;
					pk->pubexp_len = o->pubexp_len;
					pk->modulus_bits = o->modulus_bits;
				}
			}
		}
	}
	return 0;
}

static int
parse_aodf_pin(const unsigned char *buf, size_t len, int *pin_ref)
{
	const unsigned char *p = buf;
	const unsigned char *end = buf + len;

	*pin_ref = 0x00;
	while (p < end) {
		oh_der_t t;
		if (*p == 0x00 || *p == 0xFF)
			break;
		if (oh_der_next(&p, end, &t) != 0)
			break;
		/* hunt for small INTEGER as pinReference */
		if (t.tag == 0x02 && t.len == 1) {
			*pin_ref = t.val[0];
			return 0;
		}
		if (t.tag & 0x20) {
			int pr = -1;
			if (parse_aodf_pin(t.val, t.len, &pr) == 0 && pr >= 0) {
				*pin_ref = pr;
				return 0;
			}
		}
	}
	return 0;
}

static int
parse_tokeninfo(const unsigned char *buf, size_t len, oh_token_t *tok);

static void
trim_label(char *s)
{
	size_t n;

	if (!s || !s[0])
		return;
	n = strlen(s);
	while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t'))
		s[--n] = '\0';
}

static int
read_ef_bytes(oh_pcsc_t *p, const unsigned char *path, size_t path_len,
		unsigned int offset, unsigned char *buf, size_t want)
{
	oh_path_t ph;
	size_t got;

	memset(&ph, 0, sizeof(ph));
	if (path_len == 0 || path_len > OH_MAX_PATH)
		return -1;
	memcpy(ph.path, path, path_len);
	ph.path_len = path_len;
	if (select_ef(p, &ph) != 0)
		return -1;
	if (oh_read_binary(p, offset, buf, want, &got) != 0 || got < want)
		return -1;
	return 0;
}

/* HiCOS stores TokenInfo at MF/5030/5032 (not under PKCS#15 DF). */
static int
read_hicos_tokeninfo_ef(oh_pcsc_t *pcsc, oh_token_t *tok)
{
	static const unsigned char path[] = { 0x3F, 0x00, 0x50, 0x30, 0x50, 0x32 };
	unsigned char *blob = NULL;
	size_t blob_len = 0;
	oh_path_t ti_path;

	memset(&ti_path, 0, sizeof(ti_path));
	memcpy(ti_path.path, path, sizeof(path));
	ti_path.path_len = sizeof(path);
	if (read_ef_path(pcsc, &ti_path, &blob, &blob_len) != 0)
		return -1;
	trim_ff(blob, &blob_len);
	(void)parse_tokeninfo(blob, blob_len, tok);
	free(blob);
	return 0;
}

/* Card serial for CK_TOKEN_INFO.serialNumber (ASCII at MF/0900/0903). */
static int
read_hicos_card_number(oh_pcsc_t *pcsc, char *serial, size_t serialsz)
{
	static const unsigned char path[] = { 0x3F, 0x00, 0x09, 0x00, 0x09, 0x03 };
	unsigned char buf[16];
	size_t n;

	if (read_ef_bytes(pcsc, path, sizeof(path), 0, buf, sizeof(buf)) != 0)
		return -1;
	n = sizeof(buf);
	while (n > 0 && (buf[n - 1] == 0x00 || buf[n - 1] == 0xFF || buf[n - 1] == ' '))
		n--;
	copy_label(serial, serialsz, buf, n);
	return serial[0] ? 0 : -1;
}

/* Model derived from card version EF (MF/0900/0905), e.g. "CHT V32N" -> "T7S". */
static int
read_hicos_model(oh_pcsc_t *pcsc, char *model, size_t modelsz)
{
	static const unsigned char path[] = { 0x3F, 0x00, 0x09, 0x00, 0x09, 0x05 };
	unsigned char buf[24];

	if (read_ef_bytes(pcsc, path, sizeof(path), 0, buf, sizeof(buf)) != 0) {
		snprintf(model, modelsz, "HiCOS");
		return -1;
	}
	buf[sizeof(buf) - 1] = '\0';
	if (strstr((char *)buf, "V32") != NULL)
		snprintf(model, modelsz, "T7S");
	else
		snprintf(model, modelsz, "HiCOS");
	return 0;
}

static int
parse_tokeninfo(const unsigned char *buf, size_t len, oh_token_t *tok)
{
	oh_der_t seq, t;
	const unsigned char *p, *end;

	p = buf;
	end = buf + len;
	if (oh_der_next(&p, end, &seq) != 0 || seq.tag != 0x30)
		return -1;
	p = seq.val;
	end = seq.end;
	while (p < end) {
		if (oh_der_next(&p, end, &t) != 0)
			break;
		if (t.tag == 0x0C || t.tag == 0x13 || t.tag == 0x16) {
			if (tok->manufacturer[0] == '\0')
				copy_label(tok->manufacturer, sizeof(tok->manufacturer), t.val, t.len);
			else if (tok->label[0] == '\0')
				copy_label(tok->label, sizeof(tok->label), t.val, t.len);
		} else if (t.tag == 0x80)
			copy_label(tok->label, sizeof(tok->label), t.val, t.len);
	}
	trim_label(tok->label);
	trim_label(tok->manufacturer);
	if (tok->label[0] == '\0')
		snprintf(tok->label, sizeof(tok->label), "HiCOS PKI Smart Card");
	if (tok->manufacturer[0] == '\0')
		snprintf(tok->manufacturer, sizeof(tok->manufacturer),
				"Chunghwa TeleCom Co., Ltd.");
	return 0;
}

static int
parse_dir_label_path(const unsigned char *buf, size_t len,
		char *label, size_t labelsz, oh_path_t *app_path)
{
	const unsigned char *p = buf;
	const unsigned char *end = buf + len;
	oh_der_t app, t;

	memset(app_path, 0, sizeof(*app_path));
	if (label && labelsz)
		label[0] = '\0';

	while (p < end) {
		if (*p == 0xFF || *p == 0x00)
			break;
		if (oh_der_next(&p, end, &app) != 0)
			break;
		if (app.tag != 0x61)
			continue;
		{
			const unsigned char *c = app.val;
			while (c < app.end) {
				if (oh_der_next(&c, app.end, &t) != 0)
					break;
				if ((t.tag == 0x50 || t.tag == 0x0C) && label && labelsz)
					copy_label(label, labelsz, t.val, t.len);
				if (t.tag == 0x51 && t.len >= 2 && t.len <= OH_MAX_PATH) {
					memcpy(app_path->path, t.val, t.len);
					app_path->path_len = t.len;
				}
			}
		}
		if (app_path->path_len)
			return 0;
	}
	return -1;
}

static int
ensure_pkcs15_df(oh_pcsc_t *p)
{
	oh_path_t dir_path, app_path;
	unsigned char *dir = NULL;
	size_t dir_len = 0;
	char label[OH_MAX_LABEL];

	if (oh_select_mf(p) != 0)
		return -1;

	/* EF.DIR → application path (often 3F00/0800 on HiCOS) */
	memset(&dir_path, 0, sizeof(dir_path));
	dir_path.path[0] = 0x2F;
	dir_path.path[1] = 0x00;
	dir_path.path_len = 2;
	if (read_ef_path(p, &dir_path, &dir, &dir_len) == 0) {
		trim_ff(dir, &dir_len);
		if (parse_dir_label_path(dir, dir_len, label, sizeof(label), &app_path) == 0) {
			free(dir);
			if (oh_select_path(p, app_path.path, app_path.path_len, 1) == 0)
				return 0;
		} else {
			free(dir);
		}
	}

	(void)oh_select_mf(p);
	if (oh_select_aid(p, OH_AID_PKCS15, OH_AID_PKCS15_LEN) == 0)
		return 0;
	(void)oh_select_mf(p);
	if (oh_select_fid(p, FID_PKCS15_DF) == 0)
		return 0;
	/* Observed on some T7S cards */
	(void)oh_select_mf(p);
	if (oh_select_fid(p, 0x0900) == 0)
		return 0;
	(void)oh_select_mf(p);
	if (oh_select_aid(p, OH_AID_PKI, OH_AID_PKI_LEN) == 0)
		return 0;
	/* At least MF is selected — allow token info even without PKCS#15 DF */
	return oh_select_mf(p);
}

void
oh_p15_free(oh_token_t *tok)
{
	int i;
	if (!tok)
		return;
	for (i = 0; i < tok->nobjs; i++) {
		free(tok->objs[i].data);
		free(tok->objs[i].modulus);
		free(tok->objs[i].pubexp);
		tok->objs[i].data = NULL;
		tok->objs[i].modulus = NULL;
		tok->objs[i].pubexp = NULL;
	}
	memset(tok, 0, sizeof(*tok));
}

oh_object_t *
oh_p15_find(oh_token_t *tok, unsigned long handle)
{
	int i;
	if (!tok)
		return NULL;
	for (i = 0; i < tok->nobjs; i++) {
		if (tok->objs[i].handle == handle)
			return &tok->objs[i];
	}
	return NULL;
}

int
oh_p15_bind(oh_pcsc_t *pcsc, oh_token_t *tok)
{
	oh_path_t odf_path, prkdf, pukdf, cdf, aodf, ti_path;
	unsigned char *odf = NULL, *blob = NULL;
	size_t odf_len = 0, blob_len = 0;

	oh_p15_free(tok);
	snprintf(tok->label, sizeof(tok->label), "HiCOS PKI Smart Card");
	snprintf(tok->manufacturer, sizeof(tok->manufacturer),
			"Chunghwa TeleCom Co., Ltd.");
	snprintf(tok->model, sizeof(tok->model), "HiCOS");
	snprintf(tok->serial, sizeof(tok->serial), "0000000000000000");
	tok->min_pin = 6;
	tok->max_pin = 8;
	tok->pin_ref = 0x00;

	(void)oh_select_mf(pcsc);
	(void)read_hicos_tokeninfo_ef(pcsc, tok);
	(void)read_hicos_card_number(pcsc, tok->serial, sizeof(tok->serial));
	(void)read_hicos_model(pcsc, tok->model, sizeof(tok->model));

	if (ensure_pkcs15_df(pcsc) != 0)
		return -1;

	/* ODF */
	memset(&odf_path, 0, sizeof(odf_path));
	odf_path.path[0] = (FID_ODF >> 8) & 0xFF;
	odf_path.path[1] = FID_ODF & 0xFF;
	odf_path.path_len = 2;
	if (ensure_pkcs15_df(pcsc) != 0) {
		tok->bound = 1;
		return 0;
	}
	if (read_ef_path(pcsc, &odf_path, &odf, &odf_len) != 0) {
		/* Card online but PKCS#15 ODF not reachable yet */
		tok->bound = 1;
		return 0;
	}
	trim_ff(odf, &odf_len);
	if (parse_odf(odf, odf_len, &prkdf, &pukdf, &cdf, &aodf, &ti_path) != 0) {
		/* Fallback common FIDs from OpenSC profile */
		prkdf.path[0] = 0x44;
		prkdf.path[1] = 0x02;
		prkdf.path_len = 2;
		cdf.path[0] = 0x44;
		cdf.path[1] = 0x04;
		cdf.path_len = 2;
		aodf.path[0] = 0x44;
		aodf.path[1] = 0x01;
		aodf.path_len = 2;
	}
	free(odf);

	if (aodf.path_len) {
		if (ensure_pkcs15_df(pcsc) == 0 &&
		    read_ef_path(pcsc, &aodf, &blob, &blob_len) == 0) {
			trim_ff(blob, &blob_len);
			(void)parse_aodf_pin(blob, blob_len, &tok->pin_ref);
			free(blob);
			blob = NULL;
		}
	}

	if (prkdf.path_len) {
		if (ensure_pkcs15_df(pcsc) == 0 &&
		    read_ef_path(pcsc, &prkdf, &blob, &blob_len) == 0) {
			trim_ff(blob, &blob_len);
			(void)parse_prkdf(pcsc, tok, blob, blob_len);
			free(blob);
			blob = NULL;
		}
	}

	if (cdf.path_len) {
		if (ensure_pkcs15_df(pcsc) == 0 &&
		    read_ef_path(pcsc, &cdf, &blob, &blob_len) == 0) {
			trim_ff(blob, &blob_len);
			(void)parse_cdf(pcsc, tok, blob, blob_len);
			free(blob);
			blob = NULL;
		}
	}

	/* Link key refs / RSA from certs to privkeys by matching CKA_ID */
	{
		int i, j;
		for (i = 0; i < tok->nobjs; i++) {
			if (tok->objs[i].cls != OH_CLS_PRIVKEY)
				continue;
			for (j = 0; j < tok->nobjs; j++) {
				if (tok->objs[j].cls != OH_CLS_CERT)
					continue;
				if (tok->objs[i].id_len &&
				    tok->objs[i].id_len == tok->objs[j].id_len &&
				    memcmp(tok->objs[i].id, tok->objs[j].id, tok->objs[i].id_len) == 0) {
					if (!tok->objs[i].modulus && tok->objs[j].modulus) {
						tok->objs[i].modulus = malloc(tok->objs[j].modulus_len);
						tok->objs[i].pubexp = malloc(tok->objs[j].pubexp_len);
						if (tok->objs[i].modulus && tok->objs[i].pubexp) {
							memcpy(tok->objs[i].modulus, tok->objs[j].modulus, tok->objs[j].modulus_len);
							memcpy(tok->objs[i].pubexp, tok->objs[j].pubexp, tok->objs[j].pubexp_len);
							tok->objs[i].modulus_len = tok->objs[j].modulus_len;
							tok->objs[i].pubexp_len = tok->objs[j].pubexp_len;
							tok->objs[i].modulus_bits = tok->objs[j].modulus_bits;
						}
					}
				}
			}
		}
	}

	tok->bound = 1;
	return 0;
}
