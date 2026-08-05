#include "oh_apdu.h"

#include <stdlib.h>
#include <string.h>

const unsigned char OH_AID_PKCS15[] = {
	0xA0, 0x00, 0x00, 0x00, 0x63,
	0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35
};
const unsigned char OH_AID_PKI[] = {
	0xA0, 0x00, 0x00, 0x02, 0x83, 0x00, 0x00, 0x06,
	0x22, 0x01, 0x00, 0x01
};
const size_t OH_AID_PKCS15_LEN = sizeof OH_AID_PKCS15;
const size_t OH_AID_PKI_LEN = sizeof OH_AID_PKI;

/*
 * HiCOS T7S / CHTMOICA cards use proprietary CLA 0x80 (see HiCOS_SelFile).
 * ISO-style cards use CLA 0x00. Detect on first successful SELECT MF.
 */
static unsigned char g_cla = 0x80;
static int g_cla_locked;

static int
oh_ok(unsigned int sw)
{
	return sw == 0x9000;
}

unsigned char
oh_apdu_cla(void)
{
	return g_cla;
}

void
oh_apdu_set_cla(unsigned char cla)
{
	g_cla = cla;
	g_cla_locked = 1;
}

void
oh_apdu_reset_cla(void)
{
	g_cla = 0x80;
	g_cla_locked = 0;
}

static int
select_mf_with_cla(oh_pcsc_t *p, unsigned char cla)
{
	unsigned char cmd[7] = { cla, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00 };
	unsigned int sw = 0;
	size_t rlen = 0;

	if (oh_pcsc_transmit(p, cmd, sizeof(cmd), NULL, &rlen, &sw) != 0)
		return -1;
	return oh_ok(sw) ? 0 : -1;
}

int
oh_select_mf(oh_pcsc_t *p)
{
	static const unsigned char try_cla[] = { 0x80, 0x00 };
	size_t i;

	if (g_cla_locked)
		return select_mf_with_cla(p, g_cla);

	for (i = 0; i < sizeof(try_cla); i++) {
		if (select_mf_with_cla(p, try_cla[i]) == 0) {
			g_cla = try_cla[i];
			g_cla_locked = 1;
			return 0;
		}
	}
	return -1;
}

int
oh_select_aid(oh_pcsc_t *p, const unsigned char *aid, size_t len)
{
	unsigned char cmd[32];
	unsigned int sw = 0;
	size_t rlen = 0;
	unsigned char p2_try[] = { 0x0C, 0x00 };
	size_t i;

	if (len == 0 || len > 16)
		return -1;

	for (i = 0; i < sizeof(p2_try); i++) {
		cmd[0] = g_cla;
		cmd[1] = 0xA4;
		cmd[2] = 0x04;
		cmd[3] = p2_try[i];
		cmd[4] = (unsigned char)len;
		memcpy(cmd + 5, aid, len);
		rlen = 0;
		if (oh_pcsc_transmit(p, cmd, 5 + len, NULL, &rlen, &sw) != 0)
			continue;
		if (oh_ok(sw))
			return 0;
	}
	return -1;
}

int
oh_select_fid(oh_pcsc_t *p, unsigned short fid)
{
	unsigned char cmd[7] = {
		g_cla, 0xA4, 0x00, 0x00, 0x02,
		(unsigned char)(fid >> 8), (unsigned char)(fid & 0xFF)
	};
	unsigned int sw = 0;
	size_t rlen = 0;

	if (oh_pcsc_transmit(p, cmd, sizeof(cmd), NULL, &rlen, &sw) != 0)
		return -1;
	return oh_ok(sw) ? 0 : -1;
}

int
oh_select_path(oh_pcsc_t *p, const unsigned char *path, size_t path_len, int from_mf)
{
	size_t i;

	if (!path || path_len == 0 || (path_len & 1))
		return -1;

	/* HiCOS_SelFile walks path two bytes at a time */
	if (from_mf && oh_select_mf(p) != 0)
		return -1;

	for (i = 0; i + 1 < path_len; i += 2) {
		/* Skip leading MF if already selected */
		if (i == 0 && path[0] == 0x3F && path[1] == 0x00 && from_mf)
			continue;
		if (oh_select_fid(p, (unsigned short)((path[i] << 8) | path[i + 1])) != 0)
			return -1;
	}
	return 0;
}

int
oh_verify_pin(oh_pcsc_t *p, int ref, const unsigned char *pin, size_t pin_len)
{
	unsigned char cmd[5 + OH_PIN_MAX];
	unsigned char pinbuf[OH_PIN_MAX];
	unsigned int sw = 0;
	size_t rlen = 0;
	size_t n;

	if (!pin || pin_len == 0)
		return -1;
	memset(pinbuf, 0xFF, sizeof(pinbuf));
	n = pin_len > OH_PIN_MAX ? OH_PIN_MAX : pin_len;
	memcpy(pinbuf, pin, n);

	cmd[0] = g_cla;
	cmd[1] = 0x20;
	cmd[2] = 0x00;
	cmd[3] = (unsigned char)(ref & 0xFF);
	cmd[4] = OH_PIN_MAX;
	memcpy(cmd + 5, pinbuf, OH_PIN_MAX);

	if (oh_pcsc_transmit(p, cmd, sizeof(cmd), NULL, &rlen, &sw) != 0)
		return -1;
	memset(pinbuf, 0, sizeof(pinbuf));
	if (sw == 0x6983)
		return -2;
	if ((sw & 0xFFF0) == 0x63C0)
		return -3;
	return oh_ok(sw) ? 0 : -1;
}

int
oh_read_binary(oh_pcsc_t *p, unsigned int offset,
		unsigned char *buf, size_t want, size_t *got)
{
	unsigned char cmd[5];
	unsigned int sw = 0;
	size_t rlen;
	size_t try_want = want;

	if (!buf || !got || want == 0 || want > 255)
		return -1;
	if (offset > 0x7FFF)
		return -1;

retry:
	cmd[0] = g_cla;
	cmd[1] = 0xB0;
	cmd[2] = (unsigned char)((offset >> 8) & 0x7F);
	cmd[3] = (unsigned char)(offset & 0xFF);
	cmd[4] = (unsigned char)try_want;

	rlen = try_want;
	if (oh_pcsc_transmit(p, cmd, 5, buf, &rlen, &sw) != 0)
		return -1;
	/* Some HiCOS EFs reject large Le with 6987 — retry smaller */
	if (sw == 0x6987 && try_want > 16) {
		try_want = 16;
		goto retry;
	}
	if (!oh_ok(sw) && (sw & 0xFF00) != 0x6200)
		return -1;
	*got = rlen;
	return 0;
}

int
oh_read_ef(oh_pcsc_t *p, unsigned char **out, size_t *out_len)
{
	unsigned char chunk[OH_CHUNK];
	unsigned char *buf = NULL;
	size_t total = 0;
	unsigned int off = 0;
	size_t chunk_sz = 0x20; /* safer default for HiCOS */

	if (!out || !out_len)
		return -1;
	*out = NULL;
	*out_len = 0;

	for (;;) {
		size_t got = 0;
		unsigned char *nbuf;
		size_t want = chunk_sz;

		if (oh_read_binary(p, off, chunk, want, &got) != 0)
			break;
		if (got == 0)
			break;
		nbuf = realloc(buf, total + got);
		if (!nbuf) {
			free(buf);
			return -1;
		}
		buf = nbuf;
		memcpy(buf + total, chunk, got);
		total += got;
		off += (unsigned int)got;
		if (got < want)
			break;
		if (off > 64 * 1024) {
			free(buf);
			return -1;
		}
	}

	if (total == 0) {
		free(buf);
		return -1;
	}
	*out = buf;
	*out_len = total;
	return 0;
}

int
oh_mse_set_dst(oh_pcsc_t *p, unsigned char key_ref)
{
	unsigned char cmd[5 + 6] = {
		0x00, 0x22, 0x41, 0xA4, 0x06,
		0x84, 0x01, key_ref, 0x80, 0x01, 0x02
	};
	unsigned int sw = 0;
	size_t rlen = 0;

	cmd[0] = g_cla;
	if (oh_pcsc_transmit(p, cmd, sizeof(cmd), NULL, &rlen, &sw) != 0)
		return -1;
	return oh_ok(sw) ? 0 : -1;
}

int
oh_mse_set_decipher(oh_pcsc_t *p, unsigned char key_ref)
{
	unsigned char cmd[5 + 6] = {
		0x00, 0x22, 0x41, 0xB8, 0x06,
		0x84, 0x01, key_ref, 0x80, 0x01, 0x02
	};
	unsigned int sw = 0;
	size_t rlen = 0;

	cmd[0] = g_cla;
	if (oh_pcsc_transmit(p, cmd, sizeof(cmd), NULL, &rlen, &sw) != 0)
		return -1;
	if (oh_ok(sw))
		return 0;
	cmd[5] = 0x83;
	if (oh_pcsc_transmit(p, cmd, sizeof(cmd), NULL, &rlen, &sw) != 0)
		return -1;
	return oh_ok(sw) ? 0 : -1;
}

int
oh_pso_cds(oh_pcsc_t *p, const unsigned char *data, size_t data_len,
		unsigned char *out, size_t *out_len)
{
	unsigned char cmd[5 + 512];
	unsigned char resp[512];
	unsigned int sw = 0;
	size_t rlen = sizeof(resp);

	if (!data || data_len == 0 || data_len > 255 || !out || !out_len)
		return -1;

	cmd[0] = g_cla;
	cmd[1] = 0x2A;
	cmd[2] = 0x9E;
	cmd[3] = 0x9A;
	cmd[4] = (unsigned char)data_len;
	memcpy(cmd + 5, data, data_len);
	cmd[5 + data_len] = 0x00;

	if (oh_pcsc_transmit(p, cmd, 6 + data_len, resp, &rlen, &sw) != 0)
		return -1;
	if (!oh_ok(sw))
		return -1;
	if (rlen > *out_len)
		return -1;
	memcpy(out, resp, rlen);
	*out_len = rlen;
	return 0;
}

int
oh_pso_decipher(oh_pcsc_t *p, const unsigned char *cipher, size_t cipher_len,
		unsigned char *out, size_t *out_len)
{
	unsigned char cmd[5 + 513];
	unsigned char resp[512];
	unsigned int sw = 0;
	size_t rlen = sizeof(resp);
	size_t lc;

	if (!cipher || cipher_len == 0 || cipher_len > 512 || !out || !out_len)
		return -1;

	lc = cipher_len + 1;
	if (lc > 255)
		return -1;

	cmd[0] = g_cla;
	cmd[1] = 0x2A;
	cmd[2] = 0x80;
	cmd[3] = 0x86;
	cmd[4] = (unsigned char)lc;
	cmd[5] = 0x00;
	memcpy(cmd + 6, cipher, cipher_len);
	cmd[6 + cipher_len] = 0x00;

	if (oh_pcsc_transmit(p, cmd, 7 + cipher_len, resp, &rlen, &sw) != 0)
		return -1;
	if (!oh_ok(sw)) {
		cmd[4] = (unsigned char)cipher_len;
		memcpy(cmd + 5, cipher, cipher_len);
		cmd[5 + cipher_len] = 0x00;
		rlen = sizeof(resp);
		if (oh_pcsc_transmit(p, cmd, 6 + cipher_len, resp, &rlen, &sw) != 0)
			return -1;
		if (!oh_ok(sw))
			return -1;
	}
	if (rlen > *out_len)
		return -1;
	memcpy(out, resp, rlen);
	*out_len = rlen;
	return 0;
}
