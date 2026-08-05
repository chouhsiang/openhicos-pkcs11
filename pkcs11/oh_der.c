#include "oh_der.h"

int
oh_der_next(const unsigned char **pp, const unsigned char *end, oh_der_t *out)
{
	const unsigned char *p;
	unsigned int tag;
	size_t len;
	size_t hdr;

	if (!pp || !out || !*pp || *pp >= end)
		return -1;
	p = *pp;
	tag = *p++;
	hdr = 1;
	if ((tag & 0x1F) == 0x1F) {
		tag = tag << 8;
		if (p >= end)
			return -1;
		tag |= *p++;
		hdr++;
	}
	if (p >= end)
		return -1;
	if (*p & 0x80) {
		unsigned n = *p++ & 0x7F;
		size_t i;
		hdr++;
		if (n == 0 || n > 4 || p + n > end)
			return -1;
		len = 0;
		for (i = 0; i < n; i++) {
			len = (len << 8) | p[i];
			hdr++;
		}
		p += n;
	} else {
		len = *p++;
		hdr++;
	}
	if (p + len > end)
		return -1;
	out->tag = tag;
	out->hdr_len = hdr;
	out->len = len;
	out->val = p;
	out->end = p + len;
	*pp = p + len;
	return 0;
}

int
oh_der_seq(const unsigned char **pp, const unsigned char *end, oh_der_t *out)
{
	if (oh_der_next(pp, end, out) != 0)
		return -1;
	return out->tag == 0x30 ? 0 : -1;
}

int
oh_der_enter(const oh_der_t *parent, const unsigned char **child, const unsigned char **child_end)
{
	if (!parent || !(parent->tag & 0x20))
		return -1;
	*child = parent->val;
	*child_end = parent->end;
	return 0;
}

int
oh_der_find_tag(const unsigned char *p, const unsigned char *end,
		unsigned int tag, oh_der_t *out)
{
	while (p < end) {
		oh_der_t t;
		const unsigned char *q = p;
		if (oh_der_next(&q, end, &t) != 0)
			return -1;
		if (t.tag == tag) {
			*out = t;
			return 0;
		}
		p = q;
	}
	return -1;
}

int
oh_der_get_bytes(const oh_der_t *t, const unsigned char **data, size_t *len)
{
	if (!t || !data || !len)
		return -1;
	if (t->tag == 0x03) { /* BIT STRING */
		if (t->len < 1)
			return -1;
		*data = t->val + 1;
		*len = t->len - 1;
		return 0;
	}
	*data = t->val;
	*len = t->len;
	return 0;
}
