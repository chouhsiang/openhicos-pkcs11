#ifndef OPENHICOS_DER_H
#define OPENHICOS_DER_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
	unsigned int tag;
	size_t hdr_len;
	size_t len;
	const unsigned char *val;
	const unsigned char *end; /* val + len */
} oh_der_t;

/* Parse one TLV at *pp; advances *pp past the whole TLV. Returns 0 on success. */
int oh_der_next(const unsigned char **pp, const unsigned char *end, oh_der_t *out);

/* Expect constructed SEQUENCE (0x30). */
int oh_der_seq(const unsigned char **pp, const unsigned char *end, oh_der_t *out);

/* Walk children of a constructed TLV. */
int oh_der_enter(const oh_der_t *parent, const unsigned char **child, const unsigned char **child_end);

int oh_der_find_tag(const unsigned char *p, const unsigned char *end,
		unsigned int tag, oh_der_t *out);

/* Copy OCTET STRING / BIT STRING contents (skips unused-bits byte for BIT STRING). */
int oh_der_get_bytes(const oh_der_t *t, const unsigned char **data, size_t *len);

#endif
