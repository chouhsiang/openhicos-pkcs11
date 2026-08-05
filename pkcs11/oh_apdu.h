#ifndef OPENHICOS_APDU_STANDALONE_H
#define OPENHICOS_APDU_STANDALONE_H

#include "oh_pcsc.h"

#include <stddef.h>
#include <stdint.h>

#define OH_PIN_MAX 10
#define OH_CHUNK   0xC8

extern const unsigned char OH_AID_PKCS15[];
extern const unsigned char OH_AID_PKI[];
extern const size_t OH_AID_PKCS15_LEN;
extern const size_t OH_AID_PKI_LEN;

unsigned char oh_apdu_cla(void);
void oh_apdu_set_cla(unsigned char cla);
void oh_apdu_reset_cla(void);

int oh_select_mf(oh_pcsc_t *p);
int oh_select_aid(oh_pcsc_t *p, const unsigned char *aid, size_t len);
/* SELECT by 2-byte FID (P1=00) under current DF */
int oh_select_fid(oh_pcsc_t *p, unsigned short fid);
/* SELECT by path from MF (P1=08) or current DF (P1=09) */
int oh_select_path(oh_pcsc_t *p, const unsigned char *path, size_t path_len, int from_mf);

int oh_verify_pin(oh_pcsc_t *p, int ref, const unsigned char *pin, size_t pin_len);

/* Read EF from offset; grows *out via realloc. Returns 0 on success. */
int oh_read_binary(oh_pcsc_t *p, unsigned int offset,
		unsigned char *buf, size_t want, size_t *got);
/* Read entire selected EF (stops on error / empty / 6A86). */
int oh_read_ef(oh_pcsc_t *p, unsigned char **out, size_t *out_len);

int oh_mse_set_dst(oh_pcsc_t *p, unsigned char key_ref);
int oh_mse_set_decipher(oh_pcsc_t *p, unsigned char key_ref);

int oh_pso_cds(oh_pcsc_t *p, const unsigned char *data, size_t data_len,
		unsigned char *out, size_t *out_len);
int oh_pso_decipher(oh_pcsc_t *p, const unsigned char *cipher, size_t cipher_len,
		unsigned char *out, size_t *out_len);

#endif
