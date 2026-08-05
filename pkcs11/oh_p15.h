#ifndef OPENHICOS_P15_H
#define OPENHICOS_P15_H

#include "oh_pcsc.h"

#include <stddef.h>

#define OH_MAX_OBJS   32
#define OH_MAX_LABEL  64
#define OH_MAX_ID     32
#define OH_MAX_PATH   32

typedef enum {
	OH_CLS_PRIVKEY = 1,
	OH_CLS_PUBKEY  = 2,
	OH_CLS_CERT    = 3
} oh_obj_class_t;

typedef struct oh_object {
	unsigned long handle;
	oh_obj_class_t cls;
	char label[OH_MAX_LABEL];
	unsigned char id[OH_MAX_ID];
	size_t id_len;
	int key_ref;          /* private key reference for MSE */
	int can_sign;
	int can_decrypt;
	int can_verify;
	unsigned char *data;  /* cert DER or empty */
	size_t data_len;
	unsigned char *modulus;
	size_t modulus_len;
	unsigned char *pubexp;
	size_t pubexp_len;
	unsigned long modulus_bits;
} oh_object_t;

typedef struct oh_token {
	int bound;
	char label[OH_MAX_LABEL];
	char manufacturer[OH_MAX_LABEL];
	char model[16];
	char serial[32];
	unsigned long min_pin;
	unsigned long max_pin;
	int pin_ref;
	oh_object_t objs[OH_MAX_OBJS];
	int nobjs;
} oh_token_t;

/* Select PKCS#15 app and populate token objects (certs + keys). */
int oh_p15_bind(oh_pcsc_t *pcsc, oh_token_t *tok);
void oh_p15_free(oh_token_t *tok);

oh_object_t *oh_p15_find(oh_token_t *tok, unsigned long handle);

#endif
