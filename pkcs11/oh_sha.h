#ifndef OPENHICOS_SHA_H
#define OPENHICOS_SHA_H

#include <stddef.h>
#include <stdint.h>

void oh_sha1(const unsigned char *data, size_t len, unsigned char out[20]);
void oh_sha256(const unsigned char *data, size_t len, unsigned char out[32]);

#endif
