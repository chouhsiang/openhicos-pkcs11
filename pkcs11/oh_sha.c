#include "oh_sha.h"

#include <string.h>

static uint32_t
rr(uint32_t x, int n)
{
	return (x >> n) | (x << (32 - n));
}

static void
store32(unsigned char *p, uint32_t v)
{
	p[0] = (unsigned char)(v >> 24);
	p[1] = (unsigned char)(v >> 16);
	p[2] = (unsigned char)(v >> 8);
	p[3] = (unsigned char)v;
}

static uint32_t
load32(const unsigned char *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void
sha1_block(uint32_t *h, const unsigned char *block)
{
	uint32_t w[80], a, b, c, d, e, f, k, t;
	int i;

	for (i = 0; i < 16; i++)
		w[i] = load32(block + i * 4);
	for (i = 16; i < 80; i++) {
		t = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
		w[i] = (t << 1) | (t >> 31);
	}
	a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4];
	for (i = 0; i < 80; i++) {
		if (i < 20) {
			f = (b & c) | ((~b) & d);
			k = 0x5A827999;
		} else if (i < 40) {
			f = b ^ c ^ d;
			k = 0x6ED9EBA1;
		} else if (i < 60) {
			f = (b & c) | (b & d) | (c & d);
			k = 0x8F1BBCDC;
		} else {
			f = b ^ c ^ d;
			k = 0xCA62C1D6;
		}
		t = ((a << 5) | (a >> 27)) + f + e + k + w[i];
		e = d; d = c; c = (b << 30) | (b >> 2); b = a; a = t;
	}
	h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

void
oh_sha1(const unsigned char *data, size_t len, unsigned char out[20])
{
	uint32_t h[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
	unsigned char block[64];
	uint64_t bits = (uint64_t)len * 8;
	size_t i;

	while (len >= 64) {
		sha1_block(h, data);
		data += 64;
		len -= 64;
	}
	memset(block, 0, 64);
	memcpy(block, data, len);
	block[len] = 0x80;
	if (len >= 56) {
		sha1_block(h, block);
		memset(block, 0, 64);
	}
	for (i = 0; i < 8; i++)
		block[63 - i] = (unsigned char)(bits >> (8 * i));
	sha1_block(h, block);
	for (i = 0; i < 5; i++)
		store32(out + i * 4, h[i]);
}

static void
sha256_block(uint32_t *h, const unsigned char *block)
{
	static const uint32_t K[64] = {
		0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
		0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
		0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
		0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
		0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
		0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
		0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
		0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
	};
	uint32_t w[64], a, b, c, d, e, f, g, hh, t1, t2;
	int i;

	for (i = 0; i < 16; i++)
		w[i] = load32(block + i * 4);
	for (i = 16; i < 64; i++) {
		uint32_t s0 = rr(w[i - 15], 7) ^ rr(w[i - 15], 18) ^ (w[i - 15] >> 3);
		uint32_t s1 = rr(w[i - 2], 17) ^ rr(w[i - 2], 19) ^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	a = h[0]; b = h[1]; c = h[2]; d = h[3];
	e = h[4]; f = h[5]; g = h[6]; hh = h[7];
	for (i = 0; i < 64; i++) {
		uint32_t S1 = rr(e, 6) ^ rr(e, 11) ^ rr(e, 25);
		uint32_t ch = (e & f) ^ ((~e) & g);
		t1 = hh + S1 + ch + K[i] + w[i];
		uint32_t S0 = rr(a, 2) ^ rr(a, 13) ^ rr(a, 22);
		uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
		t2 = S0 + maj;
		hh = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}
	h[0] += a; h[1] += b; h[2] += c; h[3] += d;
	h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void
oh_sha256(const unsigned char *data, size_t len, unsigned char out[32])
{
	uint32_t h[8] = {
		0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
		0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
	};
	unsigned char block[64];
	uint64_t bits = (uint64_t)len * 8;
	size_t i;

	while (len >= 64) {
		sha256_block(h, data);
		data += 64;
		len -= 64;
	}
	memset(block, 0, 64);
	memcpy(block, data, len);
	block[len] = 0x80;
	if (len >= 56) {
		sha256_block(h, block);
		memset(block, 0, 64);
	}
	for (i = 0; i < 8; i++)
		block[63 - i] = (unsigned char)(bits >> (8 * i));
	sha256_block(h, block);
	for (i = 0; i < 8; i++)
		store32(out + i * 4, h[i]);
}
