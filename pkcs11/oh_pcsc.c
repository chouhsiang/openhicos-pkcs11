#include "oh_pcsc.h"

#include <stdio.h>
#include <string.h>

int
oh_pcsc_init(oh_pcsc_t *p)
{
	LONG rv;

	memset(p, 0, sizeof(*p));
	rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &p->ctx);
	return rv == SCARD_S_SUCCESS ? 0 : -1;
}

void
oh_pcsc_fini(oh_pcsc_t *p)
{
	oh_pcsc_disconnect(p);
	if (p->ctx)
		SCardReleaseContext(p->ctx);
	memset(p, 0, sizeof(*p));
}

int
oh_pcsc_list_readers(oh_pcsc_t *p, char *buf, size_t buflen)
{
	DWORD len = (DWORD)buflen;
	LONG rv;

#if defined(_WIN32)
	/* Force ANSI API so char* multi-string readers work under UNICODE builds. */
	rv = SCardListReadersA(p->ctx, NULL, buf, &len);
#else
	rv = SCardListReaders(p->ctx, NULL, buf, &len);
#endif
	return rv == SCARD_S_SUCCESS ? 0 : -1;
}

int
oh_pcsc_connect(oh_pcsc_t *p, const char *reader)
{
	LONG rv;

	if (p->connected)
		oh_pcsc_disconnect(p);

#if defined(_WIN32)
	rv = SCardConnectA(p->ctx, reader, SCARD_SHARE_SHARED,
			SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
			&p->card, &p->proto);
#else
	rv = SCardConnect(p->ctx, reader, SCARD_SHARE_SHARED,
			SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
			&p->card, &p->proto);
#endif
	if (rv != SCARD_S_SUCCESS)
		return -1;

	strncpy(p->reader, reader, sizeof(p->reader) - 1);
	p->reader[sizeof(p->reader) - 1] = '\0';
	p->connected = 1;
	return 0;
}

void
oh_pcsc_disconnect(oh_pcsc_t *p)
{
	if (p->connected) {
		SCardDisconnect(p->card, SCARD_LEAVE_CARD);
		p->connected = 0;
	}
}

int
oh_pcsc_transmit(oh_pcsc_t *p,
		const unsigned char *cmd, size_t cmd_len,
		unsigned char *resp, size_t *resp_len,
		unsigned int *sw)
{
	BYTE rbuf[520];
	DWORD rlen = sizeof(rbuf);
	LONG rv;
	SCARD_IO_REQUEST *pci;
	unsigned int sw1, sw2;

	if (!p->connected)
		return -1;

	pci = (p->proto == SCARD_PROTOCOL_T0)
			? (SCARD_IO_REQUEST *)SCARD_PCI_T0
			: (SCARD_IO_REQUEST *)SCARD_PCI_T1;
	rv = SCardTransmit(p->card, pci, (LPCBYTE)cmd, (DWORD)cmd_len,
			NULL, rbuf, &rlen);
	if (rv != SCARD_S_SUCCESS)
		return -1;
	if (rlen < 2)
		return -1;

	sw1 = rbuf[rlen - 2];
	sw2 = rbuf[rlen - 1];

	/* Handle 6C XX — retry with correct Le */
	if (sw1 == 0x6C && cmd_len >= 5) {
		unsigned char retry[512];
		if (cmd_len > sizeof(retry))
			return -1;
		memcpy(retry, cmd, cmd_len);
		retry[cmd_len - 1] = (unsigned char)sw2;
		rlen = sizeof(rbuf);
		rv = SCardTransmit(p->card, pci, retry, (DWORD)cmd_len,
				NULL, rbuf, &rlen);
		if (rv != SCARD_S_SUCCESS || rlen < 2)
			return -1;
		sw1 = rbuf[rlen - 2];
		sw2 = rbuf[rlen - 1];
	}

	/* Handle 61 XX — GET RESPONSE */
	while (sw1 == 0x61) {
		unsigned char getresp[5] = { 0x00, 0xC0, 0x00, 0x00, (unsigned char)sw2 };
		BYTE more[520];
		DWORD mlen = sizeof(more);
		size_t data_len = rlen - 2;

		rv = SCardTransmit(p->card, pci, getresp, 5, NULL, more, &mlen);
		if (rv != SCARD_S_SUCCESS || mlen < 2)
			return -1;
		if (data_len + (mlen - 2) > sizeof(rbuf) - 2)
			return -1;
		memcpy(rbuf + data_len, more, mlen - 2);
		rlen = (DWORD)(data_len + mlen);
		rbuf[rlen - 2] = more[mlen - 2];
		rbuf[rlen - 1] = more[mlen - 1];
		sw1 = rbuf[rlen - 2];
		sw2 = rbuf[rlen - 1];
	}

	*sw = (sw1 << 8) | sw2;
	if (resp && resp_len) {
		size_t n = rlen - 2;
		if (n > *resp_len)
			return -1;
		memcpy(resp, rbuf, n);
		*resp_len = n;
	}
	return 0;
}
