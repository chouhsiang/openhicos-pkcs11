#ifndef OPENHICOS_PCSC_H
#define OPENHICOS_PCSC_H

#include <stddef.h>
#include <stdint.h>

#if defined(__APPLE__)
#  include <PCSC/winscard.h>
#  include <PCSC/wintypes.h>
#elif defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <winscard.h>
#else
/* Linux / *BSD: pcsc-lite */
#  include <winscard.h>
#endif

typedef struct oh_pcsc {
	SCARDCONTEXT ctx;
	SCARDHANDLE card;
	DWORD proto;
	int connected;
	char reader[128];
} oh_pcsc_t;

int oh_pcsc_init(oh_pcsc_t *p);
void oh_pcsc_fini(oh_pcsc_t *p);
int oh_pcsc_list_readers(oh_pcsc_t *p, char *buf, size_t buflen);
int oh_pcsc_connect(oh_pcsc_t *p, const char *reader);
void oh_pcsc_disconnect(oh_pcsc_t *p);

/* Send APDU; resp includes data only (SW stripped into sw). */
int oh_pcsc_transmit(oh_pcsc_t *p,
		const unsigned char *cmd, size_t cmd_len,
		unsigned char *resp, size_t *resp_len,
		unsigned int *sw);

#endif
