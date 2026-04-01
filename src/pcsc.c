/*
 * Copyright (c) 2022 Micro Focus or one of its affiliates.
 * Copyright (c) 2022 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#if __APPLE__
#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>
#else
#include <winscard.h>
#endif /* __APPLE__ */

#include <errno.h>

#include "fido.h"
#include "fido/param.h"
#include "iso7816.h"

#if defined(_WIN32) && !defined(__MINGW32__)
#define SCardConnect SCardConnectA
#define SCardListReaders SCardListReadersA
#endif

#ifndef SCARD_PROTOCOL_Tx
#define SCARD_PROTOCOL_Tx SCARD_PROTOCOL_ANY
#endif

#define BUFSIZE 1024	/* in bytes; passed to SCardListReaders() */
#define APDULEN 264	/* 261 rounded up to the nearest multiple of 8 */
#define READERS 8	/* maximum number of readers */

/* persistent connection handle for reuse */
static TLS SCARDHANDLE pcsc_persistent_handle = 0;
static TLS SCARDCONTEXT pcsc_persistent_context = 0;

static TLS bool pcsc_handle_consumed = false;  /* Track if handle was used by fido_pcsc_open */

struct pcsc {
	SCARDCONTEXT     ctx;
	SCARDHANDLE      h;
	SCARD_IO_REQUEST req;
	uint8_t          rx_buf[APDULEN];
	size_t           rx_len;
};

static LONG
list_readers(SCARDCONTEXT ctx, char **buf)
{
	LONG s;
	DWORD len;

	len = BUFSIZE;
	if ((*buf = calloc(1, len)) == NULL)
		goto fail;
	if ((s = SCardListReaders(ctx, NULL, *buf, &len)) != SCARD_S_SUCCESS) {
		fido_log_debug("%s: SCardListReaders 0x%lx", __func__, (long)s);
		goto fail;
	}
	/* sanity check "multi-string" */
	if (len > BUFSIZE || len < 2) {
		fido_log_debug("%s: bogus len=%u", __func__, (unsigned)len);
		goto fail;
	}
	if ((*buf)[len - 1] != 0 || (*buf)[len - 2] != '\0') {
		fido_log_debug("%s: bogus buf", __func__);
		goto fail;
	}
	return (LONG)SCARD_S_SUCCESS;
fail:
	free(*buf);
	*buf = NULL;

	return (LONG)SCARD_E_NO_READERS_AVAILABLE;
}

static char *
get_reader(SCARDCONTEXT ctx, const char *path)
{
	char *reader = NULL, *buf = NULL;
	const char prefix[] = FIDO_PCSC_PREFIX "//slot";
	uint64_t n;

	if (path == NULL)
		goto out;
	if (strncmp(path, prefix, strlen(prefix)) != 0 ||
	    fido_to_uint64(path + strlen(prefix), 10, &n) < 0 ||
	    n > READERS - 1) {
		fido_log_debug("%s: invalid path %s", __func__, path);
		goto out;
	}
	if (list_readers(ctx, &buf) != SCARD_S_SUCCESS) {
		fido_log_debug("%s: list_readers", __func__);
		goto out;
	}
	for (const char *name = buf; *name != 0; name += strlen(name) + 1) {
		if (n == 0) {
			reader = strdup(name);
			goto out;
		}
		n--;
	}
	fido_log_debug("%s: failed to find reader %s", __func__, path);
out:
	free(buf);

	return reader;
}

static int
prepare_io_request(DWORD prot, SCARD_IO_REQUEST *req)
{
	switch (prot) {
	case SCARD_PROTOCOL_T0:
		req->dwProtocol = SCARD_PCI_T0->dwProtocol;
		req->cbPciLength = SCARD_PCI_T0->cbPciLength;
		break;
	case SCARD_PROTOCOL_T1:
		req->dwProtocol = SCARD_PCI_T1->dwProtocol;
		req->cbPciLength = SCARD_PCI_T1->cbPciLength;
		break;
	default:
		fido_log_debug("%s: unknown protocol %lu", __func__,
		    (u_long)prot);
		return -1;
	}

	return 0;
}

static int
copy_info(fido_dev_info_t *di, SCARDCONTEXT ctx, const char *reader, size_t idx)
{
	SCARDHANDLE h = 0;
	SCARD_IO_REQUEST req;
	DWORD prot = 0;
	LONG s;
	int ok = -1;

	memset(di, 0, sizeof(*di));
	memset(&req, 0, sizeof(req));

	if ((s = SCardConnect(ctx, reader, SCARD_SHARE_SHARED,
	    SCARD_PROTOCOL_Tx, &h, &prot)) != SCARD_S_SUCCESS) {
		fido_log_debug("%s: SCardConnect 0x%lx", __func__, (long)s);
		goto fail;
	}
	fido_log_debug("%s: %s", __func__, reader);
	if (prepare_io_request(prot, &req) < 0) {
		fido_log_debug("%s: prepare_io_request", __func__);
		goto fail;
	}
	if (asprintf(&di->path, "%s//slot%zu", FIDO_PCSC_PREFIX, idx) == -1) {
		di->path = NULL;
		fido_log_debug("%s: asprintf", __func__);
		goto fail;
	}

	if (nfc_is_fido(di->path) == false) {
		fido_log_debug("%s: nfc_is_fido: %s", __func__, di->path);
		goto fail;
	}
	if ((di->manufacturer = strdup("PC/SC")) == NULL ||
	    (di->product = strdup(reader)) == NULL)
		goto fail;

	ok = 0;
fail:
	/* In persistent mode, handle was consumed by fido_pcsc_open or needs to be saved */
	if (fido_pcsc_persistent_enabled()) {
		if (h != 0 && ok == 0 && !pcsc_handle_consumed) {
			/* Handle wasn't consumed, save it for later */
			pcsc_persistent_handle = h;
			pcsc_persistent_context = ctx;
		} else if (h != 0 && pcsc_handle_consumed) {
			/* Handle was consumed by fido_pcsc_open, don't disconnect */
			fido_log_debug("%s: PERSISTENT: connection kept open", __func__);
		} else if (h != 0) {
			/* Failed, disconnect */
			SCardDisconnect(h, SCARD_LEAVE_CARD);
		}
	} else if (h != 0) {
		SCardDisconnect(h, SCARD_LEAVE_CARD);
	}
	if (ok < 0) {
		free(di->path);
		free(di->manufacturer);
		free(di->product);
		explicit_bzero(di, sizeof(*di));
	}

	return ok;
}

int
fido_pcsc_manifest(fido_dev_info_t *devlist, size_t ilen, size_t *olen)
{
	SCARDCONTEXT ctx = 0;
	char *buf = NULL;
	LONG s;
	size_t idx = 0;
	int r = FIDO_ERR_INTERNAL;

	*olen = 0;

	if (ilen == 0)
		return FIDO_OK;
	if (devlist == NULL)
		return FIDO_ERR_INVALID_ARGUMENT;

	if ((s = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL,
	    &ctx)) != SCARD_S_SUCCESS || ctx == 0) {
		fido_log_debug("%s: SCardEstablishContext 0x%lx", __func__,
		    (long)s);
		if (s == (LONG)SCARD_E_NO_SERVICE ||
		    s == (LONG)SCARD_E_NO_SMARTCARD)
			r = FIDO_OK; /* suppress error */
		goto out;
	}
	if ((s = list_readers(ctx, &buf)) != SCARD_S_SUCCESS) {
		fido_log_debug("%s: list_readers 0x%lx", __func__, (long)s);
		if (s == (LONG)SCARD_E_NO_READERS_AVAILABLE)
			r = FIDO_OK; /* suppress error */
		goto out;
	}

	for (const char *name = buf; *name != 0; name += strlen(name) + 1) {
		if (idx == READERS) {
			fido_log_debug("%s: stopping at %zu readers", __func__,
			    idx);
			r = FIDO_OK;
			goto out;
		}
		if (copy_info(&devlist[*olen], ctx, name, idx++) == 0) {
			devlist[*olen].io = (fido_dev_io_t) {
				fido_pcsc_open,
				fido_pcsc_close,
				fido_pcsc_read,
				fido_pcsc_write,
			};
			devlist[*olen].transport = (fido_dev_transport_t) {
				fido_pcsc_rx,
				fido_pcsc_tx,
			};
			if (++(*olen) == ilen)
				break;
		}
	}

	r = FIDO_OK;
out:
	free(buf);
	/* In persistent mode, don't release context - it's saved in copy_info */
	if (ctx != 0 && !fido_pcsc_persistent_enabled())
		SCardReleaseContext(ctx);

	return r;
}

void *
fido_pcsc_open(const char *path)
{
	char *reader = NULL;
	struct pcsc *dev = NULL;
	SCARDCONTEXT ctx = 0;
	SCARDHANDLE h = 0;
	SCARD_IO_REQUEST req;
	DWORD prot = 0;
	LONG s;

	memset(&req, 0, sizeof(req));

	fido_log_debug("%s: fido_pcsc_persistent_enabled=%d", __func__,
	    (bool)fido_pcsc_persistent_enabled());

	/* In persistent mode, reuse the existing connection from copy_info() */
	if (fido_pcsc_persistent_enabled()) {
		if (pcsc_persistent_handle != 0) {
			fido_log_debug("%s: PERSISTENT: reusing connection", __func__);
			if ((dev = calloc(1, sizeof(*dev))) == NULL)
				goto fail;
			dev->ctx = pcsc_persistent_context;
			dev->h = pcsc_persistent_handle;
			/* Mark handle as consumed */
			pcsc_handle_consumed = true;
			/* Clear persistent handle to prevent reuse */
			pcsc_persistent_handle = 0;
			pcsc_persistent_context = 0;
			/* Need to get the protocol for the io_request */
			DWORD prot_len = sizeof(prot);
			if ((s = SCardStatus(dev->h, NULL, NULL, NULL, &prot, NULL, &prot_len)) 
			    != SCARD_S_SUCCESS) {
				fido_log_debug("%s: SCardStatus 0x%lx", __func__, (long)s);
				free(dev);
				dev = NULL;
				goto fail;
			}
			if (prepare_io_request(prot, &dev->req) < 0) {
				fido_log_debug("%s: prepare_io_request", __func__);
				free(dev);
				dev = NULL;
				goto fail;
			}
			return dev;
		} else {
			fido_log_debug("%s: PERSISTENT: creating new connection", __func__);
			/* Release any orphaned persistent context from copy_info() */
			if (pcsc_persistent_context != 0) {
				SCardReleaseContext(pcsc_persistent_context);
				pcsc_persistent_context = 0;
			}
		}
	}

	if ((s = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL,
	    &ctx)) != SCARD_S_SUCCESS || ctx == 0) {
		fido_log_debug("%s: SCardEstablishContext 0x%lx", __func__,
		    (long)s);
		goto fail;

	}
	if ((reader = get_reader(ctx, path)) == NULL) {
		fido_log_debug("%s: get_reader(%s)", __func__, path);
		goto fail;
	}
	if ((s = SCardConnect(ctx, reader, SCARD_SHARE_SHARED,
	    SCARD_PROTOCOL_Tx, &h, &prot)) != SCARD_S_SUCCESS) {
		fido_log_debug("%s: SCardConnect 0x%lx", __func__, (long)s);
		goto fail;
	}
	if (prepare_io_request(prot, &req) < 0) {
		fido_log_debug("%s: prepare_io_request", __func__);
		goto fail;
	}
	if ((dev = calloc(1, sizeof(*dev))) == NULL)
		goto fail;

	dev->ctx = ctx;
	dev->h = h;
	dev->req = req;
	ctx = 0;
	h = 0;
fail:
	if (h != 0)
		SCardDisconnect(h, SCARD_LEAVE_CARD);
	if (ctx != 0)
		SCardReleaseContext(ctx);
	free(reader);

	return dev;
}

void
fido_pcsc_close(void *handle)
{
	struct pcsc *dev = handle;

	/* In persistent mode, don't disconnect - connection stays open */
	if (fido_pcsc_persistent_enabled()) {
		explicit_bzero(dev->rx_buf, sizeof(dev->rx_buf));
		free(dev);
		return;
	}

	if (dev->h != 0)
		SCardDisconnect(dev->h, SCARD_LEAVE_CARD);
	if (dev->ctx != 0)
		SCardReleaseContext(dev->ctx);

	explicit_bzero(dev->rx_buf, sizeof(dev->rx_buf));
	free(dev);
}

int
fido_pcsc_read(void *handle, unsigned char *buf, size_t len, int ms)
{
	struct pcsc *dev = handle;
	int r;

	(void)ms;
	if (dev->rx_len == 0 || dev->rx_len > len ||
	    dev->rx_len > sizeof(dev->rx_buf)) {
		fido_log_debug("%s: rx_len", __func__);
		return -1;
	}
	fido_log_xxd(dev->rx_buf, dev->rx_len, "%s: reading", __func__);
	memcpy(buf, dev->rx_buf, dev->rx_len);
	explicit_bzero(dev->rx_buf, sizeof(dev->rx_buf));
	r = (int)dev->rx_len;
	dev->rx_len = 0;

	return r;
}

int
fido_pcsc_write(void *handle, const unsigned char *buf, size_t len)
{
	struct pcsc *dev = handle;
	DWORD n;
	LONG s;

	if (len > INT_MAX) {
		fido_log_debug("%s: len", __func__);
		return -1;
	}

	explicit_bzero(dev->rx_buf, sizeof(dev->rx_buf));
	dev->rx_len = 0;
	n = (DWORD)sizeof(dev->rx_buf);

	fido_log_xxd(buf, len, "%s: writing", __func__);

	if ((s = SCardTransmit(dev->h, &dev->req, buf, (DWORD)len, NULL,
	    dev->rx_buf, &n)) != SCARD_S_SUCCESS) {
		fido_log_debug("%s: SCardTransmit 0x%lx", __func__, (long)s);
		explicit_bzero(dev->rx_buf, sizeof(dev->rx_buf));
		return -1;
	}
	dev->rx_len = (size_t)n;

	fido_log_xxd(dev->rx_buf, dev->rx_len, "%s: read", __func__);

	return (int)len;
}

int
fido_pcsc_tx(fido_dev_t *d, uint8_t cmd, const u_char *buf, size_t count)
{
	return fido_nfc_tx(d, cmd, buf, count);
}

int
fido_pcsc_rx(fido_dev_t *d, uint8_t cmd, u_char *buf, size_t count, int ms)
{
	return fido_nfc_rx(d, cmd, buf, count, ms);
}

bool
fido_is_pcsc(const char *path)
{
	return strncmp(path, FIDO_PCSC_PREFIX, strlen(FIDO_PCSC_PREFIX)) == 0;
}

int
fido_dev_set_pcsc(fido_dev_t *d)
{
	if (d->io_handle != NULL) {
		fido_log_debug("%s: device open", __func__);
		return -1;
	}

	d->io_own = true;
	d->io = (fido_dev_io_t) {
		fido_pcsc_open,
		fido_pcsc_close,
		fido_pcsc_read,
		fido_pcsc_write,
	};
	d->transport = (fido_dev_transport_t) {
		fido_pcsc_rx,
		fido_pcsc_tx,
	};

	return 0;
}
