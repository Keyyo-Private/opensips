/*
 * $Id$
 *
 * content_encoding module - Content-Encoding operations module
 *
 * Copyright (C) 2013 Keyyo
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <zlib.h>

#include "../../sr_module.h"
#include "../../mem/mem.h"
#include "../../parser/parse_accept_encoding.h"
#include "api.h"

/* module functions */
static int mod_init(void);
static int child_init(int);
void destroy(void);

static cmd_export_t cmds[]=
{
	{ "load_content_encoding", (cmd_function)load_content_encoding, 0, 0, 0, 0},
	{ 0, 0, 0, 0, 0, 0 }
};

static param_export_t params[]={
	{ 0, 0, 0 }
};

/** module exports */
struct module_exports exports = {
	"content_encoding",         /* module name */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,            /* dlopen flags */
	cmds,                       /* exported functions */
	params,                     /* exported parameters */
	0,                          /* exported statistics */
	0,                          /* exported MI functions */
	0,                          /* exported pseudo-variables */
	0,                          /* extra processes */
	mod_init,                   /* module initialization function */
	(response_function) 0,      /* response handling function */
	(destroy_function) destroy, /* destroy function */
	child_init                  /* per-child init function */
};


void gzip_deflate(const str *body, str *gzip_body)
{
	z_stream strm;

	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;

	gzip_body->s = pkg_malloc(body->len);

	if(gzip_body->s) {
		gzip_body->len = body->len;
		if(deflateInit2(&strm, Z_BEST_SPEED, Z_DEFLATED, (16 + MAX_WBITS),8, Z_DEFAULT_STRATEGY) == Z_OK) {

			strm.next_in = (Bytef *) body->s;
			strm.avail_in = gzip_body->len;
			strm.next_out = (Bytef *) gzip_body->s;
			strm.avail_out = gzip_body->len;

			if(deflate(&strm, Z_FINISH) != Z_STREAM_ERROR) {
				gzip_body->len = strm.total_out;
			} else {
				LM_WARN("failed to deflate\n");
			}
		} else {
			LM_WARN("failed to init deflate\n");
		}
		deflateEnd(&strm);
	} else {
		LM_WARN("failed to allocate gzip buffer (%d)\n", body->len);
	}

	if(gzip_body->len == 0) {
		if(gzip_body->s)
		{
			pkg_free(gzip_body->s);
			gzip_body->s = NULL;
		}
	}
}

struct encoded_body *encode_body(const str *body, int accept_encoding)
{
	struct encoded_body *eb;

	if(!body || !body->s || body->len == 0) {
		// Don't bother
		return NULL;
	}

	if(accept_encoding & F_ACCEPT_ENCODING_GZIP) {
		if( (eb = (struct encoded_body *) pkg_malloc(sizeof(struct encoded_body))) == NULL ) {
			LM_WARN("failed to allocate encoded_body (%ld)\n", sizeof(struct encoded_body));
		} else {
			memset(eb, 0, sizeof(struct encoded_body));
			gzip_deflate(body, &eb->body);

			if(eb->body.len == 0) {
				/* Encoding error, give up */
				pkg_free(eb);
				eb = NULL;
			} else {
				/* Define Content-Encoding header */
				eb->content_encoding_hdr.s = "Content-Encoding: gzip" CRLF;
				eb->content_encoding_hdr.len = 22 + CRLF_LEN;
			}
		}
	} else {
		/* Unsupported encoding or identity */
		eb = NULL;
	}
	return eb;
}

void free_encoded_body(struct encoded_body *encoded_body)
{
	if(encoded_body) {
		if(encoded_body->body.s) {
			pkg_free(encoded_body->body.s);
			encoded_body->body.s = NULL;
		}

		pkg_free(encoded_body);
		encoded_body = NULL;
	}
}

static int mod_init(void)
{
	return 0;
}


static int child_init(int rank)
{
	return 0;
}


void destroy(void)
{
	return;
}

