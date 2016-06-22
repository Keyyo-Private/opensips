/*
 * $Id: parse_accept_encoding.c 49453 2013-08-06 12:29:46Z cfc $
 *
 * Accept-Encoding parser.
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

#include "../mem/mem.h"
#include "keys.h"
#include "parse_accept_encoding.h"

#define IS_DELIM(c) (*(c) == ' ' || *(c) == '\t' || *(c) == '\r' || *(c) == '\n' || *(c) == ',')

/* from parser/parse_hname2.c: */
#define LOWER_BYTE(b) ((b) | 0x20)
#define LOWER_DWORD(d) ((d) | 0x20202020)
#define READ(val) \
	(*(val + 0) + (*(val + 1) << 8) + (*(val + 2) << 16) + (*(val + 3) << 24))


/*
 * Parse Accept-Encoding HF body.
 */
static inline int parse_accept_encoding_body(str *body, unsigned int *ae)
{
	register char* p;
	register unsigned int val;
	int len, pos = 0;

	*ae = 0;

	p = body->s;
	len = body->len;

	while (pos < len) {
		/* skip spaces and commas */
		for (; pos < len && IS_DELIM(p); ++pos, ++p);

		val = LOWER_DWORD(READ(p));
		switch (val) {

			/* "identity" */
			case _iden_:
				if(pos + ACCEPT_ENCODING_IDENTITY_LEN <= len && LOWER_DWORD(READ(p+4))==_tity_ && IS_DELIM(p+ACCEPT_ENCODING_IDENTITY_LEN)) {
					*ae |= F_ACCEPT_ENCODING_IDENTITY;
					pos += ACCEPT_ENCODING_IDENTITY_LEN + 1; p += ACCEPT_ENCODING_IDENTITY_LEN + 1;
				} else
					goto default_label;
				break;

			/* "gzip" */
			case _gzip_:
				if(pos + ACCEPT_ENCODING_GZIP_LEN <= len && IS_DELIM(p+ACCEPT_ENCODING_GZIP_LEN)) {
					*ae |= F_ACCEPT_ENCODING_GZIP;
					pos += ACCEPT_ENCODING_GZIP_LEN + 1; p += ACCEPT_ENCODING_GZIP_LEN + 1;
				} else
					goto default_label;
				break;

			/* unknown */
			default:
default_label:
				/* skip element */
				for (; pos < len && !IS_DELIM(p); ++pos, ++p);
				break;
		}
	}
	
	return 0;
}

/*
 * Parse all Accept-Encoding headers
 */
int parse_accept_encoding( struct sip_msg *msg)
{
	unsigned int accept_encoding;
	struct hdr_field  *hdr;
	struct accept_encoding_body *aeb;

	/* maybe the header is already parsed! */
	LM_DBG("maybe the header is already parsed\n");
	if (msg->accept_encoding && msg->accept_encoding->parsed)
		return 0;

	/* parse to the end in order to get all ACCEPT_ENCODING headers */
	LM_DBG("parse to the end in order to get all ACCEPT_ENCODING headers\n");
	if (parse_headers(msg,HDR_EOH_F,0)==-1 || !msg->accept_encoding)
		return -1;

	/* bad luck! :-( - we have to parse them */
	accept_encoding = 0;
	for( hdr=msg->accept_encoding ; hdr ; hdr=hdr->sibling) {
		if (hdr->parsed) {
			accept_encoding |= ((struct accept_encoding_body*)hdr->parsed)->accept_encoding;
			LM_DBG("skip this parsed\n");
			continue;
		}

		aeb = (struct accept_encoding_body*)pkg_malloc(sizeof(struct accept_encoding_body));
		if (aeb == 0) {
			LM_ERR("out of pkg_memory\n");
			return -1;
		}

		LM_DBG("parsing [%.*s] %p\n",hdr->len,hdr->name.s,hdr);
		parse_accept_encoding_body(&(hdr->body), &(aeb->accept_encoding));
		aeb->accept_encoding_all = 0;
		hdr->parsed = (void*)aeb;
		accept_encoding |= aeb->accept_encoding;
		LM_DBG("parsing result %d\n", accept_encoding);
	}

	((struct accept_encoding_body*)msg->accept_encoding->parsed)->accept_encoding_all = 
		accept_encoding;
	return 0;
}
