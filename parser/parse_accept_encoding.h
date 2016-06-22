/*
 * $Id: parse_accept_encoding.h 49453 2013-08-06 12:29:46Z cfc $
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

#ifndef PARSE_ACCEPT_ENCODING_H
#define PARSE_ACCEPT_ENCODING_H

#include "msg_parser.h"
#include "../mem/mem.h"


#define F_ACCEPT_ENCODING_IDENTITY	(1 << 0)
#define F_ACCEPT_ENCODING_GZIP		(1 << 1)

#define ACCEPT_ENCODING_IDENTITY_STR	"identity"
#define ACCEPT_ENCODING_IDENTITY_LEN	(sizeof(ACCEPT_ENCODING_IDENTITY_STR)-1)

#define ACCEPT_ENCODING_GZIP_STR	"gzip"
#define ACCEPT_ENCODING_GZIP_LEN	(sizeof(ACCEPT_ENCODING_GZIP_STR)-1)

#define get_accept_encoding(p_msg) \
	((p_msg)->accept_encoding ? ((struct accept_encoding_body*)(p_msg)->accept_encoding->parsed)->accept_encoding_all : F_ACCEPT_ENCODING_IDENTITY)


struct accept_encoding_body {
	unsigned int accept_encoding;        /* accept_encoding mask for the current hdr */
	unsigned int accept_encoding_all;    /* suppoted mask for the all "accept_encoding" hdr
	                                      *  - it's set only for the first hdr in 
	                                      *  sibling list*/
};

/*
 * Parse all Accept-Encoding headers.
 */
int parse_accept_encoding( struct sip_msg *msg);


static inline void free_accept_encoding(struct accept_encoding_body **aeb)
{
	if (aeb && *aeb) {
		pkg_free(*aeb);
		*aeb = 0;
	}
}

#endif /* PARSE_ACCEPT_ENCODING_H */
