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

#ifndef CONTENT_ENCODING_API_H
#define CONTENT_ENCODING_API_H

#include "../../str.h"
#include "../../dprint.h"
#include "../../sr_module.h"
#include "content_encoding.h"

typedef struct encoded_body* (*encode_body_t)(const str *body, int accept_encoding);
typedef void (*free_encoded_body_t)(struct encoded_body *encoded_body);

str *encoded_body_content_type(int accept_encoding);
struct content_encoding_binds {
	encode_body_t encode_body;
	free_encoded_body_t free_encoded_body;
	
};

struct encoded_body {
	str body;
	str content_encoding_hdr;
};

typedef int (*load_content_encoding_f)(struct content_encoding_binds *ceb);

int load_content_encoding(struct content_encoding_binds *ceb);

static inline int load_content_encoding_api( struct content_encoding_binds *ceb )
{
	load_content_encoding_f load_content_encoding;

	/* import the content_encoding auto-loading function */
	if ( !(load_content_encoding=(load_content_encoding_f)find_export("load_content_encoding", 0, 0)))
		return -1;

	/* let the auto-loading function load all content encoding stuff */
	if (load_content_encoding( ceb )==-1)
		return -1;

	return 0;
}


#endif

