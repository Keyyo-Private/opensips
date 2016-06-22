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


#include "api.h"

int load_content_encoding(struct content_encoding_binds *ceb)
{
	if (!ceb)
	{
		LM_ERR("Invalid parameter value\n");
		return -1;
	}
	ceb->encode_body = encode_body;
	ceb->free_encoded_body = free_encoded_body;
	return 0;
}

