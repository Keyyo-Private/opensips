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

#ifndef CONTENT_ENCODING_H
#define CONTENT_ENCODING_H

struct encoded_body *encode_body(const str *body, int accept_encoding);
void free_encoded_body(struct encoded_body *encoded_body);

#endif

