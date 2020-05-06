/*
 * $Id$
 *
 * pua_dialoginfo module - publish dialog-info from dialog module
 *
 * Copyright (C) 2006 Voice Sistem S.R.L.
 * Copyright (C) 2008 Klaus Darilion IPCom
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
 */

#ifndef _PUA_DLGINFO_H
#define _PUA_DLGINFO_H
#include "../pua/pua_bind.h"
#include "pua_avp.h"

send_publish_t pua_send_publish;

void dialog_publish(char *state, struct to_body* entity, struct to_body* realentity, struct to_body *peer, str *callid,
	unsigned int initiator, unsigned int lifetime, str *localtag, str *remotetag,
	int local_rendering, int remote_rendering, str *setup_ts, str *connect_ts, str *release_ts, str *replace,
	str *icid, pua_avp_info *extra_info);

extern str presence_server;

#endif
