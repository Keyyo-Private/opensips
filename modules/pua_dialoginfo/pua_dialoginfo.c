/*
 * $Id$
 *
 * pua_dialoginfo module - publish dialog-info from dialog module
 *
 * Copyright (C) 2006 Voice Sistem S.R.L.
 * Copyright (C) 2007-2008 Dan Pascu
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
 *
 * History:
 * --------
 *  2008-08-25  initial version (kd)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/parser.h>
#include <time.h>

#include "../../sr_module.h"
#include "../../script_cb.h"
#include "../../parser/parse_expires.h"
#include "../../dprint.h"
#include "../../mem/shm_mem.h"
#include "../../parser/msg_parser.h"
#include "../../str.h"
#include "../../trim.h"
#include "../../mem/mem.h"
#include "../../pt.h"
#include "../../parser/parse_from.h"
#include "../dialog/dlg_load.h"
#include "../dialog/dlg_hash.h"
#include "../pua/pua_bind.h"
#include "pua_dialoginfo.h"
#include "pua_avp.h"
#include "../../parser/parse_content.h"
#include "../../parser/sdp/sdp_helpr_funcs.h"

#define AUDIO_STR "audio"
#define AUDIO_STR_LEN 5

/* Default module parameter values */
#define DEF_INCLUDE_CALLID 1
#define DEF_INCLUDE_LOCALREMOTE 1
#define DEF_INCLUDE_TAGS 1
#define DEF_CALLER_ALWAYS_CONFIRMED 0

#define DEFAULT_CREATED_LIFETIME 3600

/* define PUA_DIALOGINFO_DEBUG to activate more verbose
 * logging and dialog info callback debugging
 */
/* #define PUA_DIALOGINFO_DEBUG 1 */

#define DLG_PUB_A    'A'  /* caller */
#define DLG_PUB_B    'B'  /* callee */
#define DLG_PUB_AB   'D'  /* default*/

pua_api_t pua;

struct dlg_binds dlg_api;

/* Module parameter variables */
int include_callid      = DEF_INCLUDE_CALLID;
int include_localremote = DEF_INCLUDE_LOCALREMOTE;
int include_tags        = DEF_INCLUDE_TAGS;
int caller_confirmed    = DEF_CALLER_ALWAYS_CONFIRMED;
int early_timeout = -1;
str presence_server = {0, 0};
static str peer_dlg_var = {"dlg_peer", 8};
static str peer_a_dlg_var = {"dlg_peer_a", 10};
static str peer_b_dlg_var = {"dlg_peer_b", 10};
static str entity_dlg_var = {"dlg_entity", 10};
static str entity_a_dlg_var = {"dlg_entity_a", 12};
static str entity_b_dlg_var = {"dlg_entity_b", 12};
static str gpeer_dlg_var = {"dlg_gpeer", 9};
static str gpeer_a_dlg_var = {"dlg_gpeer_a", 11};
static str gpeer_b_dlg_var = {"dlg_gpeer_b", 11};
static str gentity_dlg_var = {"dlg_gentity", 11};
static str gentity_a_dlg_var = {"dlg_gentity_a", 13};
static str gentity_b_dlg_var = {"dlg_gentity_b", 13};
static str flag_dlg_var = {"dlginfo_flag", 12};
static str caller_spec_param= {0, 0};
static str callee_spec_param= {0, 0};
static str caller_a_spec_param= {0, 0};
static str callee_a_spec_param= {0, 0};
static str caller_b_spec_param= {0, 0};
static str callee_b_spec_param= {0, 0};
static pv_spec_t caller_spec;
static pv_spec_t callee_spec;
static pv_spec_t caller_a_spec;
static pv_spec_t callee_a_spec;
static pv_spec_t caller_b_spec;
static pv_spec_t callee_b_spec;
static str gcaller_spec_param= {0, 0};
static str gcallee_spec_param= {0, 0};
static str gcaller_a_spec_param= {0, 0};
static str gcallee_a_spec_param= {0, 0};
static str gcaller_b_spec_param= {0, 0};
static str gcallee_b_spec_param= {0, 0};
static str extra_info_spec_param= {0, 0};
static pv_spec_t gcaller_spec;
static pv_spec_t gcallee_spec;
static pv_spec_t gcaller_a_spec;
static pv_spec_t gcallee_a_spec;
static pv_spec_t gcaller_b_spec;
static pv_spec_t gcallee_b_spec;
static int osips_ps = 1;
static int publish_on_trying = 0;
static int nopublish_flag = -1;


static str setup_dlg_var = {"dlg_setup_time", 14};
static str connect_dlg_var = {"dlg_connect_time", 16};
static str release_dlg_var = {"dlg_release_time", 16};
static str replace_dlg_var = {"dlg_replace", 11};
static str icid_dlg_var = {"dlg_icid", 8};

/** module functions */

static int mod_init(void);
int dialoginfo_set(struct sip_msg* msg, char* str1, char* str2);
static int fixup_dlginfo(void** param, int param_no);


static cmd_export_t cmds[]=
{
	{"dialoginfo_set",(cmd_function)dialoginfo_set,0, 0, 0, REQUEST_ROUTE},
	{"dialoginfo_set",(cmd_function)dialoginfo_set,1,fixup_dlginfo,0, REQUEST_ROUTE},
	{0,                   0,                       0, 0, 0, 0}
};

static param_export_t params[]={
	{"include_callid",      INT_PARAM, &include_callid },
	{"include_localremote", INT_PARAM, &include_localremote },
	{"include_tags",        INT_PARAM, &include_tags },
	{"caller_confirmed",    INT_PARAM, &caller_confirmed },
	{"publish_on_trying",   INT_PARAM, &publish_on_trying },
	{"early_timeout",       INT_PARAM, &early_timeout },
	{"presence_server",     STR_PARAM, &presence_server.s },
	{"caller_spec_param",   STR_PARAM, &caller_spec_param.s },
	{"callee_spec_param",   STR_PARAM, &callee_spec_param.s },
	{"caller_a_spec_param",   STR_PARAM, &caller_a_spec_param.s },
	{"callee_a_spec_param",   STR_PARAM, &callee_a_spec_param.s },
	{"caller_b_spec_param",   STR_PARAM, &caller_b_spec_param.s },
	{"callee_b_spec_param",   STR_PARAM, &callee_b_spec_param.s },
	{"gcaller_spec_param",   STR_PARAM, &gcaller_spec_param.s },
	{"gcallee_spec_param",   STR_PARAM, &gcallee_spec_param.s },
	{"gcaller_a_spec_param",   STR_PARAM, &gcaller_a_spec_param.s },
	{"gcallee_a_spec_param",   STR_PARAM, &gcallee_a_spec_param.s },
	{"gcaller_b_spec_param",   STR_PARAM, &gcaller_b_spec_param.s },
	{"gcallee_b_spec_param",   STR_PARAM, &gcallee_b_spec_param.s },
	{"extra_info_spec_param",  STR_PARAM, &extra_info_spec_param.s },
	{"osips_ps",            INT_PARAM, &osips_ps },
	{"nopublish_flag",	        INT_PARAM, &nopublish_flag	},
	{0, 0, 0 }
};

struct module_exports exports= {
	"pua_dialoginfo",		/* module name */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,		/* dlopen flags */
	cmds,					/* exported functions */
	params,					/* exported parameters */
	0,						/* exported statistics */
	0,						/* exported MI functions */
	0,						/* exported pseudo-variables */
	0,						/* extra processes */
	mod_init,				/* module initialization function */
	0,						/* response handling function */
	0,						/* destroy function */
	NULL					/* per-child init function */
};


#ifdef PUA_DIALOGINFO_DEBUG
static void
__dialog_cbtest(struct dlg_cell *dlg, int type, struct dlg_cb_params *_params)
{
	str tag;

	LM_DBG("dialog callback received, from=%.*s, to=%.*s\n",
		dlg->from_uri.len, dlg->from_uri.s, dlg->to_uri.len, dlg->to_uri.s);

	if (dlg->tag[0].len && dlg->tag[0].s ) {
		LM_DBG("dialog callback: tag[0] = %.*s\n",
			dlg->tag[0].len, dlg->tag[0].s);
	}
	if (dlg->tag[0].len && dlg->tag[1].s ) {
		LM_DBG("dialog callback: tag[1] = %.*s\n",
			dlg->tag[1].len, dlg->tag[1].s);
	}

	if (_params->msg && _params->msg!=FAKED_REPLY && type != DLGCB_DESTROY) {
		/* get to tag*/
		if ( !_params->msg->to) {
			/* to header not defined, parse to header */
			LM_DBG("to header not defined, parse to header\n");
			if (parse_headers(_params->msg, HDR_TO_F,0)<0) {
				/* parser error */
				LM_ERR("parsing of to-header failed\n");
				tag.s = 0;
				tag.len = 0;
			} else if (!_params->msg->to) {
				/* to header still not defined */
				LM_ERR("no to although to-header is parsed: bad reply "
					"or missing TO hdr :-/\n");
				tag.s = 0;
				tag.len = 0;
			} else
				tag = get_to(_params->msg)->tag_value;
		} else {
			tag = get_to(_params->msg)->tag_value;
			if (tag.s==0 || tag.len==0) {
				LM_DBG("missing TAG param in TO hdr :-/\n");
				tag.s = 0;
				tag.len = 0;
			}
		}
		if (tag.s) {
			LM_DBG("dialog callback: _params->msg->to->parsed->tag_value "
				"= %.*s\n", tag.len, tag.s);
		}
	}

	switch (type) {
	case DLGCB_FAILED:
		LM_DBG("dialog callback type 'DLGCB_FAILED' received, from=%.*s\n",
			dlg->from_uri.len, dlg->from_uri.s);
		break;
	case DLGCB_CONFIRMED:
		LM_DBG("dialog callback type 'DLGCB_CONFIRMED' received, from=%.*s\n",
			dlg->from_uri.len, dlg->from_uri.s);
		break;
	case DLGCB_REQ_WITHIN:
		LM_DBG("dialog callback type 'DLGCB_REQ_WITHIN' received, from=%.*s\n",
			dlg->from_uri.len, dlg->from_uri.s);
		break;
	case DLGCB_TERMINATED:
		LM_DBG("dialog callback type 'DLGCB_TERMINATED' received, from=%.*s\n",
			dlg->from_uri.len, dlg->from_uri.s);
		break;
	case DLGCB_EXPIRED:
		LM_DBG("dialog callback type 'DLGCB_EXPIRED' received, from=%.*s\n",
			dlg->from_uri.len, dlg->from_uri.s);
		break;
	case DLGCB_EARLY:
		LM_DBG("dialog callback type 'DLGCB_EARLY' received, from=%.*s\n",
			dlg->from_uri.len, dlg->from_uri.s);
		break;
	case DLGCB_RESPONSE_FWDED:
		LM_DBG("dialog callback type 'DLGCB_RESPONSE_FWDED' received, "
			"from=%.*s\n", dlg->from_uri.len, dlg->from_uri.s);
		break;
	case DLGCB_RESPONSE_WITHIN:
		LM_DBG("dialog callback type 'DLGCB_RESPONSE_WITHIN' received, "
			"from=%.*s\n", dlg->from_uri.len, dlg->from_uri.s);
		break;
	case DLGCB_MI_CONTEXT:
		LM_DBG("dialog callback type 'DLGCB_MI_CONTEXT' received, from=%.*s\n",
			dlg->from_uri.len, dlg->from_uri.s);
		break;
	case DLGCB_DESTROY:
		LM_DBG("dialog callback type 'DLGCB_DESTROY' received, from=%.*s\n",
			dlg->from_uri.len, dlg->from_uri.s);
		break;
	default:
		LM_DBG("dialog callback type 'unknown' received, from=%.*s\n",
			dlg->from_uri.len, dlg->from_uri.s);
	}
}
#endif

static int
is_rendering(struct sip_msg *msg)
{
	int sdp_session_num = 0, sdp_stream_num;
	sdp_session_cell_t* sdp_session;
	sdp_stream_cell_t* sdp_stream;

	if (0 == parse_sdp(msg)) {
		for(;;) {
			sdp_session = get_sdp_session(msg, sdp_session_num);
			if(!sdp_session) break;
			sdp_stream_num = 0;
			for(;;) {
				sdp_stream = get_sdp_stream(msg, sdp_session_num, sdp_stream_num);
				if(!sdp_stream) break;
				if(sdp_stream->media.len==AUDIO_STR_LEN &&
					strncmp(sdp_stream->media.s,AUDIO_STR,AUDIO_STR_LEN)==0) {
					if(sdp_stream->is_on_hold)
						return 0;
					else
						return 1;
				}
				sdp_stream_num++;
			}
			sdp_session_num++;
		}
	}
	return -1;
}

static void
__dialog_sendpublish(struct dlg_cell *dlg, int type, struct dlg_cb_params *_params)
{
	str ttag = {0,0}, ftag = {0,0};
	struct to_body from, from_a, from_b;
	struct to_body gfrom, gfrom_a, gfrom_b;
	str peer_uri= {0, 0}, peer_a_uri= {0, 0}, peer_b_uri= {0, 0};
	str gpeer_uri= {0, 0}, gpeer_a_uri= {0, 0}, gpeer_b_uri= {0, 0};
	char flag = DLG_PUB_AB;
	str flag_str;
	struct to_body peer_a_to_body, peer_b_to_body;
	struct to_body gpeer_a_to_body, gpeer_b_to_body;
	str entity_uri= {0, 0}, entity_a_uri= {0, 0}, entity_b_uri= {0, 0};
	str gentity_uri= {0, 0}, gentity_a_uri= {0, 0}, gentity_b_uri= {0, 0};
	int buf_len = 255;
	struct sip_msg* msg = _params->msg;
	int local_rendering = -1;
	int remote_rendering = -1;
	str *to_tag =NULL, *from_tag = NULL;

	str setup_ts = {0,0};
	str connect_ts = {0,0};
	str release_ts = {0,0};
	str replace = {0,0};
	str icid = {0,0};

	flag_str.s = &flag;
	flag_str.len = 1;

	pua_avp_info *extra_info = (pua_avp_info*)*_params->param;

	memset(&from, 0, sizeof(struct to_body));
	memset(&from_a, 0, sizeof(struct to_body));
	memset(&from_b, 0, sizeof(struct to_body));
	memset(&gfrom, 0, sizeof(struct to_body));
	memset(&gfrom_a, 0, sizeof(struct to_body));
	memset(&gfrom_b, 0, sizeof(struct to_body));

	/* try to extract the flag */
	dlg_api.fetch_dlg_value(dlg, &flag_dlg_var, &flag_str, 1);
	LM_DBG("flag = %c\n", flag);

	if(flag == DLG_PUB_AB || flag == DLG_PUB_A)
	{
		peer_a_uri.len = buf_len;
		peer_a_uri.s = (char*)pkg_malloc(buf_len);
		gpeer_a_uri.len = buf_len;
		gpeer_a_uri.s = (char*)pkg_malloc(buf_len);
		if(peer_a_uri.s == NULL || gpeer_a_uri.s == NULL)
		{
			LM_ERR("No more memory\n");
			goto error;
		}
		/* extract the peer_a_uri */
		if(dlg_api.fetch_dlg_value(dlg, &peer_a_dlg_var, &peer_a_uri, 1) <0)
		{
			peer_a_uri.len = 0;
		}
		if(dlg_api.fetch_dlg_value(dlg, &gpeer_a_dlg_var, &gpeer_a_uri, 1) <0)
		{
			gpeer_a_uri.len = 0;
		}

		if(peer_a_uri.len)
		{
			LM_DBG("peer_a_uri = %.*s\n", peer_a_uri.len, peer_a_uri.s);
		}
	}

	if(flag == DLG_PUB_AB || flag == DLG_PUB_B)
	{
		peer_b_uri.len = buf_len;
		peer_b_uri.s = (char*)pkg_malloc(buf_len);
		gpeer_b_uri.len = buf_len;
		gpeer_b_uri.s = (char*)pkg_malloc(buf_len);
		if(peer_b_uri.s == NULL || gpeer_b_uri.s == NULL)
		{
			LM_ERR("No more memory\n");
			goto error;
		}
		/* extract the peer_b_uri */
		if(dlg_api.fetch_dlg_value(dlg, &peer_b_dlg_var, &peer_b_uri, 1) <0)
		{
			peer_b_uri.len = 0;
		}
		if(dlg_api.fetch_dlg_value(dlg, &gpeer_b_dlg_var, &gpeer_b_uri, 1) <0)
		{
			gpeer_b_uri.len = 0;
		}

		if(peer_b_uri.len)
		{
			LM_DBG("peer_b_uri = %.*s\n", peer_b_uri.len, peer_b_uri.s);
		}
	}


	if( ( (flag == DLG_PUB_AB || flag == DLG_PUB_A) && peer_a_uri.len == 0 ) ||
	    ( (flag == DLG_PUB_AB || flag == DLG_PUB_B) && peer_b_uri.len == 0 ))
	{
		peer_uri.len = buf_len;
		peer_uri.s = (char*)pkg_malloc(buf_len);
		gpeer_uri.len = buf_len;
		gpeer_uri.s = (char*)pkg_malloc(buf_len);
		if(peer_uri.s == NULL || gpeer_uri.s == NULL)
		{
			LM_ERR("No more memory\n");
			goto error;
		}
		/* extract the peer_uri */
		if(dlg_api.fetch_dlg_value(dlg, &peer_dlg_var, &peer_uri, 1) < 0 || peer_uri.len==0)
		{
			LM_ERR("Failed to fetch peer uri dialog variable\n");
			goto error;
		}
		if(dlg_api.fetch_dlg_value(dlg, &gpeer_dlg_var, &gpeer_uri, 1) < 0)
		{
			gpeer_uri.len = 0;
		}


		LM_DBG("peer_uri = %.*s\n", peer_uri.len, peer_uri.s);

		if( (flag == DLG_PUB_AB || flag == DLG_PUB_A) && peer_a_uri.len == 0 )
		{
			memcpy(peer_a_uri.s, peer_uri.s, peer_uri.len);
			peer_a_uri.len = peer_uri.len;
		}

		if( (flag == DLG_PUB_AB || flag == DLG_PUB_B) && peer_b_uri.len == 0 )
		{
			memcpy(peer_b_uri.s, peer_uri.s, peer_uri.len);
			peer_b_uri.len = peer_uri.len;
		}

		if( (flag == DLG_PUB_AB || flag == DLG_PUB_A) && gpeer_a_uri.len == 0 && gpeer_uri.len != 0)
		{
			memcpy(gpeer_a_uri.s, gpeer_uri.s, gpeer_uri.len);
			gpeer_a_uri.len = gpeer_uri.len;
		}

		if( (flag == DLG_PUB_AB || flag == DLG_PUB_B) && peer_b_uri.len == 0 && gpeer_uri.len != 0)
		{
			memcpy(gpeer_b_uri.s, gpeer_uri.s, gpeer_uri.len);
			gpeer_b_uri.len = gpeer_uri.len;
		}

	}

	dlg_api.fetch_dlg_value(dlg, &setup_dlg_var, &setup_ts, 1);
	dlg_api.fetch_dlg_value(dlg, &connect_dlg_var, &connect_ts, 1);
	dlg_api.fetch_dlg_value(dlg, &release_dlg_var, &release_ts, 1);
	dlg_api.fetch_dlg_value(dlg, &replace_dlg_var, &replace, 1);
	dlg_api.fetch_dlg_value(dlg, &icid_dlg_var, &icid, 1);

	if( flag == DLG_PUB_AB || flag == DLG_PUB_A)
	{
		parse_to(peer_a_uri.s, peer_a_uri.s+peer_a_uri.len, &peer_a_to_body);
		if(peer_a_to_body.error != PARSE_OK)
		{
			LM_ERR("Failed to peer A uri [%.*s]\n", peer_a_uri.len, peer_a_uri.s);
			goto error;
		}
		if(gpeer_a_uri.len != 0)
		{
			parse_to(gpeer_a_uri.s, gpeer_a_uri.s+gpeer_a_uri.len, &gpeer_a_to_body);
			if(gpeer_a_to_body.error != PARSE_OK)
			{
				LM_ERR("Failed to gpeer A uri [%.*s]\n", gpeer_a_uri.len, gpeer_a_uri.s);
				goto error;
			}
		} else
		{
			gpeer_a_to_body.uri.len = 0;
		}
	}

	if( flag == DLG_PUB_AB || flag == DLG_PUB_B)
	{
		parse_to(peer_b_uri.s, peer_b_uri.s+peer_b_uri.len, &peer_b_to_body);
		if(peer_b_to_body.error != PARSE_OK)
		{
			LM_ERR("Failed to peer B uri [%.*s]\n", peer_b_uri.len, peer_b_uri.s);
			goto error;
		}
		if(gpeer_b_uri.len != 0)
		{
			parse_to(gpeer_b_uri.s, gpeer_b_uri.s+gpeer_b_uri.len, &gpeer_b_to_body);
			if(gpeer_b_to_body.error != PARSE_OK)
			{
				LM_ERR("Failed to gpeer B uri [%.*s]\n", gpeer_b_uri.len, gpeer_b_uri.s);
				goto error;
			}
		} else
		{
			gpeer_b_to_body.uri.len = 0;
		}

	}

	/* check if entity A is also custom */
	if(flag == DLG_PUB_AB || flag == DLG_PUB_A)
	{
		entity_a_uri.len = buf_len;
		entity_a_uri.s = (char*)pkg_malloc(buf_len);
		gentity_a_uri.len = buf_len;
		gentity_a_uri.s = (char*)pkg_malloc(buf_len);
		if(entity_a_uri.s == NULL || gentity_a_uri.s == NULL )
		{
			LM_ERR("No more memory\n");
			goto error;
		}

		if(dlg_api.fetch_dlg_value(dlg, &entity_a_dlg_var, &entity_a_uri, 1) == 0)
		{
			/* overwrite from with this value */
			parse_to(entity_a_uri.s, entity_a_uri.s + entity_a_uri.len, &from_a);
			if(from_a.error != PARSE_OK)
			{
				LM_ERR("Wrong format for entity body\n");
				goto error;
			}
			LM_DBG("entity_a_uri = %.*s\n", entity_a_uri.len, entity_a_uri.s);
			LM_DBG("from a uri = %.*s\n", from_a.uri.len, from_a.uri.s);
		}
		if(dlg_api.fetch_dlg_value(dlg, &gentity_a_dlg_var, &gentity_a_uri, 1) == 0)
		{
			/* overwrite from with this value */
			parse_to(gentity_a_uri.s, gentity_a_uri.s + gentity_a_uri.len, &gfrom_a);
			if(gfrom_a.error != PARSE_OK)
			{
				LM_ERR("Wrong format for entity body\n");
				goto error;
			}
			LM_DBG("gentity_a_uri = %.*s\n", gentity_a_uri.len, gentity_a_uri.s);
			LM_DBG("gfrom a uri = %.*s\n", gfrom_a.uri.len, gfrom_a.uri.s);
		}

	}

	/* check if entity B is also custom */
	if(flag == DLG_PUB_AB || flag == DLG_PUB_B)
	{
		entity_b_uri.len = buf_len;
		entity_b_uri.s = (char*)pkg_malloc(buf_len);
		gentity_b_uri.len = buf_len;
		gentity_b_uri.s = (char*)pkg_malloc(buf_len);
		if(entity_b_uri.s == NULL || gentity_b_uri.s == NULL)
		{
			LM_ERR("No more memory\n");
			goto error;
		}

		if(dlg_api.fetch_dlg_value(dlg, &entity_b_dlg_var, &entity_b_uri, 1) == 0)
		{
			/* overwrite from with this value */
			parse_to(entity_b_uri.s, entity_b_uri.s + entity_b_uri.len, &from_b);
			if(from_b.error != PARSE_OK)
			{
				LM_ERR("Wrong format for entity body\n");
				goto error;
			}
			LM_DBG("entity_b_uri = %.*s\n", entity_b_uri.len, entity_b_uri.s);
			LM_DBG("from b uri = %.*s\n", from_b.uri.len, from_b.uri.s);
		}
		if(dlg_api.fetch_dlg_value(dlg, &gentity_b_dlg_var, &gentity_b_uri, 1) == 0)
		{
			/* overwrite from with this value */
			parse_to(gentity_b_uri.s, gentity_b_uri.s + gentity_b_uri.len, &gfrom_b);
			if(gfrom_b.error != PARSE_OK)
			{
				LM_ERR("Wrong format for entity body\n");
				goto error;
			}
			LM_DBG("gentity_b_uri = %.*s\n", gentity_b_uri.len, gentity_b_uri.s);
			LM_DBG("gfrom b uri = %.*s\n", gfrom_b.uri.len, gfrom_b.uri.s);
		}

	}

	if( ( (flag == DLG_PUB_AB || flag == DLG_PUB_A) && from_a.uri.len == 0 ) ||
	    ( (flag == DLG_PUB_AB || flag == DLG_PUB_B) && from_b.uri.len == 0 ))
	{
		from.uri = dlg->from_uri;
		entity_uri.len = buf_len;
		entity_uri.s = (char*)pkg_malloc(buf_len);
		if(entity_uri.s == NULL)
		{
			LM_ERR("No more memory\n");
			goto error;
		}

		/* check if entity is also custom */
		if(dlg_api.fetch_dlg_value(dlg, &entity_dlg_var, &entity_uri, 1) == 0)
		{
			/* overwrite from with this value */
			parse_to(entity_uri.s, entity_uri.s + entity_uri.len, &from);
			if(from.error != PARSE_OK)
			{
				LM_ERR("Wrong format for entity body\n");
				goto error;
			}
			LM_DBG("entity_uri = %.*s\n", entity_uri.len, entity_uri.s);
			LM_DBG("from uri = %.*s\n", from.uri.len, from.uri.s);
		}

		if( (flag == DLG_PUB_AB || flag == DLG_PUB_A) && from_a.uri.len == 0 )
		{
			from_a.uri = from.uri;
		}

		if( (flag == DLG_PUB_AB || flag == DLG_PUB_B) && from_b.uri.len == 0 )
		{
			from_b.uri = from.uri;
		}
	
	}

	if( ( (flag == DLG_PUB_AB || flag == DLG_PUB_A) && gfrom_a.uri.len == 0 ) ||
	    ( (flag == DLG_PUB_AB || flag == DLG_PUB_B) && gfrom_b.uri.len == 0 ))
	{
		gfrom.uri.len = 0;
		gentity_uri.len = buf_len;
		gentity_uri.s = (char*)pkg_malloc(buf_len);
		if(gentity_uri.s == NULL)
		{
			LM_ERR("No more memory\n");
			goto error;
		}


		/* check if entity is also custom */
		if(dlg_api.fetch_dlg_value(dlg, &gentity_dlg_var, &gentity_uri, 1) == 0)
		{
			/* overwrite from with this value */
			parse_to(gentity_uri.s, gentity_uri.s + gentity_uri.len, &gfrom);
			if(gfrom.error != PARSE_OK)
			{
				LM_ERR("Wrong format for entity body\n");
				goto error;
			}
			LM_DBG("gentity_uri = %.*s\n", gentity_uri.len, gentity_uri.s);
			LM_DBG("gfrom uri = %.*s\n", gfrom.uri.len, gfrom.uri.s);
		}

		if( (flag == DLG_PUB_AB || flag == DLG_PUB_A) && gfrom_a.uri.len == 0 )
		{
			gfrom_a.uri = gfrom.uri;
		}

		if( (flag == DLG_PUB_AB || flag == DLG_PUB_B) && gfrom_b.uri.len == 0 )
		{
			gfrom_b.uri = gfrom.uri;
		}
	
	}


	if (include_tags) {
		/* caller tag */
		from_tag = &(dlg->legs[DLG_CALLER_LEG].tag);
		/* get to tag*/
		if ( (!_params->msg || _params->msg == FAKED_REPLY) || (!_params->msg->to && (parse_headers(_params->msg, HDR_TO_F,0)<0)) || !_params->msg->to)  {
			ttag.s = 0;
			ttag.len = 0;
		} else {
			ttag = get_to(_params->msg)->tag_value;
			if (ttag.s==0 || ttag.len==0) {
				ttag.s = 0;
				ttag.len = 0;
			}
		}

		/* get from tag*/
		if ( (!_params->msg || _params->msg == FAKED_REPLY) || (parse_from_header(_params->msg) <0)) {
			LM_ERR("missing From hdr :-/\n");
			ftag.s = 0;
			ftag.len = 0;
		} else {
			ftag = get_from(_params->msg)->tag_value;
			if (ftag.s==0 || ftag.len==0) {
				LM_ERR("missing TAG param in From hdr :-/\n");
				ftag.s = 0;
				ftag.len = 0;
			}
		}

		/* Identity callee tag */
		if(ftag.len != 0 && (ftag.len != from_tag->len || strncmp(ftag.s, from_tag->s, ftag.len) != 0))
		{
			to_tag = &ftag;
		} else if(ttag.len != 0 && (ttag.len != from_tag->len || strncmp(ttag.s, from_tag->s, ttag.len) != 0))
		{
			to_tag = &ttag;
		}

		LM_DBG("FROMTAG: %s, TOTAG: %s\n", (from_tag ? from_tag->s : "null" )  , (to_tag ? to_tag->s : "null" ) ); 
	}

	LM_DBG("dialog lifetime : %d\n", dlg->lifetime);

	switch (type) {
	case DLGCB_FAILED:
	case DLGCB_TERMINATED:
	case DLGCB_EXPIRED:
		LM_DBG("dialog over, from=%.*s\n", dlg->from_uri.len, dlg->from_uri.s);
		if(flag == DLG_PUB_AB || flag == DLG_PUB_A)
		{
			dialog_publish("terminated", &from_a, &from_a, &peer_a_to_body, &(dlg->callid), 1, 0, from_tag, to_tag, -1, -1, &setup_ts, &connect_ts, &release_ts, &replace, &icid, extra_info);
			if(gfrom_a.uri.len != 0)
				dialog_publish("terminated", &gfrom_a, &gfrom_a, &peer_a_to_body, &(dlg->callid), 1, 0, from_tag, to_tag, -1, -1, &setup_ts, &connect_ts, &release_ts, &replace, &icid, extra_info);
		}
		if(flag == DLG_PUB_AB || flag == DLG_PUB_B)
		{
			dialog_publish("terminated", &peer_b_to_body, &peer_b_to_body, &from_b, &(dlg->callid), 0, 0, to_tag, from_tag, -1, -1, &setup_ts, &connect_ts, &release_ts, &replace, &icid, extra_info);
			if(gpeer_b_to_body.uri.len != 0)
				dialog_publish("terminated", &gpeer_b_to_body, &gpeer_b_to_body, &from_b, &(dlg->callid), 0, 0, to_tag, from_tag, -1, -1, &setup_ts, &connect_ts, &release_ts, &replace, &icid, extra_info);
		}
 
		break;
	case DLGCB_RESPONSE_WITHIN:
		if (get_cseq(msg)->method_id==METHOD_INVITE) {
			if (msg->flags & nopublish_flag) {
				LM_DBG("nopublish flag was set for this INVITE\n");
				break;
			}
			LM_DBG("nopublish flag not set for this INVITE, will publish\n");
		} else {
			/* no publish for non-INVITEs */
			break;
		}
	case DLGCB_CONFIRMED:
		if (_params->msg && _params->msg != FAKED_REPLY )
		{
			if (_params->direction == DLG_DIR_DOWNSTREAM)
			{
				local_rendering = is_rendering(_params->msg);
			}

			if (_params->direction == DLG_DIR_UPSTREAM)
			{
				remote_rendering = is_rendering(_params->msg);
			}
		}

		LM_DBG("dialog confirmed, from=%.*s\n", dlg->from_uri.len, dlg->from_uri.s);
		if(flag == DLG_PUB_AB || flag == DLG_PUB_A)
		{
			dialog_publish("confirmed", &from_a, &from_a, &peer_a_to_body, &(dlg->callid), 1, dlg->lifetime, from_tag, to_tag, local_rendering, remote_rendering, &setup_ts, &connect_ts, &release_ts, &replace, &icid, extra_info);
			if(gfrom_a.uri.len != 0)
				dialog_publish("confirmed", &gfrom_a, &gfrom_a, &peer_a_to_body, &(dlg->callid), 1, dlg->lifetime, from_tag, to_tag, local_rendering, remote_rendering, &setup_ts, &connect_ts, &release_ts, &replace, &icid, extra_info);
		}
		if(flag == DLG_PUB_AB || flag == DLG_PUB_B)
		{
			dialog_publish("confirmed", &peer_b_to_body, &peer_b_to_body, &from_b, &(dlg->callid), 0, dlg->lifetime, to_tag, from_tag, remote_rendering, local_rendering, &setup_ts, &connect_ts, &release_ts, &replace, &icid, extra_info);
			if(gpeer_b_to_body.uri.len != 0)
				dialog_publish("confirmed", &gpeer_b_to_body, &gpeer_b_to_body, &from_b, &(dlg->callid), 0, dlg->lifetime, to_tag, from_tag, remote_rendering, local_rendering, &setup_ts, &connect_ts, &release_ts, &replace, &icid, extra_info);
		}
		break;
	case DLGCB_EARLY:
		LM_DBG("dialog is early, from_a=%.*s\n", from_a.uri.len, from_a.uri.s);
		LM_DBG("dialog is early, from_b=%.*s\n", from_b.uri.len, from_b.uri.s);
		if(flag == DLG_PUB_AB || flag == DLG_PUB_A)
		{
			if (caller_confirmed) {
				dialog_publish("confirmed", &from_a, &from_a, &peer_a_to_body, &(dlg->callid), 1,
					early_timeout > 0 && early_timeout < dlg->lifetime ? early_timeout : dlg->lifetime, from_tag, to_tag, -1, -1, &setup_ts, &connect_ts, &release_ts, &replace, &icid, extra_info);
			} else {
				dialog_publish("early", &from_a, &from_a, &peer_a_to_body, &(dlg->callid), 1,
					early_timeout > 0 && early_timeout < dlg->lifetime ? early_timeout : dlg->lifetime, from_tag, to_tag, -1, -1, &setup_ts, &connect_ts, &release_ts, &replace, &icid, extra_info);
			}
			if(gfrom_a.uri.len != 0)
				dialog_publish("early", &gfrom_a, &gfrom_a, &peer_a_to_body, &(dlg->callid), 1,
					early_timeout > 0 && early_timeout < dlg->lifetime ? early_timeout : dlg->lifetime, from_tag, to_tag, -1, -1, &setup_ts, &connect_ts, &release_ts, &replace, &icid, extra_info);
		}

		if(flag == DLG_PUB_AB || flag == DLG_PUB_B)
		{
			dialog_publish("early", &peer_b_to_body, &peer_b_to_body, &from_b, &(dlg->callid), 0,
				early_timeout > 0 && early_timeout < dlg->lifetime ? early_timeout : dlg->lifetime, to_tag, from_tag, -1, -1, &setup_ts, &connect_ts, &release_ts, &replace, &icid, extra_info);
			if(gpeer_b_to_body.uri.len != 0)
				dialog_publish("early", &gpeer_b_to_body, &gpeer_b_to_body, &from_b, &(dlg->callid), 0,
					early_timeout > 0 && early_timeout < dlg->lifetime ? early_timeout : dlg->lifetime, to_tag, from_tag, -1, -1, &setup_ts, &connect_ts, &release_ts, &replace, &icid, extra_info);
		}
		break;
	default:
		LM_ERR("unhandled dialog callback type %d received, from=%.*s\n", type, dlg->from_uri.len, dlg->from_uri.s);
		if(flag == DLG_PUB_AB || flag == DLG_PUB_A)
		{
			dialog_publish("terminated", &from_a, &from_a, &peer_a_to_body, &(dlg->callid), 1, 0, from_tag, to_tag, -1, -1, &setup_ts, &connect_ts, &release_ts, &replace, &icid, extra_info);
			if(gfrom_a.uri.len != 0)
				dialog_publish("terminated", &gfrom_a, &gfrom_a, &peer_a_to_body, &(dlg->callid), 1, 0, from_tag, to_tag, -1, -1, &setup_ts, &connect_ts, &release_ts, &replace, &icid, extra_info);
		}
		if(flag == DLG_PUB_AB || flag == DLG_PUB_B)
		{
			dialog_publish("terminated", &peer_b_to_body, &peer_b_to_body, &from_b, &(dlg->callid), 0, 0, to_tag, from_tag, -1, -1, &setup_ts, &connect_ts, &release_ts, &replace, &icid, extra_info);
			if(gpeer_b_to_body.uri.len != 0)
				dialog_publish("terminated", &gpeer_b_to_body, &gpeer_b_to_body, &from_b, &(dlg->callid), 0, 0, to_tag, from_tag, -1, -1, &setup_ts, &connect_ts, &release_ts, &replace, &icid, extra_info);
		}
	}
error:
	if(peer_uri.s)
		pkg_free(peer_uri.s);
	if(peer_a_uri.s)
		pkg_free(peer_a_uri.s);
	if(peer_b_uri.s)
		pkg_free(peer_b_uri.s);
	if(entity_uri.s)
		pkg_free(entity_uri.s);
	if(entity_a_uri.s)
		pkg_free(entity_a_uri.s);
	if(entity_b_uri.s)
		pkg_free(entity_b_uri.s);
	if (from.param_lst)
		free_to_params(&from);
	if (from_a.param_lst)
		free_to_params(&from_a);
	if (from_b.param_lst)
		free_to_params(&from_b);
	if (gfrom.param_lst)
		free_to_params(&gfrom);
	if (gfrom_a.param_lst)
		free_to_params(&gfrom_a);
	if (gfrom_b.param_lst)
		free_to_params(&gfrom_b);
	if(gpeer_uri.s)
		pkg_free(gpeer_uri.s);
	if(gpeer_a_uri.s)
		pkg_free(gpeer_a_uri.s);
	if(gpeer_b_uri.s)
		pkg_free(gpeer_b_uri.s);
	if(gentity_uri.s)
		pkg_free(gentity_uri.s);
	if(gentity_a_uri.s)
		pkg_free(gentity_a_uri.s);
	if(gentity_b_uri.s)
		pkg_free(gentity_b_uri.s);
 
}


static void
__dialog_loaded(struct dlg_cell *dlg, int type, struct dlg_cb_params *_params)
{
	str peer_uri= {0, 0};
	if(dlg_api.fetch_dlg_value(dlg, &peer_dlg_var, &peer_uri, 1)==0 && peer_uri.len!=0) {
		/* register dialog callbacks which triggers sending PUBLISH */
		if (dlg_api.register_dlgcb(dlg,
			DLGCB_FAILED| DLGCB_CONFIRMED | DLGCB_TERMINATED | DLGCB_EXPIRED |
			DLGCB_RESPONSE_WITHIN | DLGCB_EARLY,
			__dialog_sendpublish, 0, 0) != 0) {
			LM_ERR("cannot register callback for interesting dialog types\n");
		}
	}
}


int dialoginfo_process_body(struct publ_info* publ, str** fin_body,
									   int ver, str* tuple)
{
	xmlNodePtr node = NULL;
	xmlDocPtr doc = NULL;
	char* version;
	str* body = NULL;
	int len;

	doc = xmlParseMemory(publ->body->s, publ->body->len);
	if (doc == NULL) {
		LM_ERR("while parsing xml memory\n");
		goto error;
	}
	/* change version */
	node = doc->children;
	if (node == NULL)
	{
		LM_ERR("while extracting dialog-info node\n");
		goto error;
	}
	version = int2str(ver, &len);
	version[len] = '\0';

	if (!xmlNewProp(node, BAD_CAST "version", BAD_CAST version))
	{
		LM_ERR("while setting version attribute\n");
		goto error;
	}
	body = (str*)pkg_malloc(sizeof(str));
	if (body == NULL)
	{
		LM_ERR("NO more memory left\n");
		goto error;
	}
	memset(body, 0, sizeof(str));
	xmlDocDumpMemory(doc, (xmlChar**)(void*)&body->s, &body->len);
	LM_DBG(">>> publish body: >%*s<\n", body->len, body->s);

	xmlFreeDoc(doc);
	*fin_body = body;
	if (*fin_body == NULL)
		LM_DBG("NULL fin_body\n");

	xmlMemoryDump();
	xmlCleanupParser();
	return 1;

	error:
	if (doc)
		xmlFreeDoc(doc);
	if (body)
		pkg_free(body);
	xmlMemoryDump();
	xmlCleanupParser();
	return -1;
}

static int mod_init_spec_param(str *spec_param, pv_spec_t *spec, char *param_name)
{
	if(spec_param->s)
	{
		spec_param->len = strlen(spec_param->s);
		if(pv_parse_spec(spec_param, spec)==NULL)
		{
			LM_ERR("failed to parse %s spec\n", param_name);
			return -2;
		}

		switch(spec->type) {
			case PVT_NONE:
			case PVT_EMPTY:
			case PVT_NULL:
			case PVT_MARKER:
			case PVT_COLOR:
				LM_ERR("invalid %s spec\n", param_name);
				return -3;
			default: ;
		}
	}
	return 0;
}

/**
 * init module function
 */
static int mod_init(void)
{
	bind_pua_t bind_pua;
	evs_process_body_t* evp=0;
	int ret;

	bind_pua= (bind_pua_t)find_export("bind_pua", 1,0);
	if (!bind_pua)
	{
		LM_ERR("Can't bind pua\n");
		return -1;
	}

	if (bind_pua(&pua) < 0)
	{
		LM_ERR("Can't bind pua\n");
		return -1;
	}
	if(pua.send_publish == NULL)
	{
		LM_ERR("Could not import send_publish\n");
		return -1;
	}
	pua_send_publish= pua.send_publish;

	if (nopublish_flag!= -1 && nopublish_flag > MAX_FLAG) {
		LM_ERR("invalid nopublish flag %d!!\n", nopublish_flag);
		return -1;
	}
        nopublish_flag = (nopublish_flag!=-1)?(1<<nopublish_flag):0;

	if(!osips_ps)
		evp = dialoginfo_process_body;

	/* add event in pua module */
	if(pua.add_event(DIALOG_EVENT, "dialog", "application/dialog-info+xml", evp) < 0) {
		LM_ERR("failed to add 'dialog' event to pua module\n");
		return -1;
	}

	/* bind to the dialog API */
	if (load_dlg_api(&dlg_api)!=0) {
		LM_ERR("failed to find dialog API - is dialog module loaded?\n");
		return -1;
	}

        // register dialog loading callback
        if (dlg_api.register_dlgcb(NULL, DLGCB_LOADED, __dialog_loaded, NULL, NULL) != 0) {
                LM_CRIT("cannot register callback for dialogs loaded from the database\n");
        }

	if(presence_server.s)
		presence_server.len = strlen(presence_server.s);

	if( ( ret = mod_init_spec_param(&caller_spec_param, &caller_spec, "caller")) )
	{
		return ret;
	}

	if( (ret = mod_init_spec_param(&callee_spec_param, &callee_spec, "callee")) )
	{
		return ret;
	}

	if( (ret = mod_init_spec_param(&caller_a_spec_param, &caller_a_spec, "caller_a")) )
	{
		return ret;
	}

	if( (ret = mod_init_spec_param(&callee_a_spec_param, &callee_a_spec, "callee_a")) )
	{
		return ret;
	}

	if( (ret = mod_init_spec_param(&caller_b_spec_param, &caller_b_spec, "caller_b")) )
	{
		return ret;
	}

	if( (ret = mod_init_spec_param(&callee_b_spec_param, &callee_b_spec, "callee_b")) )
	{
		return ret;
	}

	if( ( ret = mod_init_spec_param(&gcaller_spec_param, &gcaller_spec, "gcaller")) )
	{
		return ret;
	}

	if( (ret = mod_init_spec_param(&gcallee_spec_param, &gcallee_spec, "gcallee")) )
	{
		return ret;
	}

	if( (ret = mod_init_spec_param(&gcaller_a_spec_param, &gcaller_a_spec, "gcaller_a")) )
	{
		return ret;
	}

	if( (ret = mod_init_spec_param(&gcallee_a_spec_param, &gcallee_a_spec, "gcallee_a")) )
	{
		return ret;
	}

	if( (ret = mod_init_spec_param(&gcaller_b_spec_param, &gcaller_b_spec, "gcaller_b")) )
	{
		return ret;
	}

	if( (ret = mod_init_spec_param(&gcallee_b_spec_param, &gcallee_b_spec, "gcallee_b")) )
	{
		return ret;
	}

	if( (ret = mod_init_avp_param(&extra_info_spec_param, "extra_info")) )
	{
		return ret;
	}

	return 0;
}

static int check_flag(char* flag, int len)
{
	if(len != 1)
		goto error;

	if(flag[0] == DLG_PUB_A || flag[0] == DLG_PUB_B || flag[0] == DLG_PUB_AB)
		return 1;

error:
	LM_ERR("Wrong format for dialoginfo_set() parameter. Accepted values: A, B or D\n");
	return 0;
}

static void free_extra_info( void *p )
{
	pua_avp_free(p);
}

int get_caller_from_spec(struct sip_msg* msg, struct dlg_cell * dlg, pv_spec_t *spec, struct to_body *from, str *dlg_var)
{
	struct to_body FROM;
	pv_value_t tok;
	int len =0;
	int buf_len= 255;
	char caller_buf[256];

	memset(&tok, 0, sizeof(pv_value_t));
	if(pv_get_spec_value(msg, spec, &tok) < 0)  /* if value set */
	{
		LM_ERR("Failed to get caller value\n");
		return -1;
	}
	if(tok.flags&PV_VAL_STR)
	{
		str caller_str;
		if(tok.rs.len + CRLF_LEN > buf_len)
		{
			LM_ERR("Buffer overflow");
			return -1;
		}
		trim(&tok.rs);
		memcpy(caller_buf, tok.rs.s, tok.rs.len);
		len = tok.rs.len;
		if(strncmp(tok.rs.s+len-CRLF_LEN, CRLF, CRLF_LEN))
		{
			memcpy(caller_buf + len, CRLF, CRLF_LEN);
			len+= CRLF_LEN;
		}

		parse_to(caller_buf, caller_buf+len , &FROM);
		if(FROM.error != PARSE_OK)
		{
			LM_ERR("Failed to parse caller specification - not a valid uri\n");
			return -1;
		}
		from = &FROM;
		caller_str.s = caller_buf;
		caller_str.len = len;
		LM_DBG("caller: %*s- len= %d\n", len, caller_buf, len);
		/* store caller in a dlg variable */
		if(dlg_api.store_dlg_value(dlg, dlg_var, &caller_str)< 0)
		{
			LM_ERR("Failed to store dialog ruri\n");
			return -1;
		}
	}

	return 0;
}

int get_callee_from_spec(struct sip_msg* msg, struct dlg_cell * dlg, pv_spec_t *spec, str *peer_uri)
{
	pv_value_t tok;
	int len =0;
	int buf_len= 255;

	memset(&tok, 0, sizeof(pv_value_t));
	if(pv_get_spec_value(msg, spec, &tok) < 0)
	{
		LM_ERR("Failed to get callee value\n");
		return -1;
	}
	if(tok.flags&PV_VAL_STR)
	{
		if(tok.rs.len + CRLF_LEN > buf_len)
		{
			LM_ERR("Buffer overflow");
			return -1;
		}
		trim(&tok.rs);
		memcpy(peer_uri->s, tok.rs.s, tok.rs.len);
		len = tok.rs.len;
		if(strncmp(tok.rs.s+len-CRLF_LEN, CRLF, CRLF_LEN))
		{
			memcpy(peer_uri->s + len, CRLF, CRLF_LEN);
			len+= CRLF_LEN;
		}
		peer_uri->len = len;
	}
	return 0;
}

/*
 *	By default
 *		- caller is taken from the From header
 *		- callee is taken from RURI
 *	If the pseudovariables for caller or callee are defined, those values are used
 * */

int dialoginfo_set(struct sip_msg* msg, char* flag_pv, char* str2)
{
	struct dlg_cell * dlg;
	str peer_uri= {0, 0}; /* constructed from TO display name and RURI */
	str peer_a_uri= {0, 0}; /* constructed from TO display name and RURI */
	str peer_b_uri= {0, 0}; /* constructed from TO display name and RURI */
	str gpeer_uri= {0, 0}; /* constructed from TO display name and RURI */
	str gpeer_a_uri= {0, 0}; /* constructed from TO display name and RURI */
	str gpeer_b_uri= {0, 0}; /* constructed from TO display name and RURI */
	struct to_body* from_a, * from_b, peer_a_to_body, peer_b_to_body, *to;
	struct to_body* gfrom_a, * gfrom_b, gpeer_a_to_body, gpeer_b_to_body;
	str* ruri;
	int len =0;
	char flag= DLG_PUB_AB;
	static char buf[256];
	int buf_len= 255;
	int fbuf_len= 255;
	str flag_str;
	char callee_buf[256];
	char callee_a_buf[256];
	char callee_b_buf[256];
	char gcallee_buf[256];
	char gcallee_a_buf[256];
	char gcallee_b_buf[256];
	str tag, *from_tag;
	str setup_ts = {0,0};
	str connect_ts = {0,0};
	str release_ts = {0,0};
	str replace = {0,0};
	str icid = {0,0};

	if (msg->REQ_METHOD != METHOD_INVITE)
		return 1;

	if(dlg_api.create_dlg(msg,0)< 0)
	{
		LM_ERR("Failed to create dialog\n");
		return -1;
	}

	dlg = dlg_api.get_dlg();

	dlg_api.fetch_dlg_value(dlg, &replace_dlg_var, &replace, 1);

	LM_DBG("new INVITE dialog created: from=%.*s\n",
		dlg->from_uri.len, dlg->from_uri.s);

	/* store flag, if defined  */
	if(flag_pv)
	{
		if(pv_printf(msg, (pv_elem_t*)flag_pv, buf, &fbuf_len)<0)
		{
			LM_ERR("cannot print the format\n");
			return -1;
		}

		if(!check_flag(buf, fbuf_len))
		{
			LM_ERR("Wrong value for flag\n");
			return -1;
		}
		flag = buf[0];
		flag_str.s = buf;
		flag_str.len = fbuf_len;
		if(dlg_api.store_dlg_value(dlg, &flag_dlg_var, &flag_str)< 0)
		{
			LM_ERR("Failed to store dialog ruri\n");
			return -1;
		}
	}

	from_a = from_b = get_from(msg);
	gfrom_a = gfrom_b = NULL;
	/* if defined overwrite */
	if(caller_spec_param.s) /* if parameter defined */
	{
		if(get_caller_from_spec(msg, dlg, &caller_spec, from_a, &entity_dlg_var))
		{
			LM_ERR("Failed to get_caller_from_spec caller_spec\n");
			return -1;
		}
		from_b = from_a;
	}

	if(gcaller_spec_param.s) /* if parameter defined */
	{
		if(get_caller_from_spec(msg, dlg, &gcaller_spec, gfrom_a, &gentity_dlg_var))
		{
			LM_ERR("Failed to get_caller_from_spec gcaller_spec\n");
			return -1;
		}
		gfrom_b = gfrom_a;
	}

	if( (flag == DLG_PUB_A || flag == DLG_PUB_AB) && caller_a_spec_param.s) /* if we publish to A and parameter defined */
	{
		if(get_caller_from_spec(msg, dlg, &caller_a_spec, from_a, &entity_a_dlg_var))
		{
			LM_ERR("Failed to get_caller_from_spec caller_a_spec\n");
			return -1;
		}
	}

	if( (flag == DLG_PUB_A || flag == DLG_PUB_AB) && gcaller_a_spec_param.s) /* if we publish to A and parameter defined */
	{
		if(get_caller_from_spec(msg, dlg, &gcaller_a_spec, gfrom_a, &gentity_a_dlg_var))
		{
			LM_ERR("Failed to get_caller_from_spec gcaller_a_spec\n");
			return -1;
		}
	}

	if( (flag == DLG_PUB_B || flag == DLG_PUB_AB) && caller_b_spec_param.s) /* if we publish to B and parameter defined */
	{
		if(get_caller_from_spec(msg, dlg, &caller_b_spec, from_b, &entity_b_dlg_var))
		{
			LM_ERR("Failed to get_caller_from_spec caller_b_spec\n");
			return -1;
		}
	}

	if( (flag == DLG_PUB_B || flag == DLG_PUB_AB) && gcaller_b_spec_param.s) /* if we publish to B and parameter defined */
	{
		if(get_caller_from_spec(msg, dlg, &gcaller_b_spec, gfrom_b, &gentity_b_dlg_var))
		{
			LM_ERR("Failed to get_caller_from_spec gcaller_b_spec\n");
			return -1;
		}
	}


	if((flag == DLG_PUB_A || flag == DLG_PUB_AB) && callee_a_spec_param.s)
	{
		peer_a_uri.s = callee_a_buf;
		if(get_callee_from_spec(msg, dlg, &callee_a_spec, &peer_a_uri))
		{
			LM_ERR("Failed to get_callee_from_spec callee_a_spec\n");
			return -1;
		}
	}

	if((flag == DLG_PUB_A || flag == DLG_PUB_AB) && gcallee_a_spec_param.s)
	{
		gpeer_a_uri.s = gcallee_a_buf;
		if(get_callee_from_spec(msg, dlg, &gcallee_a_spec, &gpeer_a_uri))
		{
			LM_ERR("Failed to get_callee_from_spec gcallee_a_spec\n");
			return -1;
		}
	}

	if((flag == DLG_PUB_B || flag == DLG_PUB_AB) && callee_b_spec_param.s)
	{
		peer_b_uri.s = callee_b_buf;
		if(get_callee_from_spec(msg, dlg, &callee_b_spec, &peer_b_uri))
		{
			LM_ERR("Failed to get_callee_from_spec callee_b_spec\n");
			return -1;
		}
	}

	if((flag == DLG_PUB_B || flag == DLG_PUB_AB) && gcallee_b_spec_param.s)
	{
		gpeer_b_uri.s = gcallee_b_buf;
		if(get_callee_from_spec(msg, dlg, &gcallee_b_spec, &gpeer_b_uri))
		{
			LM_ERR("Failed to get_callee_from_spec gcallee_b_spec\n");
			return -1;
		}
	}

	pua_avp_info *extra_info = pua_create_pua_avp_info();
	if ( !extra_info )
	{
		LM_ERR("Failed to create pua_avp struct\n");
		return -1;
	}
	pua_get_avp_info(extra_info);
	dlg_api.fetch_dlg_value(dlg, &icid_dlg_var, &icid, 1);

	if( (peer_a_uri.len == 0 && (flag == DLG_PUB_A || flag == DLG_PUB_AB)) || (peer_b_uri.len == 0 && (flag == DLG_PUB_B || flag == DLG_PUB_AB)) )
	{
		peer_uri.s = callee_buf;
		if(callee_spec_param.s)
		{
			if(get_callee_from_spec(msg, dlg, &callee_spec, &peer_uri))
			{
				LM_ERR("Failed to get_callee_from_spec callee_spec\n");
				return -1;
			}
		}

		if(peer_uri.len == 0)
		{
			ruri = GET_RURI(msg);
			LM_ERR("ruri = %.*s\n", ruri->len, ruri->s);
			to = get_to(msg);
			len= to->display.len + 2 + ruri->len + CRLF_LEN;
			if(len > buf_len)
			{
				LM_ERR("Buffer overflow %d > %d\n", len, buf_len);
				return -1;
			}
			len = 0;
			if(to->display.len && to->display.s)
			{
				memcpy(peer_uri.s, to->display.s, to->display.len);
				peer_uri.s[to->display.len]='<';
				len = to->display.len + 1;
			}
			memcpy(peer_uri.s + len, ruri->s, ruri->len);
			len+= ruri->len;
			if(to->display.len)
			{
				peer_uri.s[len++]='>';
				peer_uri.s[len++]='>';
				memcpy(peer_uri.s + len, CRLF, CRLF_LEN);
				len+= CRLF_LEN;
			}
			peer_uri.len = len;
			LM_DBG("Peer uri = %.*s\n", peer_uri.len, peer_uri.s);
		}

		/* store peer uri in dialog structure */
		if(dlg_api.store_dlg_value(dlg, &peer_dlg_var, &peer_uri)< 0)
		{
			LM_ERR("Failed to store dialog ruri\n");
			return -1;
		}
	}

	if( (gpeer_a_uri.len == 0 && (flag == DLG_PUB_A || flag == DLG_PUB_AB)) || (gpeer_b_uri.len == 0 && (flag == DLG_PUB_B || flag == DLG_PUB_AB)) )
	{
		gpeer_uri.s = gcallee_buf;
		if(gcallee_spec_param.s)
		{
			if(get_callee_from_spec(msg, dlg, &gcallee_spec, &gpeer_uri))
			{
				return -1;
			}
		}

		/* store peer uri in dialog structure */
		if(dlg_api.store_dlg_value(dlg, &gpeer_dlg_var, &gpeer_uri)< 0)
		{
			LM_ERR("Failed to store dialog ruri\n");
			return -1;
		}
	}


	if((flag == DLG_PUB_A || flag == DLG_PUB_AB))
	{
		if(peer_a_uri.len == 0)
		{
			peer_a_uri.s = peer_uri.s;
			peer_a_uri.len = peer_uri.len;
		} else
		{
			/* store peer uri in dialog structure */
			if(dlg_api.store_dlg_value(dlg, &peer_a_dlg_var, &peer_a_uri)< 0)
			{
				LM_ERR("Failed to store dialog ruri\n");
				return -1;
			}
		}
		parse_to(peer_a_uri.s, peer_a_uri.s+peer_a_uri.len, &peer_a_to_body);
		if(peer_a_to_body.error != PARSE_OK)
		{
			LM_ERR("Failed to peer A uri [%.*s] / [%.*s]\n", peer_a_uri.len, peer_a_uri.s, peer_uri.len, peer_uri.s);
			return -1;
		}
	}

	if((flag == DLG_PUB_A || flag == DLG_PUB_AB))
	{
		if(gpeer_a_uri.len == 0)
		{
			gpeer_a_uri.s = gpeer_uri.s;
			gpeer_a_uri.len = gpeer_uri.len;

		} else
		{
			/* store peer uri in dialog structure */
			if(dlg_api.store_dlg_value(dlg, &gpeer_a_dlg_var, &gpeer_a_uri)< 0)
			{
				LM_ERR("Failed to store dialog ruri\n");
				return -1;
			}
		}

		if(gpeer_a_uri.len != 0)
		{
			parse_to(gpeer_a_uri.s, gpeer_a_uri.s+gpeer_a_uri.len, &gpeer_a_to_body);
			if(gpeer_a_to_body.error != PARSE_OK)
			{
				LM_ERR("Failed to gpeer A uri [%.*s] / [%.*s]\n", gpeer_a_uri.len, gpeer_a_uri.s, gpeer_uri.len, gpeer_uri.s);
				return -1;
			}
		}
	}

	if((flag == DLG_PUB_B || flag == DLG_PUB_AB))
	{
		if(peer_b_uri.len == 0)
		{
			peer_b_uri.s = peer_uri.s;
			peer_b_uri.len = peer_uri.len;

		} else
		{
			/* store peer uri in dialog structure */
			if(dlg_api.store_dlg_value(dlg, &peer_b_dlg_var, &peer_b_uri)< 0)
			{
				LM_ERR("Failed to store dialog ruri\n");
				return -1;
			}
		}

		parse_to(peer_b_uri.s, peer_b_uri.s+peer_b_uri.len, &peer_b_to_body);
		if(peer_b_to_body.error != PARSE_OK)
		{
			LM_ERR("Failed to peer B uri [%.*s] / [%.*s]\n", peer_b_uri.len, peer_b_uri.s, peer_uri.len, peer_uri.s);
			return -1;
		}
	}

	if((flag == DLG_PUB_B || flag == DLG_PUB_AB))
	{
		if(gpeer_b_uri.len == 0)
		{
			gpeer_b_uri.s = gpeer_uri.s;
			gpeer_b_uri.len = gpeer_uri.len;

		} else
		{
			/* store peer uri in dialog structure */
			if(dlg_api.store_dlg_value(dlg, &gpeer_b_dlg_var, &gpeer_b_uri)< 0)
			{
				LM_ERR("Failed to store dialog ruri\n");
				return -1;
			}
		}

		if(gpeer_b_uri.len != 0)
		{
			parse_to(gpeer_b_uri.s, gpeer_b_uri.s+gpeer_b_uri.len, &gpeer_b_to_body);
			if(gpeer_b_to_body.error != PARSE_OK)
			{
				LM_ERR("Failed to gpeer B uri [%.*s] / [%.*s]\n", gpeer_b_uri.len, gpeer_b_uri.s, gpeer_uri.len, gpeer_uri.s);
				return -1;
			}
		}
	}


	/* register dialog callbacks which triggers sending PUBLISH */
	if (dlg_api.register_dlgcb(dlg,
		DLGCB_FAILED| DLGCB_CONFIRMED | DLGCB_TERMINATED | DLGCB_EXPIRED |
		DLGCB_RESPONSE_WITHIN | DLGCB_EARLY,
		__dialog_sendpublish, extra_info, free_extra_info) != 0) {
		LM_ERR("cannot register callback for interesting dialog types\n");
		return -1;
	}

#ifdef PUA_DIALOGINFO_DEBUG
	/* dialog callback testing (registered last to be executed first) */
	if (dlg_api.register_dlgcb(dlg,
		DLGCB_FAILED| DLGCB_CONFIRMED | DLGCB_REQ_WITHIN | DLGCB_TERMINATED |
		DLGCB_EXPIRED | DLGCB_EARLY | DLGCB_RESPONSE_FWDED |
		DLGCB_RESPONSE_WITHIN  | DLGCB_MI_CONTEXT | DLGCB_DESTROY,
		__dialog_cbtest, NULL, NULL) != 0) {
		LM_ERR("cannot register callback for all dialog types\n");
		return -1;
	}
#endif
	if (include_tags) {
		/* get from tag*/
		if ( !msg->from && ((parse_headers(msg, HDR_FROM_F,0)<0) || !msg->from) ) {
			LM_ERR("missing From hdr :-/\n");
			tag.s = 0;
			tag.len = 0;
		} else {
			tag = get_from(msg)->tag_value;
			if (tag.s==0 || tag.len==0) {
				LM_ERR("missing TAG param in From hdr :-/\n");
				tag.s = 0;
				tag.len = 0;
			} else {
				from_tag =&tag;
			}
		}
	}

        if(publish_on_trying) {
	        if(flag == DLG_PUB_A || flag == DLG_PUB_AB)
		{
			dialog_publish("trying", from_a, from_a, &peer_a_to_body, &(dlg->callid), 1, DEFAULT_CREATED_LIFETIME, from_tag, 0, is_rendering(msg), -1, &setup_ts, &connect_ts, &release_ts, &replace, &icid, extra_info);
			if(gfrom_a)
				dialog_publish("trying", gfrom_a, gfrom_a, &peer_a_to_body, &(dlg->callid), 1, DEFAULT_CREATED_LIFETIME, from_tag, 0, is_rendering(msg), -1, &setup_ts, &connect_ts, &release_ts, &replace, &icid, extra_info);
		}

	        if(flag == DLG_PUB_B || flag == DLG_PUB_AB)
		{
			dialog_publish("trying", &peer_b_to_body, &peer_b_to_body, from_b, &(dlg->callid), 0, DEFAULT_CREATED_LIFETIME, 0, from_tag, -1, is_rendering(msg), &setup_ts, &connect_ts, &release_ts, &replace, &icid, extra_info);
			if(gpeer_b_uri.len != 0)
				dialog_publish("trying", &gpeer_b_to_body, &gpeer_b_to_body, from_b, &(dlg->callid), 0, DEFAULT_CREATED_LIFETIME, 0, from_tag, -1, is_rendering(msg), &setup_ts, &connect_ts, &release_ts, &replace, &icid, extra_info);
		}
        }

	return 1;
}

static int fixup_dlginfo(void** param, int param_no)
{
	pv_elem_t *model;
	str s;

	if(param_no== 0)
		return 0;

	if(*param)
	{
		s.s = (char*)(*param); s.len = strlen(s.s);
		if(pv_parse_format(&s, &model)<0)
		{
			LM_ERR( "wrong format[%s]\n",(char*)(*param));
			return E_UNSPEC;
		}

		*param = (void*)model;
		return 0;
	}
	LM_ERR( "null format\n");
	return E_UNSPEC;
}

