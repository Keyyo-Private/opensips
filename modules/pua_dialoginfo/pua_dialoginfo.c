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
static str entity_dlg_var = {"dlg_entity", 10};
static str flag_dlg_var = {"dlginfo_flag", 12};
static str caller_spec_param= {0, 0};
static str callee_spec_param= {0, 0};
static pv_spec_t caller_spec;
static pv_spec_t callee_spec;
static int osips_ps = 1;
static int publish_on_trying = 0;
static int nopublish_flag = -1;


static str setup_dlg_var = {"dlg_setup_time", 14};
static str connect_dlg_var = {"dlg_connect_time", 16};
static str release_dlg_var = {"dlg_release_time", 16};
static str replace_dlg_var = {"dlg_replace", 11};

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
	struct to_body from;
	str peer_uri= {0, 0};
	char flag = DLG_PUB_AB;
	str flag_str;
	struct to_body peer_to_body;
	str entity_uri= {0, 0};
	int buf_len = 255;
	struct sip_msg* msg = _params->msg;
	int local_rendering = -1;
	int remote_rendering = -1;
	str *to_tag =NULL, *from_tag = NULL;

	str setup_ts = {0,0};
	str connect_ts = {0,0};
	str release_ts = {0,0};
	str replace = {0,0};


	flag_str.s = &flag;
	flag_str.len = 1;

	memset(&from, 0, sizeof(struct to_body));
	memset(&peer_to_body, 0, sizeof(struct to_body));

	from.uri = dlg->from_uri;

	peer_uri.len = buf_len;
	peer_uri.s = (char*)pkg_malloc(buf_len);
	if(peer_uri.s == NULL)
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

	LM_DBG("peer_uri = %.*s\n", peer_uri.len, peer_uri.s);

	dlg_api.fetch_dlg_value(dlg, &setup_dlg_var, &setup_ts, 1);
	dlg_api.fetch_dlg_value(dlg, &connect_dlg_var, &connect_ts, 1);
	dlg_api.fetch_dlg_value(dlg, &release_dlg_var, &release_ts, 1);
	dlg_api.fetch_dlg_value(dlg, &replace_dlg_var, &replace, 1);

	parse_to(peer_uri.s, peer_uri.s+peer_uri.len, &peer_to_body);
	if(peer_to_body.error != PARSE_OK)
	{
		LM_ERR("Failed to peer uri [%.*s]\n", peer_uri.len, peer_uri.s);
		goto error;
	}

	/* try to extract the flag */
	dlg_api.fetch_dlg_value(dlg, &flag_dlg_var, &flag_str, 1);
	LM_DBG("flag = %c\n", flag);

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
			dialog_publish("terminated", &from, &peer_to_body, &(dlg->callid), 1, 0, from_tag, to_tag, -1, -1, &setup_ts, &connect_ts, &release_ts, &replace);
		if(flag == DLG_PUB_AB || flag == DLG_PUB_B)
			dialog_publish("terminated", &peer_to_body, &from, &(dlg->callid), 0, 0, to_tag, from_tag, -1, -1, &setup_ts, &connect_ts, &release_ts, &replace);
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
			dialog_publish("confirmed", &from, &peer_to_body, &(dlg->callid), 1, dlg->lifetime, from_tag, to_tag, local_rendering, remote_rendering, &setup_ts, &connect_ts, &release_ts, &replace);
		if(flag == DLG_PUB_AB || flag == DLG_PUB_B)
			dialog_publish("confirmed", &peer_to_body, &from, &(dlg->callid), 0, dlg->lifetime, to_tag, from_tag, remote_rendering, local_rendering, &setup_ts, &connect_ts, &release_ts, &replace);
		break;
	case DLGCB_EARLY:
		LM_DBG("dialog is early, from=%.*s\n", from.uri.len, from.uri.s);
		if(flag == DLG_PUB_AB || flag == DLG_PUB_A)
		{
			if (caller_confirmed) {
				dialog_publish("confirmed", &from, &peer_to_body, &(dlg->callid), 1,
					early_timeout > 0 && early_timeout < dlg->lifetime ? early_timeout : dlg->lifetime, from_tag, to_tag, -1, -1, &setup_ts, &connect_ts, &release_ts, &replace);
			} else {
				dialog_publish("early", &from, &peer_to_body, &(dlg->callid), 1,
					early_timeout > 0 && early_timeout < dlg->lifetime ? early_timeout : dlg->lifetime, from_tag, to_tag, -1, -1, &setup_ts, &connect_ts, &release_ts, &replace);
			}
		}

		if(flag == DLG_PUB_AB || flag == DLG_PUB_B)
		{
			dialog_publish("early", &peer_to_body, &from, &(dlg->callid), 0,
				early_timeout > 0 && early_timeout < dlg->lifetime ? early_timeout : dlg->lifetime, to_tag, from_tag, -1, -1, &setup_ts, &connect_ts, &release_ts, &replace);
		}
		break;
	default:
		LM_ERR("unhandled dialog callback type %d received, from=%.*s\n", type, dlg->from_uri.len, dlg->from_uri.s);
		if(flag == DLG_PUB_AB || flag == DLG_PUB_A)
			dialog_publish("terminated", &from, &peer_to_body, &(dlg->callid), 1, 0, from_tag, to_tag, local_rendering, remote_rendering, &setup_ts, &connect_ts, &release_ts, &replace);
		if(flag == DLG_PUB_AB || flag == DLG_PUB_B)
			dialog_publish("terminated", &peer_to_body, &from, &(dlg->callid), 0, 0, to_tag, from_tag, remote_rendering, local_rendering, &setup_ts, &connect_ts, &release_ts, &replace);
	}
error:
	if(peer_uri.s)
		pkg_free(peer_uri.s);
	if(entity_uri.s)
		pkg_free(entity_uri.s);
	if (peer_to_body.param_lst)
		free_to_params(&peer_to_body);
	if (from.param_lst)
		free_to_params(&from);
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

/**
 * init module function
 */
static int mod_init(void)
{
	bind_pua_t bind_pua;
	evs_process_body_t* evp=0;

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

	if(caller_spec_param.s)
	{
		caller_spec_param.len = strlen(caller_spec_param.s);
		if(pv_parse_spec(&caller_spec_param, &caller_spec)==NULL)
		{
			LM_ERR("failed to parse caller spec\n");
			return -2;
		}
		switch(caller_spec.type) {
			case PVT_NONE:
			case PVT_EMPTY:
			case PVT_NULL:
			case PVT_MARKER:
			case PVT_COLOR:
				LM_ERR("invalid caller spec\n");
				return -3;
			default: ;
		}
	}

	if(callee_spec_param.s)
	{
		callee_spec_param.len = strlen(callee_spec_param.s);
		if(pv_parse_spec(&callee_spec_param, &callee_spec)==NULL)
		{
			LM_ERR("failed to parse callee spec\n");
			return -2;
		}
		switch(callee_spec.type) {
			case PVT_NONE:
			case PVT_EMPTY:
			case PVT_NULL:
			case PVT_MARKER:
			case PVT_COLOR:
				LM_ERR("invalid callee spec\n");
				return -3;
			default: ;
		}
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
	struct to_body* from, peer_to_body, FROM, *to;
	str* ruri;
	int len =0,ret=-1;
	char flag= DLG_PUB_AB;
	static char buf[256];
	int buf_len= 255;
	str flag_str;
	char caller_buf[256], callee_buf[256];
	pv_value_t tok;
	str tag, *from_tag;
	str setup_ts = {0,0};
	str connect_ts = {0,0};
	str release_ts = {0,0};
	str replace = {0,0};

	peer_to_body.param_lst = FROM.param_lst = NULL;

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

	from = get_from(msg);
	/* if defined overwrite */
	if(caller_spec_param.s) /* if parameter defined */
	{
		memset(&tok, 0, sizeof(pv_value_t));
		if(pv_get_spec_value(msg, &caller_spec, &tok) < 0)  /* if value set */
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
				goto end;
			}
			from = &FROM;
			caller_str.s = caller_buf;
			caller_str.len = len;
			LM_DBG("caller: %*s- len= %d\n", len, caller_buf, len);
			/* store caller in a dlg variable */
			if(dlg_api.store_dlg_value(dlg, &entity_dlg_var, &caller_str)< 0)
			{
				LM_ERR("Failed to store dialog ruri\n");
				goto end;
			}
		}
	}

	peer_uri.s = callee_buf;
	if(callee_spec_param.s)
	{
		memset(&tok, 0, sizeof(pv_value_t));
		if(pv_get_spec_value(msg, &callee_spec, &tok) < 0)
		{
			LM_ERR("Failed to get callee value\n");
			goto end;
		}
		if(tok.flags&PV_VAL_STR)
		{
			if(tok.rs.len + CRLF_LEN > buf_len)
			{
				LM_ERR("Buffer overflow");
				goto end;
			}
			trim(&tok.rs);
			memcpy(peer_uri.s, tok.rs.s, tok.rs.len);
			len = tok.rs.len;
			if(strncmp(tok.rs.s+len-CRLF_LEN, CRLF, CRLF_LEN))
			{
				memcpy(peer_uri.s + len, CRLF, CRLF_LEN);
				len+= CRLF_LEN;
			}
			peer_uri.len = len;
		}
		else
			goto default_callee;
	}
	else
	{
default_callee:
		ruri = GET_RURI(msg);
		to = get_to(msg);
		len= to->display.len + 2 + ruri->len + CRLF_LEN;
		if(len > buf_len)
		{
			LM_ERR("Buffer overflow\n");
			goto end;
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
		}
		memcpy(peer_uri.s + len, CRLF, CRLF_LEN);
		len+= CRLF_LEN;
		peer_uri.len = len;
	}
	LM_DBG("Peer uri = %.*s\n", peer_uri.len, peer_uri.s);

	parse_to(peer_uri.s, peer_uri.s+peer_uri.len, &peer_to_body);
	if(peer_to_body.error != PARSE_OK)
	{
		LM_ERR("Failed to peer uri [%.*s]\n", peer_uri.len, peer_uri.s);
		goto end;
	}

	/* store peer uri in dialog structure */
	if(dlg_api.store_dlg_value(dlg, &peer_dlg_var, &peer_uri)< 0)
	{
		LM_ERR("Failed to store dialog ruri\n");
		goto end;
	}

	/* store flag, if defined  */
	if(flag_pv)
	{
		if(pv_printf(msg, (pv_elem_t*)flag_pv, buf, &buf_len)<0)
		{
			LM_ERR("cannot print the format\n");
			goto end;
		}

		if(!check_flag(buf, buf_len))
		{
			LM_ERR("Wrong value for flag\n");
			goto end;
		}
		flag = buf[0];
		flag_str.s = buf;
		flag_str.len = buf_len;
		if(dlg_api.store_dlg_value(dlg, &flag_dlg_var, &flag_str)< 0)
		{
			LM_ERR("Failed to store dialog ruri\n");
			goto end;
		}
	}

	/* register dialog callbacks which triggers sending PUBLISH */
	if (dlg_api.register_dlgcb(dlg,
		DLGCB_FAILED| DLGCB_CONFIRMED | DLGCB_TERMINATED | DLGCB_EXPIRED |
		DLGCB_RESPONSE_WITHIN | DLGCB_EARLY,
		__dialog_sendpublish, 0, 0) != 0) {
		LM_ERR("cannot register callback for interesting dialog types\n");
		goto end;
	}

#ifdef PUA_DIALOGINFO_DEBUG
	/* dialog callback testing (registered last to be executed first) */
	if (dlg_api.register_dlgcb(dlg,
		DLGCB_FAILED| DLGCB_CONFIRMED | DLGCB_REQ_WITHIN | DLGCB_TERMINATED |
		DLGCB_EXPIRED | DLGCB_EARLY | DLGCB_RESPONSE_FWDED |
		DLGCB_RESPONSE_WITHIN  | DLGCB_MI_CONTEXT | DLGCB_DESTROY,
		__dialog_cbtest, NULL, NULL) != 0) {
		LM_ERR("cannot register callback for all dialog types\n");
		goto end;
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
		        dialog_publish("trying", from, &peer_to_body, &(dlg->callid), 1, DEFAULT_CREATED_LIFETIME, from_tag, 0, is_rendering(msg), -1, &setup_ts, &connect_ts, &release_ts, &replace);

	        if(flag == DLG_PUB_B || flag == DLG_PUB_AB)
		        dialog_publish("trying", &peer_to_body, from, &(dlg->callid), 0, DEFAULT_CREATED_LIFETIME, 0, from_tag, -1, is_rendering(msg), &setup_ts, &connect_ts, &release_ts, &replace);
        }

	ret=1;
end:
	if (peer_to_body.param_lst)
		free_to_params(&peer_to_body);
	if (FROM.param_lst)
		free_to_params(&FROM);
	return ret;
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

