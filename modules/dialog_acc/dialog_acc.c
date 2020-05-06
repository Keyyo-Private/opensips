
#include <stdio.h>
#include "dialog_acc.h"
#include "acc_rad.h"
#include "acc_avp.h"
#include "icid.h"
#include "dialog_acc_db_handler.h"

//#include "dialog_acc_mi.h"

#include "../../sr_module.h"
#include "../../mem/shm_mem.h"
#include "../dialog/dlg_load.h"
#include "../../parser/parse_from.h"
#include "../../locking.h"
#include "../../ut.h"

/* function declarations */
static int mod_init( void );
static int child_init( int rank );
static int mod_destroy( void );
static void on_dialog_replies( struct dlg_cell *dlg, int type, struct dlg_cb_params *_params );
static void on_dialog_ended( struct dlg_cell *dlg, int type, struct dlg_cb_params *_params );
static void on_dialog_saved( struct dlg_cell *dlg, int type, struct dlg_cb_params *_params );

/* static variables */ 
struct dlg_binds dlg_api; 

/* module parameter */
static char *radius_config = NULL;
static str db_url = str_init("postgres://opensips:opensipsrw@localhost/opensips");
static int initial_buffer_size = 128;
static int buffer_increment = 64;
static char *ingw_avp_param = "$avp(ingw)";
static char *route_avp_param = "$avp(routes)";
static char *routedesc_avp_param = "$avp(routes_name)";
static char *causes_avp_param = "$avp(failcode)";
static char *accavp_avp_param = "$avp(acc_avp)";
static int dlg_acc_flag = -1;

static str setup_dlg_var = {"dlg_setup_time", 14};
static str connect_dlg_var = {"dlg_connect_time", 16};
static str release_dlg_var = {"dlg_release_time", 16};
static str icid_dlg_var = {"dlg_icid", 8};

static param_export_t mod_params[]={
	{ "radius_config",   STR_PARAM, &radius_config       },
	{ "db_url",          STR_PARAM, &db_url              },
	{ "db_mode",         INT_PARAM, &dlg_acc_db_mode     },
	{ "avp_ingw",        STR_PARAM, &ingw_avp_param      },
	{ "avp_routes",      STR_PARAM, &route_avp_param     },
	{ "avp_route_desc",  STR_PARAM, &routedesc_avp_param },
	{ "avp_causes",      STR_PARAM, &causes_avp_param    },
	{ "avp_accavp",      STR_PARAM, &accavp_avp_param    },
	{ "account_flag",    INT_PARAM, &dlg_acc_flag        },
};

/*
static mi_export_t mi_cmds[] = {
	{ "dlg_acc_list",	mi_dlg_acc_list,       0,  0,  0},
	{ 0, 0, 0, 0, 0}
};
*/

struct module_exports exports = {
	"dialog_acc",						// module name
	MODULE_VERSION,
	DEFAULT_DLFLAGS,					// dlopen flags
	NULL,								// exported functions
	mod_params,							// exported parameters
	NULL,								// exported statistics
//	mi_cmds,							// exported MI functions
	NULL,								// exported MI functions (bis)
	NULL,								// exported pseudo-variables
	NULL,								// extra processes
	mod_init,							// module init function (before fork. kids will inherit)
	NULL,								// reply processing function
	(destroy_function)mod_destroy,		// destroy function
	child_init							// child init function
};

/* Implementation */

/*
 * Calculate diff between two timeval
 */
static void diff_tv( struct timeval start, struct timeval stop, struct timeval *diff )
{
	if ( stop.tv_usec > start.tv_usec )
	{
		diff->tv_sec = stop.tv_sec - start.tv_sec;
		diff->tv_usec = stop.tv_usec - start.tv_usec;
	}
	else
	{
		diff->tv_sec = stop.tv_sec - start.tv_sec - 1;
		diff->tv_usec = stop.tv_usec - start.tv_usec + 1000000;
	}
}

/*
 * Free dlg_acc_info
 */
static void dlg_acc_free( void *p )
{
	dlg_acc_info *infos = (dlg_acc_info*)p;

	shm_free( infos->buffer );
	shm_free( infos );
}

/*
 * Create and initialize a new dialog_acc_info struct
 */
dlg_acc_info *dlg_acc_create_acc_info( void )
{
	dlg_acc_info *infos;

	infos = (dlg_acc_info *)shm_malloc( sizeof(dlg_acc_info) );
	if ( !infos )
	{ 
		LM_ERR("out of shm memory\n" );
		return NULL;
	}
	memset( infos, 0, sizeof(*infos) );

	infos->buffer = (char *)shm_malloc( initial_buffer_size );
	if ( !infos->buffer )
	{ 
		shm_free(infos);
		LM_ERR("out of shm memory\n" );
		return NULL;
	}
	infos->buffer_size = initial_buffer_size;
	
	return infos;
}

/*
 * Set a string in the dialog informations
 * Reallocate memory if needed, and readjust all strings in dialog informations
 */
int dlg_acc_set_str( dlg_acc_info *infos, int index, char *src, int len )
{
	int i;
	int realloc_size;

	if ( !src || !len )
	{
		return 1;
	}

	// Reallocate memory if needed
	if ( infos->buffer_index + len > infos->buffer_size )
	{
		char *old_buffer = infos->buffer;

		realloc_size = buffer_increment;
		while ( infos->buffer_index + len > infos->buffer_size + realloc_size )
		{
			realloc_size += buffer_increment;
		}

		infos->buffer = (char*)shm_realloc( infos->buffer, infos->buffer_size + realloc_size );
		if ( !infos->buffer )
		{
			infos->buffer = old_buffer;
			LM_ERR("out of shm memory\n" );
			return 0;
		}

		infos->buffer_size += realloc_size;
		LM_INFO( "Reallocating %d bytes : %p->%p\n", infos->buffer_size, old_buffer, infos->buffer );
		if ( old_buffer != infos->buffer )
		{
			// Buffer has moved, reassign all strings
			memcpy( infos->buffer, old_buffer, infos->buffer_index );
			for ( i = 0; i < DLG_ACC_STR_MAX; i++ )
			{
				if ( infos->strings[i].s )
				{
					infos->strings[i].s += infos->buffer - old_buffer;
				}
			}
		}
	}

	infos->strings[index].s = infos->buffer + infos->buffer_index;
	infos->strings[index].len = len;
	memcpy( infos->strings[index].s, src, len );
	infos->buffer_index += len;
	return 1;
}


/*
 * Handle save
 */
static void on_dialog_saved(struct dlg_cell *dlg, int type, struct dlg_cb_params *_params)
{
	dlg_acc_info *infos = (dlg_acc_info*)*_params->param;

	if( dlg->state == DLG_STATE_DELETED )
	{
		if( remove_dialog_acc_from_db( dlg ) )
			LM_ERR("Could not remove dialog acc from db\n");
	}
	else
	{
		if( update_dialog_acc_to_db( dlg, infos ) )
			LM_ERR("Could not update dialog to db\n");
	}

	LM_INFO( "SAVED -> HASH_ID=%d | ENTRY_ID=%d | CONNECT=%d\n", dlg->h_id, dlg->h_entry, (int)infos->connect_ts.tv_sec);
}



dlg_acc_info *init_from_sip(struct dlg_cell *dlg, struct dlg_cb_params *_params)
{
	struct sip_msg *request = _params->msg;
	struct sip_uri *uri;
	dlg_acc_info *infos;
	char buf[256];
	str sbuf;

	if (request->REQ_METHOD != METHOD_INVITE)
	{
		LM_ERR("Request is not an INVITE.\n");
		return NULL;
	}

	if ( parse_headers(request, HDR_EOH_F, 0) == -1)
	{
		LM_ERR("failed to parse headers in message.\n");
		return NULL;
	}

	// Create dialog accounting infos
	// Allocation is done in shared memory since data will be used in other
	// transactions, meaning probably in other process
	infos = dlg_acc_create_acc_info();
	if ( !infos )
	{ 
		return NULL;
	}

	// Set setup time
	gettimeofday( &infos->setup_ts, NULL );
	sprintf(buf, "%d",(int) infos->setup_ts.tv_sec);
	sbuf.s = buf;
	sbuf.len = strlen(buf);
	dlg_api.store_dlg_value(dlg, &setup_dlg_var, &sbuf);

	// Set calling/called number
	uri = parse_from_uri( request );
	if ( uri ) 
	{
		dlg_acc_set_str( infos, DLG_ACC_STR_CALLING_ID, uri->user.s, uri->user.len );
		dlg_acc_set_str( infos, DLG_ACC_STR_USERNAME, get_from(request)->display.s, get_from(request)->display.len );
	}

	// Read request-uri, and set first SMC-VOIP-PrevDest-Info
	dlg_acc_set_str( infos, DLG_ACC_STR_REQUEST_URI, request->first_line.u.request.uri.s, request->first_line.u.request.uri.len );

	// Read From header
	if ( request->from )
	{
		dlg_acc_set_str( infos, DLG_ACC_STR_FROM, request->from->body.s, request->from->body.len );
	}

	// Read CONTACT header
	if ( request->contact )
	{
		dlg_acc_set_str( infos, DLG_ACC_STR_CONTACT, request->contact->body.s, request->contact->body.len );
	}

	// Read P-Asserted-Identity
	if ( request->pai )
	{
		dlg_acc_set_str( infos, DLG_ACC_STR_ASSERT_ID, request->pai->body.s, request->pai->body.len );
	}

	// Call ID
	if ( request->callid )
	{
		dlg_acc_set_str( infos, DLG_ACC_STR_CALL_ID, request->callid->body.s, request->callid->body.len );
	}

	// Read ICID or generate it
	dlg_acc_get_icid( request, infos );

	// Send ICID
	dlg_api.store_dlg_value(dlg, &icid_dlg_var, &infos->strings[DLG_ACC_STR_ICID]);

	// Diversion
	if ( request->diversion )
	{
		dlg_acc_set_str( infos, DLG_ACC_STR_DIVERSION, request->diversion->body.s, request->diversion->body.len );
	}


	// Setup in-gateway from avp
	dlg_acc_set_ingw( infos );

	// Setup user defined avp
	dlg_acc_set_accavp( infos );

	return infos;
}

static void on_dialog_created(struct dlg_cell *dlg, int type, struct dlg_cb_params *_params)
{
	dlg_acc_info *infos;

	if ( dlg_acc_flag != -1 && type == DLGCB_CREATED )
	{
		if ( (_params->msg->flags & (1<<dlg_acc_flag)) == 0 )
			return;
	}

	infos = ( type == DLGCB_CREATED ) ? init_from_sip( dlg, _params ) : load_dialog_acc_info_from_db( dlg );

	if ( ! infos )
	{
		LM_ERR( "Can't create dialog accounting infos\n" );
		return;
	}

	if (dlg_api.register_dlgcb(dlg, DLGCB_RESPONSE_FWDED, on_dialog_replies, infos, NULL) != 0)
		LM_ERR("cannot register callback for dialog confirmation\n");

	if (dlg_api.register_dlgcb(dlg, DLGCB_TERMINATED | DLGCB_FAILED | DLGCB_EXPIRED, on_dialog_ended, infos, dlg_acc_free) != 0)
		LM_ERR("cannot register callback for dialog termination\n");

	if (dlg_api.register_dlgcb(dlg, DLGCB_SAVED, on_dialog_saved, infos, NULL) != 0)
		LM_ERR("cannot register callback for dialog saved\n");

	LM_INFO( "dlg_acc : setup start=%d, icid=%.*s\n", (int)infos->connect_ts.tv_sec, infos->strings[DLG_ACC_STR_ICID].len, infos->strings[DLG_ACC_STR_ICID].s );
	LM_INFO( "CREATE -> HASH_ID=%d | ENTRY_ID=%d | CONNECT=%d\n", dlg->h_id, dlg->h_entry, (int)infos->connect_ts.tv_sec);

	// Setup accouting
	if ( ( type == DLGCB_CREATED ) && radius_config )
	{
		dlg_acc_do_rad_setup( dlg, infos );
	}
}

/*
 * Handle connect
 */
static void on_dialog_replies(struct dlg_cell *dlg, int type, struct dlg_cb_params *_params)
{
	struct sip_msg *reply = _params->msg;
	char buf[256];
	str sbuf;
	dlg_acc_info *infos = (dlg_acc_info*)*_params->param;

	if (reply!=FAKED_REPLY && reply->REPLY_STATUS==200)
	{
		// Setup routes & prev-routes from avp
		dlg_acc_set_route( infos );
		dlg_acc_set_prev_routes( infos );
		dlg_acc_set_str( infos, DLG_ACC_STR_PREV_CAUSE, "200", 3 );
		infos->nb_prev_cause = 1;
		dlg_acc_set_causes( infos );
		infos->route_handled = 1;

		// Set connect time
		gettimeofday( &infos->connect_ts, NULL );
		sprintf(buf, "%d", (int) infos->connect_ts.tv_sec);
		sbuf.s = buf;
		sbuf.len = strlen(buf);
		dlg_api.store_dlg_value(dlg, &connect_dlg_var, &sbuf);

		infos->connected = 1;

		LM_DBG( "dlg_acc : connect start=%d, icid=%.*s\n", (int)infos->connect_ts.tv_sec, infos->strings[DLG_ACC_STR_ICID].len, infos->strings[DLG_ACC_STR_ICID].s );
		// Connect accouting
		if ( radius_config )
		{
			dlg_acc_do_rad_connect( dlg, infos );
		}
	}

	LM_INFO( "REPLY -> HASH_ID=%d | ENTRY_ID=%d | CONNECT=%d\n", dlg->h_id, dlg->h_entry, (int)infos->connect_ts.tv_sec);
}


/*
 * Handle release
 */
static void on_dialog_ended(struct dlg_cell *dlg, int type, struct dlg_cb_params *_params)
{
	char buf[256];
	str sbuf;
	dlg_acc_info *infos = (dlg_acc_info*)*_params->param;

	// Setup route from avp
	if ( infos->route_handled == 0 )
	{
		dlg_acc_set_route( infos );
		dlg_acc_set_prev_routes( infos );
		dlg_acc_set_causes( infos );
		infos->route_handled = 1;
	}

	// Set release & session time
	gettimeofday( &infos->release_ts, NULL );
	sprintf(buf, "%d", (int) infos->release_ts.tv_sec);
	sbuf.s = buf;
	sbuf.len = strlen(buf);
	dlg_api.store_dlg_value(dlg, &release_dlg_var, &sbuf);

	if ( infos->connected )
	{
		diff_tv( infos->connect_ts, infos->release_ts, &infos->session_ts );
	}
	else
	{
		infos->connect_ts = infos->release_ts;
	}

	LM_INFO( "dlg_acc : release msg=%p, start=%d, icid=%.*s\n", _params->msg, (int)infos->connect_ts.tv_sec, infos->strings[DLG_ACC_STR_ICID].len, infos->strings[DLG_ACC_STR_ICID].s );

	// Set the hang-up originator
	switch ( type )
	{
	case DLGCB_TERMINATED:
		switch ( _params->direction )
		{
		case DLG_DIR_DOWNSTREAM:
			infos->hangup_originator = DLG_ACC_HUP_CALLER;
			break;
		case DLG_DIR_UPSTREAM:
			infos->hangup_originator = DLG_ACC_HUP_CALLEE;
			break;
		case DLG_DIR_NONE:
			infos->hangup_originator = DLG_ACC_HUP_PROXY;
			break;
		}
		break;
	case DLGCB_FAILED:
		if ( _params->msg && ( _params->msg != FAKED_REPLY ) && ( _params->msg->first_line.type == SIP_REPLY ) && ( _params->msg->first_line.u.reply.statuscode == 487 ) )
		{
			infos->hangup_originator = DLG_ACC_HUP_CALLER;
		}
		else if ( _params->msg == FAKED_REPLY )
		{
			infos->hangup_originator = DLG_ACC_HUP_PROXY;
		}
		else
		{
			infos->hangup_originator = DLG_ACC_HUP_CALLEE;
		}
		break;
	case DLGCB_EXPIRED:
		infos->hangup_originator = DLG_ACC_HUP_PROXY;
		break;
	}

	// Do release accouting
	if ( radius_config )
	{
		dlg_acc_do_rad_release( dlg, infos );
	}

	LM_INFO( "END -> HASH_ID=%d | ENTRY_ID=%d\n", dlg->h_id, dlg->h_entry);
}


static int mod_init( void )
{
	LM_INFO("Dialog Accounting module - initializing\n");

	if ( dlg_acc_flag!=-1 && dlg_acc_flag>MAX_FLAG) {
		LM_ERR("invalid account flag %d!!\n",dlg_acc_flag);
		return -1;
	}

	// Setup DB access
	/* if a database should be used to store the dialogs' information */
	if( dlg_acc_db_mode == DB_MODE_NONE)
	{
		db_url.s = 0; 
		db_url.len = 0;
	} 
	else 
	{
		if( dlg_acc_db_mode != DB_MODE_DELAYED )
		{
			LM_ERR("unsupported db_mode %d\n", dlg_acc_db_mode);
			return -1;
		}

		if ( ! db_url.s || ! db_url.len ) 
		{
			LM_ERR("db_url not configured for db_mode %d\n", dlg_acc_db_mode);
			return -1;
		}

		if( init_dlg_acc_db( &db_url ) != 0 ) 
		{
			LM_ERR("failed to initialize the DB support\n");
			return -1;
		}
	}

	// Initialize avp parameters
	if ( init_avp_params( ingw_avp_param, route_avp_param, routedesc_avp_param, causes_avp_param, accavp_avp_param ) != 0 )
	{
		return -1;
	}

	// bind to the dialog API
	if( load_dlg_api( &dlg_api ) != 0 ) 
	{
		LM_CRIT("cannot load the dialog module API\n");
		return -1;
	}

	// register dialog creation callback
	if( dlg_api.register_dlgcb( NULL, DLGCB_CREATED, on_dialog_created, NULL, NULL ) != 0 ) 
	{
		LM_CRIT("cannot register callback for dialog creation\n");
		return -1;
	}

	// register dialog creation callback
	if( dlg_api.register_dlgcb( NULL, DLGCB_LOADED, on_dialog_created, NULL, NULL ) != 0 ) 
	{
		LM_CRIT("cannot register callback for dialog loading\n");
		return -1;
	}

	// We needed db connection only for DLGCB_LOADED.
	// A new connection will be created by each child.
	destroy_dlg_acc_db();

	// Read Radius configuration file
	if ( radius_config )
	{
		if ( dlg_acc_rad_init( radius_config ) != 0 )
		{
			LM_CRIT("Unable to configure radius\n");
			return -1;
		}
	}

	return 0;
}

static int child_init(int rank)
{
	if ( dlg_acc_connect_db(&db_url) ) 
	{
		LM_ERR("failed to connect to database (rank=%d)\n",rank);
		return -1;
	}

	return 0;
}

static int mod_destroy( void )
{
	if( dlg_acc_db_mode == DB_MODE_DELAYED )
	{
		destroy_dlg_acc_db();
	}

	/* no DB interaction from now on */
	dlg_acc_db_mode = DB_MODE_NONE;

	return 0;
}

void dump_acc_info(dlg_acc_info *pdai)
{
	if( pdai )
		LM_INFO( "dlg_acc : \nICID=%.*s\nUSERNAME=%.*s\nCALLING_ID=%.*s\nCALLED_ID=%.*s\nASSERT_ID=%.*s\nCALL_ID=%.*s\n", 
			pdai->strings[DLG_ACC_STR_ICID].len, pdai->strings[DLG_ACC_STR_ICID].s,
			pdai->strings[DLG_ACC_STR_USERNAME].len, pdai->strings[DLG_ACC_STR_USERNAME].s,
			pdai->strings[DLG_ACC_STR_CALLING_ID].len, pdai->strings[DLG_ACC_STR_CALLING_ID].s,
			pdai->strings[DLG_ACC_STR_PREV_DEST_INFO].len, pdai->strings[DLG_ACC_STR_PREV_DEST_INFO].s,
			pdai->strings[DLG_ACC_STR_ASSERT_ID].len, pdai->strings[DLG_ACC_STR_ASSERT_ID].s,
			pdai->strings[DLG_ACC_STR_CALL_ID].len, pdai->strings[DLG_ACC_STR_CALL_ID].s);
}

