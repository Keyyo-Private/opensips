
#include "acc_rad.h"

#include "../../radius.h"

#ifndef USE_FREERADIUS
	#include <radiusclient-ng.h>
#else
	#include <freeradius-client.h>
#endif

/* Radius attributes for dialog accounting */
enum {
	DA_RA_STATUS,
	DA_RA_USER_NAME,
	DA_RA_CALLING_ID,
	DA_RA_SETUP_TIME,
	DA_RA_SETUP_TIME_MS,
	DA_RA_CONNECT_TIME,
	DA_RA_CONNECT_TIME_MS,
	DA_RA_STOP_TIME,
	DA_RA_STOP_TIME_MS,
	DA_RA_SESSION_TIME,
	DA_RA_SESSION_TIME_MS,
	DA_RA_ICID,
	DA_RA_CALL_ID,
	DA_RA_ASSERT_ID,
	DA_RA_INGW,
	DA_RA_PREV_DEST_INFO,
	DA_RA_DEST_INFO,
	DA_RA_ROUTE_DESC,
	DA_RA_CAUSE,
	DA_RA_PREV_CAUSE,
	DA_RA_FROM,
	DA_RA_CONTACT,
	DA_RA_DIVERSION,
	DA_RA_HUP_ORIG,
	DA_RA_ACCAVP,

	DA_RA_STATIC_MAX
};

/* Radius values for dialog accounting */
enum {
	DA_RV_STATUS_SETUP,
	DA_RV_STATUS_START,
	DA_RV_STATUS_STOP,

	DA_RV_HUP_CALLER,
	DA_RV_HUP_CALLEE,
	DA_RV_HUP_PROXY,
	DA_RV_HUP_UNKNOWN,

	DA_RV_STATIC_MAX
};

/* local variables */
static void *rh;
static struct attr rd_attrs[DA_RA_STATIC_MAX];
static struct val rd_vals[DA_RV_STATIC_MAX];

int dlg_acc_init_radius_acct(void)
{
		return 0;
}

int dlg_acc_add_radius_enum( VALUE_PAIR **send, struct attr attribute, struct val value )
{
	LM_DBG( "add %s = %s\n", attribute.n, value.n );
	if ( ! rc_avpair_add( rh, send, attribute.v, &value.v, -1, 0))
    {
		LM_ERR("failed to add radius attributes\n");
		return -1;
	}

	return 0;
}

int dlg_acc_add_radius_str( VALUE_PAIR **send, struct attr attribute, str value )
{
	if ( ! value.s )
	{
		return 0;
	}

	LM_DBG( "add %s = %.*s\n", attribute.n, value.len, value.s );
	if ( ! rc_avpair_add( rh, send, attribute.v, value.s, value.len, 0))
    {
		LM_ERR("failed to add radius attributes\n");
		return -1;
	}

	return 0;
}

int dlg_acc_add_radius_int( VALUE_PAIR **send, struct attr attribute, int value )
{
	LM_DBG( "add %s = %d\n", attribute.n, value );
	if ( ! rc_avpair_add( rh, send, attribute.v, &value, -1, 0))
    {
		LM_ERR("failed to add radius attributes\n");
		return -1;
	}

	return 0;
}

int dlg_acc_send_radius( VALUE_PAIR **send )
{
	if ( rc_acct( rh, SIP_PORT, *send ) != OK_RC )
   	{
		LM_ERR("radius accounting failed\n");
		return -1;
	}

	return 0;
}

void dlg_acc_free_radius_acct( VALUE_PAIR **send )
{
	rc_avpair_free( *send );
}


// TODO
int dlg_acc_rad_init( char *radius_config )
{
	/* read config */
	if ((rh = rc_read_config(radius_config)) == NULL) {
		LM_ERR("failed to open radius config file: %s\n", radius_config );
		return -1;
	}

	/* read dictionary */
	if (rc_read_dictionary(rh, rc_conf_str(rh, "dictionary"))!=0) {
		LM_ERR("failed to read radius dictionary\n");
		return -1;
	}

	rd_attrs[DA_RA_STATUS].n          = "Acct-Status-Type";
	rd_attrs[DA_RA_ICID].n            = "SMC-VOIP-ICID";
	rd_attrs[DA_RA_ASSERT_ID].n       = "SMC-VOIP-OrigAssertedId";
	rd_attrs[DA_RA_CALLING_ID].n      = "Calling-Station-Id";
	rd_attrs[DA_RA_USER_NAME].n       = "User-Name";
	rd_attrs[DA_RA_CALL_ID].n         = "SMC-VOIP-Call-ID";
	rd_attrs[DA_RA_INGW].n            = "SMC-VOIP-Orig-GK-Name";
	rd_attrs[DA_RA_PREV_DEST_INFO].n  = "SMC-VOIP-PrevDest-Info";
	rd_attrs[DA_RA_DEST_INFO].n       = "SMC-VOIP-Dest-Info";
	rd_attrs[DA_RA_ROUTE_DESC].n      = "SMC-VOIP-Route-Description";
	rd_attrs[DA_RA_CAUSE].n           = "KEYYO-Cause";
	rd_attrs[DA_RA_PREV_CAUSE].n      = "KEYYO-PrevCause";
	rd_attrs[DA_RA_SETUP_TIME].n      = "KEYYO-Setup-Time";
	rd_attrs[DA_RA_SETUP_TIME_MS].n   = "KEYYO-SetupTimeMillisec";
	rd_attrs[DA_RA_CONNECT_TIME].n    = "SMC-VOIP-Start-Time";
	rd_attrs[DA_RA_CONNECT_TIME_MS].n = "SMC-VOIP-StartTimeMillisec";
	rd_attrs[DA_RA_STOP_TIME].n       = "SMC-VOIP-Stop-Time";
	rd_attrs[DA_RA_STOP_TIME_MS].n    = "SMC-VOIP-StopTimeMillisec";
	rd_attrs[DA_RA_SESSION_TIME].n    = "Acct-Session-Time";
	rd_attrs[DA_RA_SESSION_TIME_MS].n = "SMC-VOIP-SessionTimeMillisec";
	rd_attrs[DA_RA_FROM].n            = "KEYYO-From";
	rd_attrs[DA_RA_CONTACT].n         = "KEYYO-Contact";
	rd_attrs[DA_RA_DIVERSION].n       = "SMC-VOIP-Diversion";
	rd_attrs[DA_RA_HUP_ORIG].n        = "KEYYO-HangupOrig";
	rd_attrs[DA_RA_ACCAVP].n          = "KEYYO-AVP";

	rd_vals[DA_RV_STATUS_SETUP].n = "Interim-Update";
	rd_vals[DA_RV_STATUS_START].n = "Start";
	rd_vals[DA_RV_STATUS_STOP].n  = "Stop";
	rd_vals[DA_RV_HUP_CALLER].n   = "Hangup-Caller";
	rd_vals[DA_RV_HUP_CALLEE].n   = "Hangup-Callee";
	rd_vals[DA_RV_HUP_PROXY].n    = "Hangup-Proxy";
	rd_vals[DA_RV_HUP_UNKNOWN].n  = "Hangup-Unknown";

	INIT_AV(rh, rd_attrs, DA_RA_STATIC_MAX, rd_vals, DA_RV_STATIC_MAX, "dlg_acc", -1, -1);

	return 0;
}

/*
 * Send Setup accouting
 */
void dlg_acc_do_rad_setup( struct dlg_cell *dlg, dlg_acc_info *infos )
{
	int i,idest;
	VALUE_PAIR *send = NULL;
	int err;
	char char_buffer[256];
	str str_tmp;

	err = dlg_acc_init_radius_acct();
	err = err || dlg_acc_add_radius_enum( &send, rd_attrs[DA_RA_STATUS],        rd_vals[DA_RV_STATUS_SETUP]            );
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_ICID],          infos->strings[DLG_ACC_STR_ICID]       );
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_CALL_ID],       infos->strings[DLG_ACC_STR_CALL_ID]    );
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_ASSERT_ID],     infos->strings[DLG_ACC_STR_ASSERT_ID]  );
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_USER_NAME],     infos->strings[DLG_ACC_STR_USERNAME]   );
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_CALLING_ID],    infos->strings[DLG_ACC_STR_CALLING_ID] );
	err = err || dlg_acc_add_radius_int(  &send, rd_attrs[DA_RA_SETUP_TIME],    infos->setup_ts.tv_sec                 );
	err = err || dlg_acc_add_radius_int(  &send, rd_attrs[DA_RA_SETUP_TIME_MS], infos->setup_ts.tv_usec/1000           );
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_INGW],          infos->strings[DLG_ACC_STR_INGW]       );
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_FROM],          infos->strings[DLG_ACC_STR_FROM]       );
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_CONTACT],       infos->strings[DLG_ACC_STR_CONTACT]    );
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_DIVERSION],     infos->strings[DLG_ACC_STR_DIVERSION]  );
	
	sprintf( char_buffer, "1:%.*s", infos->strings[DLG_ACC_STR_REQUEST_URI].len, infos->strings[DLG_ACC_STR_REQUEST_URI].s );
	str_tmp.s = char_buffer;
	str_tmp.len = strlen( char_buffer );
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_PREV_DEST_INFO], str_tmp );
	for ( i = 0; i < infos->nb_prev_dest_info-1; i++ )
	{
		// strings[DLG_ACC_STR_PREV_DEST_INFO] contains all routes from last (ie Dest-Info) to first
		idest = infos->nb_prev_dest_info-1-i;
		sprintf( char_buffer, "%d:%.*s", i+2, infos->strings[DLG_ACC_STR_PREV_DEST_INFO + idest].len, infos->strings[DLG_ACC_STR_PREV_DEST_INFO + idest].s );
		str_tmp.s = char_buffer;
		str_tmp.len = strlen( char_buffer );
		err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_PREV_DEST_INFO], str_tmp );
	}

	for ( i = 0; i < infos->nb_accavp; i++ )
	{
		err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_ACCAVP], infos->strings[DLG_ACC_STR_ACCAVP + i]);
	}

	err = err || dlg_acc_send_radius( &send );
	dlg_acc_free_radius_acct( &send );
}

/*
 * Send Connect accouting
 */
void dlg_acc_do_rad_connect( struct dlg_cell *dlg, dlg_acc_info *infos )
{
	int i,idest;
	VALUE_PAIR *send = NULL;
	int err;
	char char_buffer[256];
	str str_tmp;

	err = dlg_acc_init_radius_acct();
	err = err || dlg_acc_add_radius_enum( &send, rd_attrs[DA_RA_STATUS],          rd_vals[DA_RV_STATUS_START]            );
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_ICID],            infos->strings[DLG_ACC_STR_ICID]       );
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_CALL_ID],         infos->strings[DLG_ACC_STR_CALL_ID]    );
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_ASSERT_ID],       infos->strings[DLG_ACC_STR_ASSERT_ID]  );
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_USER_NAME],       infos->strings[DLG_ACC_STR_USERNAME]   );
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_CALLING_ID],      infos->strings[DLG_ACC_STR_CALLING_ID] );
	err = err || dlg_acc_add_radius_int(  &send, rd_attrs[DA_RA_SETUP_TIME],      infos->setup_ts.tv_sec                 );
	err = err || dlg_acc_add_radius_int(  &send, rd_attrs[DA_RA_SETUP_TIME_MS],   infos->setup_ts.tv_usec/1000           );
	err = err || dlg_acc_add_radius_int(  &send, rd_attrs[DA_RA_CONNECT_TIME],    infos->connect_ts.tv_sec               );
	err = err || dlg_acc_add_radius_int(  &send, rd_attrs[DA_RA_CONNECT_TIME_MS], infos->connect_ts.tv_usec/1000         );
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_INGW],            infos->strings[DLG_ACC_STR_INGW]       );
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_FROM],            infos->strings[DLG_ACC_STR_FROM]       );
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_CONTACT],         infos->strings[DLG_ACC_STR_CONTACT]    );
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_DIVERSION],       infos->strings[DLG_ACC_STR_DIVERSION]  );

	sprintf( char_buffer, "1:%.*s", infos->strings[DLG_ACC_STR_REQUEST_URI].len, infos->strings[DLG_ACC_STR_REQUEST_URI].s );
	str_tmp.s = char_buffer;
	str_tmp.len = strlen( char_buffer );
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_PREV_DEST_INFO], str_tmp );
	for ( i = 0; i < infos->nb_prev_dest_info-1; i++ )
	{
		// strings[DLG_ACC_STR_PREV_DEST_INFO] contains all routes from last (ie Dest-Info) to first
		idest = infos->nb_prev_dest_info-1-i;
		sprintf( char_buffer, "%d:%.*s", i+2, infos->strings[DLG_ACC_STR_PREV_DEST_INFO + idest].len, infos->strings[DLG_ACC_STR_PREV_DEST_INFO + idest].s );
		str_tmp.s = char_buffer;
		str_tmp.len = strlen( char_buffer );
		err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_PREV_DEST_INFO], str_tmp );
	}
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_DEST_INFO],       infos->strings[DLG_ACC_STR_DEST_INFO]  );
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_ROUTE_DESC],      infos->strings[DLG_ACC_STR_ROUTE_DESC] );

	for ( i = 0; i < infos->nb_accavp; i++ )
	{
		err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_ACCAVP], infos->strings[DLG_ACC_STR_ACCAVP + i]);
	}

	err = err || dlg_acc_send_radius( &send );
	dlg_acc_free_radius_acct( &send );
}

/*
 * Send Release accouting
 */
void dlg_acc_do_rad_release( struct dlg_cell *dlg, dlg_acc_info *infos )
{
	int i,idest;
	VALUE_PAIR *send = NULL;
	int err;
	int_str avp_val;
	int avp_name;
	int rv_hup;
	char char_buffer[256];
	str str_tmp;
	pv_param_p ingw_param;

	//search_first_avp( /* flags */, /* name */, /* &val */, NULL );
	str_tmp.s = "ingw";
	str_tmp.len = strlen(str_tmp.s);
	avp_name = get_avp_id(&str_tmp);
	if ( search_first_avp( AVP_NAME_STR, avp_name, &avp_val, NULL ) )
	{
		LM_INFO( "in-gateway=%.*s\n", avp_val.s.len, avp_val.s.s );
	}

	switch ( infos->hangup_originator )
	{
	case DLG_ACC_HUP_CALLER:
		rv_hup = DA_RV_HUP_CALLER;
		break;
	case DLG_ACC_HUP_CALLEE:
		rv_hup = DA_RV_HUP_CALLEE;
		break;
	case DLG_ACC_HUP_PROXY:
		rv_hup = DA_RV_HUP_PROXY;
		break;
	default:
		rv_hup = DA_RV_HUP_UNKNOWN;
	}

	err = dlg_acc_init_radius_acct();
	err = err || dlg_acc_add_radius_enum( &send, rd_attrs[DA_RA_STATUS],          rd_vals[DA_RV_STATUS_STOP]             );
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_ICID],            infos->strings[DLG_ACC_STR_ICID]       );
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_CALL_ID],         infos->strings[DLG_ACC_STR_CALL_ID]    );
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_ASSERT_ID],       infos->strings[DLG_ACC_STR_ASSERT_ID]  );
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_USER_NAME],       infos->strings[DLG_ACC_STR_USERNAME]   );
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_CALLING_ID],      infos->strings[DLG_ACC_STR_CALLING_ID] );
	err = err || dlg_acc_add_radius_int(  &send, rd_attrs[DA_RA_SETUP_TIME],      infos->setup_ts.tv_sec                 );
	err = err || dlg_acc_add_radius_int(  &send, rd_attrs[DA_RA_SETUP_TIME_MS],   infos->setup_ts.tv_usec/1000           );
	err = err || dlg_acc_add_radius_int(  &send, rd_attrs[DA_RA_CONNECT_TIME],    infos->connect_ts.tv_sec               );
	err = err || dlg_acc_add_radius_int(  &send, rd_attrs[DA_RA_CONNECT_TIME_MS], infos->connect_ts.tv_usec/1000         );
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_INGW],            infos->strings[DLG_ACC_STR_INGW]       );
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_FROM],            infos->strings[DLG_ACC_STR_FROM]       );
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_CONTACT],         infos->strings[DLG_ACC_STR_CONTACT]    );
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_DIVERSION],       infos->strings[DLG_ACC_STR_DIVERSION]  );
	err = err || dlg_acc_add_radius_enum( &send, rd_attrs[DA_RA_HUP_ORIG],        rd_vals[rv_hup]                        );
	if ( infos->connected )
	{
		err = err || dlg_acc_add_radius_int( &send, rd_attrs[DA_RA_STOP_TIME],       infos->release_ts.tv_sec       );
		err = err || dlg_acc_add_radius_int( &send, rd_attrs[DA_RA_STOP_TIME_MS],    infos->release_ts.tv_usec/1000 );
		err = err || dlg_acc_add_radius_int( &send, rd_attrs[DA_RA_SESSION_TIME],    infos->session_ts.tv_sec       );
		err = err || dlg_acc_add_radius_int( &send, rd_attrs[DA_RA_SESSION_TIME_MS], infos->session_ts.tv_usec/1000 );
	}

	// Send request-uri and prev-dest-infos
	sprintf( char_buffer, "1:%.*s", infos->strings[DLG_ACC_STR_REQUEST_URI].len, infos->strings[DLG_ACC_STR_REQUEST_URI].s );
	str_tmp.s = char_buffer;
	str_tmp.len = strlen( char_buffer );
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_PREV_DEST_INFO], str_tmp );
	for ( i = 0; i < infos->nb_prev_dest_info-1; i++ )
	{
		// strings[DLG_ACC_STR_PREV_DEST_INFO] contains all routes from last (ie Dest-Info) to first
		idest = infos->nb_prev_dest_info-1-i;
		sprintf( char_buffer, "%d:%.*s", i+2, infos->strings[DLG_ACC_STR_PREV_DEST_INFO + idest].len, infos->strings[DLG_ACC_STR_PREV_DEST_INFO + idest].s );
		str_tmp.s = char_buffer;
		str_tmp.len = strlen( char_buffer );
		err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_PREV_DEST_INFO], str_tmp );
	}
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_DEST_INFO],       infos->strings[DLG_ACC_STR_DEST_INFO]  );
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_ROUTE_DESC],      infos->strings[DLG_ACC_STR_ROUTE_DESC] );

	// Send failcauses
	sprintf( char_buffer, "%.*s", infos->strings[DLG_ACC_STR_PREV_CAUSE].len, infos->strings[DLG_ACC_STR_PREV_CAUSE].s );
	str_tmp.s = char_buffer;
	str_tmp.len = strlen( char_buffer );
	err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_CAUSE], str_tmp );
	for ( i = 0; i < infos->nb_prev_cause-1; i++ )
	{
		// strings[DLG_ACC_STR_PREV_CAUSE] contains all fail causes from last to first
		idest = infos->nb_prev_cause-i-1;
		sprintf( char_buffer, "%d:%.*s", i+2, infos->strings[DLG_ACC_STR_PREV_CAUSE + idest].len, infos->strings[DLG_ACC_STR_PREV_CAUSE + idest].s );
		str_tmp.s = char_buffer;
		str_tmp.len = strlen( char_buffer );
		err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_PREV_CAUSE], str_tmp );
	}

	for ( i = 0; i < infos->nb_accavp; i++ )
	{
		err = err || dlg_acc_add_radius_str(  &send, rd_attrs[DA_RA_ACCAVP], infos->strings[DLG_ACC_STR_ACCAVP + i]);
	}

	err = err || dlg_acc_send_radius( &send );
	dlg_acc_free_radius_acct( &send );
}


