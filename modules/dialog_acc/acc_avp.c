
#include "acc_avp.h"

#include "../../pvar.h"
#include "../../mem/mem.h"


static int     ingw_avp_type;
static int     ingw_avp_name;

static int     route_avp_type;
static int     route_avp_name;

static int     routedesc_avp_type;
static int     routedesc_avp_name;

static int     causes_avp_type;
static int     causes_avp_name;

static int     accavp_avp_type;
static int     accavp_avp_name;

static int dlg_acc_set_avp_param( char *param_name, int *avp_type, int *avp_name )
{
	pv_spec_t avp_spec;
	unsigned short avp_flags;
	str s;
	if ( param_name && *param_name )
	{
		s.s = param_name;
		s.len = strlen(s.s);
		if (pv_parse_spec(&s, &avp_spec)==0 || avp_spec.type!=PVT_AVP)
		{
			LM_ERR("malformed or non AVP %s AVP definition\n", param_name);
			return -1;
		}

		if(pv_get_avp_name(0, &avp_spec.pvp, avp_name, &avp_flags)!=0)
		{
			LM_ERR("[%s]- invalid AVP definition\n", param_name);
			return -1;
		}
		*avp_type = avp_flags;
	} else {
		avp_name = 0;
		*avp_type = 0;
	}

	return 0;
}

int init_avp_params( char *ingw_avp_param, char *route_avp_param, char *routedesc_avp_param, char *causes_avp_param, char *accavp_avp_param )
{
	int ret;

	ret = dlg_acc_set_avp_param( ingw_avp_param, &ingw_avp_type, &ingw_avp_name );
	if ( ret != 0 )
	{
		return ret;
	}

	ret = dlg_acc_set_avp_param( route_avp_param, &route_avp_type, &route_avp_name );
	if ( ret != 0 )
	{
		return ret;
	}

	ret = dlg_acc_set_avp_param( routedesc_avp_param, &routedesc_avp_type, &routedesc_avp_name );
	if ( ret != 0 )
	{
		return ret;
	}

	ret = dlg_acc_set_avp_param( causes_avp_param, &causes_avp_type, &causes_avp_name );
	if ( ret != 0 )
	{
		return ret;
	}

	ret = dlg_acc_set_avp_param( accavp_avp_param, &accavp_avp_type, &accavp_avp_name );
	if ( ret != 0 )
	{
		return ret;
	}

	return 0;
}

int dlg_acc_set_ingw( dlg_acc_info *infos )
{
	struct usr_avp *avp;
	int_str val_istr;

	avp = search_first_avp( ingw_avp_type, ingw_avp_name, &val_istr, 0);
	if (!avp)
		return 1;

	if (avp->flags & AVP_VAL_STR) {
		dlg_acc_set_str( infos, DLG_ACC_STR_INGW, val_istr.s.s, val_istr.s.len );
	} else {
		// ???
	}

	return 0;
}

int dlg_acc_set_route( dlg_acc_info *infos )
{
	struct usr_avp *avp;
	int_str val_istr;
	char *route_desc;

	avp = search_first_avp( route_avp_type, route_avp_name, &val_istr, 0);
	if (!avp)
	{
		LM_INFO( "No route avp\n" );
		return 1;
	}

	if (avp->flags & AVP_VAL_STR) {
		dlg_acc_set_str( infos, DLG_ACC_STR_DEST_INFO, val_istr.s.s, val_istr.s.len );
	} else {
		// ???
	}

	avp = search_first_avp( routedesc_avp_type, routedesc_avp_name, &val_istr, 0);
	if (!avp)
	{
		LM_INFO( "No route description avp\n" );
		return 1;
	}

	if (avp->flags & AVP_VAL_STR)
	{
		route_desc = (char*)pkg_malloc( val_istr.s.len + 3 );
		// TODO : check pkg_malloc OK
		strcpy( route_desc, "RN=" );
		strncpy( route_desc + 3, val_istr.s.s, val_istr.s.len );
		dlg_acc_set_str( infos, DLG_ACC_STR_ROUTE_DESC, route_desc, val_istr.s.len + 3 );
		pkg_free( route_desc );
	} else {
		// ???
	}

	return 0;
}

int dlg_acc_set_prev_routes( dlg_acc_info *infos )
{
	struct usr_avp *avp;
	int_str val_istr;

	avp = search_first_avp( route_avp_type, route_avp_name, &val_istr, 0 );
	while ( avp && infos->nb_prev_dest_info < DLG_ACC_PREV_DEST_INFO_MAX )
	{
		if ( avp->flags & AVP_VAL_STR ) {
			dlg_acc_set_str( infos, DLG_ACC_STR_PREV_DEST_INFO+infos->nb_prev_dest_info, val_istr.s.s, val_istr.s.len );
			infos->nb_prev_dest_info++;
		} else {
			// ???
		}

		avp = search_next_avp( avp, &val_istr );
	}

	return 0;
}

int dlg_acc_set_causes( dlg_acc_info *infos )
{
	struct usr_avp *avp;
	int_str val_istr;

	avp = search_first_avp( causes_avp_type, causes_avp_name, &val_istr, 0 );
	while ( avp && infos->nb_prev_cause < DLG_ACC_PREV_DEST_INFO_MAX )
	{
		if ( avp->flags & AVP_VAL_STR ) {
			dlg_acc_set_str( infos, DLG_ACC_STR_PREV_CAUSE+infos->nb_prev_cause, val_istr.s.s, val_istr.s.len );
			infos->nb_prev_cause++;
		} else {
			// ???
		}

		avp = search_next_avp( avp, &val_istr );
	}

	return 0;
}

int dlg_acc_set_accavp( dlg_acc_info *infos )
{
	struct usr_avp *avp;
	int_str val_istr;

	avp = search_first_avp( accavp_avp_type, accavp_avp_name, &val_istr, 0 );
	while ( avp && infos->nb_accavp < DLG_ACC_ACCAVP_MAX )
	{
		if ( avp->flags & AVP_VAL_STR ) {
			dlg_acc_set_str( infos, DLG_ACC_STR_ACCAVP+infos->nb_accavp, val_istr.s.s, val_istr.s.len );
			infos->nb_accavp++;
		} else {
			// ???
		}

		avp = search_next_avp( avp, &val_istr );
	}

	return 0;
}

