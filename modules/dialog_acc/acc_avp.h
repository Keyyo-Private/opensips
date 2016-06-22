#ifndef _DIALOG_ACC_AVP_H_
#define _DIALOG_ACC_AVP_H_

#include "dialog_acc.h"

int init_avp_params( char *ingw_avp_param, char *route_avp_param, char *routedesc_avp_param, char *causes_avp_param, char *accavp_avp_param );
int dlg_acc_set_ingw( dlg_acc_info *infos );
int dlg_acc_set_route( dlg_acc_info *infos );
int dlg_acc_set_prev_routes( dlg_acc_info *infos );
int dlg_acc_set_causes( dlg_acc_info *infos );
int dlg_acc_set_accavp( dlg_acc_info *infos );

#endif

