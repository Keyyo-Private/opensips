#ifndef _DIALOG_ACC_RAD_H_
#define _DIALOG_ACC_RAD_H_

#include "dialog_acc.h"
#include "../dialog/dlg_hash.h"

int dlg_acc_rad_init( char *radius_config );

void dlg_acc_do_rad_setup( struct dlg_cell *dlg, dlg_acc_info *infos );
void dlg_acc_do_rad_connect( struct dlg_cell *dlg, dlg_acc_info *infos );
void dlg_acc_do_rad_release( struct dlg_cell *dlg, dlg_acc_info *infos );

#endif

