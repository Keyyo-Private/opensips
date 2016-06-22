/*
 * $Id: dlg_acc_db_handler.h 2009-01-29 $
 *
 *
 * History:
 * --------
 * 2009-01-29  initial version
 */


#ifndef _DLG_ACC_DB_HANDLER_H_
#define _DLG_ACC_DB_HANDLER_H_

#include "../../str.h"
#include "../../db/db.h"

#include "dialog_acc.h"
#include "../dialog/dlg_hash.h"

#define HASH_ID_COL			"hash_id"
#define ENTRY_ID_COL		"hash_entry"
#define DATA_COL			"data"

#define DIALOG_ACC_TABLE_NAME		"dialog_acc"

#define DLG_ACC_TABLE_VERSION		2

/*every minute the dialogs' information will be refreshed*/
#define DB_DEFAULT_UPDATE_PERIOD		60
#define DB_MODE_NONE				0
#define DB_MODE_REALTIME			1
#define DB_MODE_DELAYED				2
#define DB_MODE_SHUTDOWN			3

#define DIALOG_ACC_TABLE_COL_NO 		3

#define DIALOG_ACC_FETCH_SIZE			128

extern str hash_id_column; 
extern str entry_id_column;
extern str data_column;

extern str dialog_acc_table_name;

extern int dlg_acc_db_mode;

#define should_remove_dlg_db() ( dlg_acc_db_mode && ( dlg_acc_db_mode != DB_MODE_SHUTDOWN ) )


int init_dlg_acc_db(const str *db_url);
int dlg_acc_connect_db(const str *db_url);
void destroy_dlg_acc_db();

int remove_dialog_acc_from_db(struct dlg_cell * cell);
int update_dialog_acc_to_db(struct dlg_cell * cell, dlg_acc_info *pdai);
void dialog_acc_update_db(unsigned int ticks, void * param);
dlg_acc_info *load_dialog_acc_info_from_db(struct dlg_cell *cell);

#endif
