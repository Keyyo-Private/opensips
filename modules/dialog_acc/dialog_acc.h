#ifndef _DIALOG_ACC_H_
#define _DIALOG_ACC_H_

#include <sys/time.h>

#include "../../sr_module.h"

/* Constant for string in dialog informations */
#define DLG_ACC_PREV_DEST_INFO_MAX 20
#define DLG_ACC_ACCAVP_MAX	   10

enum
{
	DLG_ACC_STR_ICID,
	DLG_ACC_STR_USERNAME,
	DLG_ACC_STR_CALLING_ID,
	DLG_ACC_STR_ASSERT_ID,
	DLG_ACC_STR_CALL_ID,
	DLG_ACC_STR_INGW,
	DLG_ACC_STR_REQUEST_URI,
	DLG_ACC_STR_PREV_DEST_INFO,
	DLG_ACC_STR_DEST_INFO = DLG_ACC_STR_PREV_DEST_INFO + DLG_ACC_PREV_DEST_INFO_MAX,
	DLG_ACC_STR_PREV_CAUSE,
	DLG_ACC_STR_ROUTE_DESC = DLG_ACC_STR_PREV_CAUSE + DLG_ACC_PREV_DEST_INFO_MAX,
	DLG_ACC_STR_FROM,
	DLG_ACC_STR_CONTACT,
	DLG_ACC_STR_ACCAVP,
	DLG_ACC_STR_DIVERSION = DLG_ACC_STR_ACCAVP + DLG_ACC_ACCAVP_MAX,

	DLG_ACC_STR_MAX
};

/* Hangup Originator */
enum
{
	DLG_ACC_HUP_UNKNOWN,
	DLG_ACC_HUP_CALLER,
	DLG_ACC_HUP_CALLEE,
	DLG_ACC_HUP_PROXY
};

/* Structure containing dialog informations */
struct _dlg_acc_info
{
	struct timeval setup_ts;
	struct timeval connect_ts;
	struct timeval release_ts;
	struct timeval session_ts;
	int connected;
	int route_handled;
	int hangup_originator;
	int nb_prev_dest_info;
	int nb_prev_cause;
	int nb_accavp;
	str strings[DLG_ACC_STR_MAX];

	int buffer_size;
	int buffer_index;
	char *buffer;
};
typedef struct _dlg_acc_info dlg_acc_info;

/* Function to use to set a string in dialog informations */
int dlg_acc_set_str( dlg_acc_info *infos, int index, char *src, int len );

// dlg_acc_info access functions
dlg_acc_info *dlg_acc_create_acc_info( void );
void dump_acc_info(dlg_acc_info *pdai);

#endif
