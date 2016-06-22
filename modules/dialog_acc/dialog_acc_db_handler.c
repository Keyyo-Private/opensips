/*
 * $Id: dlg_acc_db_handler.c 2009-01-29 $
 *
 *
 * History:
 * --------
 * 2009-01-29  initial version
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "../../dprint.h"
#include "../../ut.h"
#include "../../timer.h"
#include "../../db/db.h"
#include "../../str.h"
#include "../../socket_info.h"

#include "../dialog/dlg_hash.h"
#include "dialog_acc.h"
#include "dialog_acc_db_handler.h"

str hash_id_column			=	str_init(HASH_ID_COL);
str entry_id_column			=	str_init(ENTRY_ID_COL);
str data_column				=	str_init(DATA_COL);

str dialog_acc_table_name	=	str_init(DIALOG_ACC_TABLE_NAME);

int dlg_acc_db_mode			=	DB_MODE_NONE;

static db_con_t* dialog_acc_db_handle    = 0; /* database connection handle */
static db_func_t dialog_acc_dbf;

void serialize_data(dlg_acc_info *pdai, str *data);
void unserialize_data(str *data, dlg_acc_info *pdai);

#define SET_INT_VALUE(_val, _int)\
	do{\
		VAL_INT(_val)   = _int;\
		VAL_NULL(_val) = 0;\
	}while(0);

#define SET_STR_VALUE(_val, _str)\
	do{\
		if ( (_str).len != 0) { \
			VAL_STR((_val)).s 		= (_str).s;\
			VAL_STR((_val)).len 	= (_str).len;\
			VAL_NULL(_val) = 0;\
		} else { \
			VAL_STR((_val)).s 		= NULL;\
			VAL_STR((_val)).len 	= 0;\
			VAL_NULL(_val) = 1;\
		}\
	}while(0);

#define GET_STR_VALUE(_res, _values, _index, _not_null, _unref)\
	do{\
		if (VAL_NULL((_values)+ (_index))) { \
			{ \
				(_res).s = 0; \
				(_res).len = 0; \
			}\
		} else { \
			(_res).s = VAL_STR((_values)+ (_index)).s;\
			(_res).len = strlen(VAL_STR((_values)+ (_index)).s);\
		} \
	}while(0);


int dlg_acc_connect_db(const str *db_url)
{
	if (dialog_acc_db_handle) 
	{
		LM_CRIT("BUG - db connection found already open\n");
		return -1;
	}

	if( ( dialog_acc_db_handle = dialog_acc_dbf.init( db_url ) ) == 0 )
		return -1;

	return 0;
}


static int use_dialog_acc_table(void)
{
	if(!dialog_acc_db_handle)
	{
		LM_ERR("invalid database handle\n");
		return -1;
	}

	if( dialog_acc_dbf.use_table( dialog_acc_db_handle, &dialog_acc_table_name ) < 0 ) 
	{
		LM_ERR("Error in use_table\n");
		return -1;
	}

	return 0;
}


int remove_all_dialogs_acc_from_db(void)
{
	if ( use_dialog_acc_table() != 0 )
		return -1;

	if(dialog_acc_dbf.delete(dialog_acc_db_handle, NULL, NULL, NULL, 0) < 0)
	{
		LM_ERR("failed to delete database information\n");
		return -1;
	}

	return 0;
}


int init_dlg_acc_db(const str *db_url)
{
	/* Find a database module */
	if( db_bind_mod( db_url, &dialog_acc_dbf ) < 0 )
	{
		LM_ERR("Unable to bind to a database driver\n");
		return -1;
	}

	if( dlg_acc_connect_db( db_url ) != 0 )
	{
		LM_ERR("unable to connect to the database\n");
		return -1;
	}

	if( db_check_table_version( &dialog_acc_dbf, dialog_acc_db_handle, &dialog_acc_table_name, DLG_ACC_TABLE_VERSION) < 0 ) 
	{
		LM_ERR("error during table version check.\n");
		return -1;
	}

	return 0;
}


void destroy_dlg_acc_db(void)
{
	/* close the DB connection */
	if (dialog_acc_db_handle) {
		dialog_acc_dbf.close(dialog_acc_db_handle);
		dialog_acc_db_handle = 0;
	}
}


dlg_acc_info *load_dialog_acc_info_from_db(struct dlg_cell *cell)
{
	str data;
	db_key_t comp_cols[2] = { &hash_id_column, &entry_id_column };
	db_key_t query_cols[1] = { &data_column };
	dlg_acc_info *pdai=NULL;
	db_val_t * values;
	db_row_t * rows;
	db_res_t * res=NULL;

	db_val_t val[2];

	VAL_TYPE(&val[0]) = VAL_TYPE(&val[1]) = DB_INT;
	VAL_NULL(&val[0]) = VAL_NULL(&val[1]) = 0;
	VAL_INT(&val[0]) = cell->h_id; VAL_INT(&val[1]) = cell->h_entry;

	if( use_dialog_acc_table() != 0 )
		return NULL;

	if( dialog_acc_dbf.query( 
		dialog_acc_db_handle,	// Connection handle
		comp_cols,				// WHERE columns names
		0,						// Comparison operator (0 means =)
		val,					// Comparison values
		query_cols,				// Selected columns names
		2,						// Key-value pairs provided for the WHERE clause
		1,						// Number of selected columns
		0,						// order by columns
		0    					// Results to be stored
		) < 0) 
	{
		LM_ERR("Error while querying (fetch) database\n");
		return NULL;
	}

	if( dialog_acc_dbf.fetch_result( dialog_acc_db_handle, &res, DIALOG_ACC_FETCH_SIZE ) < 0 )
	{
		LM_ERR("fetching rows failed\n");
		return NULL;
	}

	if( ( rows = RES_ROWS(res) ) > 0 )
	{
		values = ROW_VALUES( rows );
		GET_STR_VALUE(data, values, 0, 1, 0);
		pdai = dlg_acc_create_acc_info();
		if( ! pdai )
		{
			LM_ERR("Could not allocate a new dlg_acc_info in load_dialog_acc_info_from_db\n");
			goto error;
		}

		unserialize_data( &data, pdai );
	}

	dialog_acc_dbf.free_result(dialog_acc_db_handle, res);
	return pdai;

error:
	dialog_acc_dbf.free_result(dialog_acc_db_handle, res);
	return NULL;
}


/* this is only called from destroy_dlg, where the cell's entry 
 * lock is acquired
 */
int remove_dialog_acc_from_db(struct dlg_cell * cell)
{
	db_val_t values[2];
	db_key_t match_keys[2] = { &hash_id_column, &entry_id_column};

	/*if the dialog hasn 't been yet inserted in the database*/
	LM_DBG("trying to remove a dialog, update_flag is %i\n", cell->flags);
	if (cell->flags & DLG_FLAG_NEW) 
		return 0;

	if( use_dialog_acc_table() != 0 )
		return -1;

	VAL_TYPE(values) = VAL_TYPE(values + 1) = DB_INT;
	VAL_NULL(values) = VAL_NULL(values + 1) = 0;

	VAL_INT(values)     = cell->h_id;
	VAL_INT(values + 1) = cell->h_entry;

	if(dialog_acc_dbf.delete(
		dialog_acc_db_handle,	// Connection handle
		match_keys,				// Columns names to match
		0,						// Operator for matching (0 means =)
		values,					// Values to be matched
		2						// Number of columns names provided
		) < 0) 
	{
		LM_ERR("failed to delete database information\n");
		return -1;
	}

	LM_DBG("callid was %.*s\n", cell->callid.len, cell->callid.s );

	return 0;
}


int update_dialog_acc_to_db(struct dlg_cell * cell, dlg_acc_info *pdai)
{
	db_val_t values[DIALOG_ACC_TABLE_COL_NO];
	str data;

	db_key_t insert_keys[DIALOG_ACC_TABLE_COL_NO] = { 
		&hash_id_column,
		&entry_id_column,
		&data_column
	};

	if( use_dialog_acc_table() != 0 )
		return -1;

	serialize_data( pdai, &data );

	LM_INFO( "cell flag %d\n", cell->flags );
	LM_INFO( "data=%.*s\n", data.len, data.s );
	if((cell->flags & DLG_FLAG_NEW) != 0)
	{
		/* save all the current dialogs information*/
		VAL_TYPE(values) = VAL_TYPE(values + 1) = DB_INT;
		VAL_TYPE(values + 2) = DB_STR;

		SET_INT_VALUE(values, cell->h_id);
		SET_INT_VALUE(values + 1, cell->h_entry);
		SET_STR_VALUE(values + 2, data);

		if( ( dialog_acc_dbf.insert(
			dialog_acc_db_handle,	// Connection handle
			insert_keys,			// Columns names
			values,					// Values
			DIALOG_ACC_TABLE_COL_NO // Number of values
			) ) !=0 )
		{
			LM_ERR("could not add another dialog acc to db\n");
			goto error;
		}
		cell->flags &= ~(DLG_FLAG_NEW|DLG_FLAG_CHANGED);
		
	} 
	else if((cell->flags & DLG_FLAG_CHANGED) != 0) 
	{
		/* save only dialog's state and timeout */
		VAL_TYPE(values) = VAL_TYPE(values + 1) = DB_INT;
		VAL_TYPE(values + 2) = DB_STR;

		SET_INT_VALUE(values, cell->h_entry);
		SET_INT_VALUE(values + 1, cell->h_id);
		SET_STR_VALUE(values + 2, data);

		if((dialog_acc_dbf.update(
			dialog_acc_db_handle,	// Connection handle
			(insert_keys),			// Columns names 2 B matched
			0,						// Operator (0 means =)
			(values),				// Values to match
			(insert_keys + 2),		// Columns names 2 B modified
			(values + 2),			// New values to update
			2,						// Number of key-value pairs for matching
			1						// Number of key-value pairs to update
			)) !=0 )
		{
			LM_ERR("could not update database info\n");
			goto error;
		}
		cell->flags &= ~(DLG_FLAG_CHANGED);
	} 

	pkg_free(data.s);
	return 0;

error:
	pkg_free(data.s);
	return -1;
}


void serialize_data(dlg_acc_info *pdai, str *data)
{
	char tmp[4096],
		field[1024];
	int len;
	int i;

	memset(tmp, 0, 4096);

	if ( (pdai->setup_ts.tv_sec != 0) || ((pdai->setup_ts.tv_usec/1000) != 0) )
	{
		sprintf(field, "Setup:%d\n,SetupMs:%d\n",
			(int)pdai->setup_ts.tv_sec, 
			(int)(pdai->setup_ts.tv_usec/1000));
		strcat(tmp, field);
	}

	if ( (pdai->connect_ts.tv_sec != 0) || ((pdai->connect_ts.tv_usec/1000) != 0) )
	{
		sprintf(field, "Connect:%d\n,ConnectMs:%d\n",
			(int)pdai->connect_ts.tv_sec, 
			(int)(pdai->connect_ts.tv_usec/1000));
		strcat(tmp, field);
	}

	if ( (pdai->release_ts.tv_sec != 0) || ((pdai->release_ts.tv_usec/1000) != 0) )
	{
		sprintf(field, "Release:%d\n,ReleaseMs:%d\n",
			(int)pdai->release_ts.tv_sec, 
			(int)(pdai->release_ts.tv_usec/1000));
		strcat(tmp, field);
	}

	if ( (pdai->session_ts.tv_sec != 0) || ((pdai->session_ts.tv_usec/1000) != 0) )
	{
		sprintf(field, "Session:%d\n,SessionMs:%d\n",
			(int)pdai->session_ts.tv_sec, 
			(int)(pdai->session_ts.tv_usec/1000));
		strcat(tmp, field);
	}

	if( pdai->strings[DLG_ACC_STR_ICID].len )
	{
		sprintf(field, "ICID:%.*s\n", pdai->strings[DLG_ACC_STR_ICID].len, pdai->strings[DLG_ACC_STR_ICID].s);
		strcat(tmp, field);
	}

	if( pdai->strings[DLG_ACC_STR_USERNAME].len )
	{
		sprintf(field, "Username:%.*s\n", pdai->strings[DLG_ACC_STR_USERNAME].len, pdai->strings[DLG_ACC_STR_USERNAME].s);
		strcat(tmp, field);
	}

	if( pdai->strings[DLG_ACC_STR_CALLING_ID].len )
	{
		sprintf(field, "Calling-ID:%.*s\n", pdai->strings[DLG_ACC_STR_CALLING_ID].len, pdai->strings[DLG_ACC_STR_CALLING_ID].s);
		strcat(tmp, field);
	}

	if( pdai->strings[DLG_ACC_STR_ASSERT_ID].len )
	{
		sprintf(field, "Assert-ID:%.*s\n", pdai->strings[DLG_ACC_STR_ASSERT_ID].len, pdai->strings[DLG_ACC_STR_ASSERT_ID].s);
		strcat(tmp, field);
	}

	if( pdai->strings[DLG_ACC_STR_CALL_ID].len )
	{
		sprintf(field, "Call-ID:%.*s\n", pdai->strings[DLG_ACC_STR_CALL_ID].len, pdai->strings[DLG_ACC_STR_CALL_ID].s);
		strcat(tmp, field);
	}

	if( pdai->strings[DLG_ACC_STR_INGW].len )
	{
		sprintf(field, "InGw:%.*s\n", pdai->strings[DLG_ACC_STR_INGW].len, pdai->strings[DLG_ACC_STR_INGW].s);
		strcat(tmp, field);
	}

	if( pdai->strings[DLG_ACC_STR_REQUEST_URI].len )
	{
		sprintf(field, "Request-URI:%.*s\n", pdai->strings[DLG_ACC_STR_REQUEST_URI].len, pdai->strings[DLG_ACC_STR_REQUEST_URI].s);
		strcat(tmp, field);
	}

	for ( i = 0; i < pdai->nb_prev_dest_info; i++ )
	{
		sprintf(field, "PrevDest-Info:%.*s\n", pdai->strings[DLG_ACC_STR_PREV_DEST_INFO+i].len, pdai->strings[DLG_ACC_STR_PREV_DEST_INFO+i].s);
		strcat(tmp, field);
	}

	if( pdai->strings[DLG_ACC_STR_DEST_INFO].len )
	{
		sprintf(field, "Dest-Info:%.*s\n", pdai->strings[DLG_ACC_STR_DEST_INFO].len, pdai->strings[DLG_ACC_STR_DEST_INFO].s);
		strcat(tmp, field);
	}

	for ( i = 0; i < pdai->nb_prev_cause; i++ )
	{
		sprintf(field, "PrevCause:%.*s\n", pdai->strings[DLG_ACC_STR_PREV_CAUSE+i].len, pdai->strings[DLG_ACC_STR_PREV_CAUSE+i].s);
		strcat(tmp, field);
	}

	if( pdai->strings[DLG_ACC_STR_ROUTE_DESC].len )
	{
		sprintf(field, "RouteDesc:%.*s\n", pdai->strings[DLG_ACC_STR_ROUTE_DESC].len, pdai->strings[DLG_ACC_STR_ROUTE_DESC].s);
		strcat(tmp, field);
	}

	if( pdai->strings[DLG_ACC_STR_FROM].len )
	{
		sprintf(field, "From:%.*s\n", pdai->strings[DLG_ACC_STR_FROM].len, pdai->strings[DLG_ACC_STR_FROM].s);
		strcat(tmp, field);
	}

	if( pdai->strings[DLG_ACC_STR_CONTACT].len )
	{
		sprintf(field, "Contact:%.*s\n", pdai->strings[DLG_ACC_STR_CONTACT].len, pdai->strings[DLG_ACC_STR_CONTACT].s);
		strcat(tmp, field);
	}

	if( pdai->strings[DLG_ACC_STR_DIVERSION].len )
	{
		sprintf(field, "Diversion:%.*s\n", pdai->strings[DLG_ACC_STR_DIVERSION].len, pdai->strings[DLG_ACC_STR_DIVERSION].s);
		strcat(tmp, field);
	}

	for ( i = 0; i < pdai->nb_accavp; i++ )
	{
		sprintf(field, "AccAVP:%.*s\n", pdai->strings[DLG_ACC_STR_ACCAVP+i].len, pdai->strings[DLG_ACC_STR_ACCAVP+i].s);
		strcat(tmp, field);
	}

	len = strlen(tmp);
	data->s = (char *)pkg_malloc( len );
	if ( ! data->s )
	{
		LM_ERR("No more pkg memory. (size requested = %d)\n", len);
		return;
	}
	memcpy(data->s, tmp, len);
	data->len = len;
}

void unserialize_data(str *data, dlg_acc_info *pdai)
{
	char field[16], value[16];
	int vlen = 16;
	char *ptr, *ptr_s;

	ptr = data->s;

	while( ( ptr_s = strchr( ptr, '\n' ) ) && ( ptr_s < ( ptr + data->len ) ) )
	{
		strcpy( field, "ICID:" );
		if( strstr( ptr, field ) == ptr )
			dlg_acc_set_str(pdai, DLG_ACC_STR_ICID, ptr + strlen( field ), ptr_s - ptr - strlen( field ) );

		strcpy( field, "Username:" );
		if( strstr( ptr, field ) == ptr )
			dlg_acc_set_str(pdai, DLG_ACC_STR_USERNAME, ptr + strlen( field ), ptr_s - ptr - strlen( field ) );

		strcpy( field, "Calling-ID:" );
		if( strstr( ptr, field ) == ptr )
			dlg_acc_set_str(pdai, DLG_ACC_STR_CALLING_ID, ptr + strlen( field ), ptr_s - ptr - strlen( field ) );

		strcpy( field, "Assert-ID:" );
		if( strstr( ptr, field ) == ptr )
			dlg_acc_set_str(pdai, DLG_ACC_STR_ASSERT_ID, ptr + strlen( field ), ptr_s - ptr - strlen( field ) );

		strcpy( field, "Call-ID:" );
		if( strstr( ptr, field ) == ptr )
			dlg_acc_set_str(pdai, DLG_ACC_STR_CALL_ID, ptr + strlen( field ), ptr_s - ptr - strlen( field ) );

		strcpy( field, "InGw:" );
		if( strstr( ptr, field ) == ptr )
			dlg_acc_set_str(pdai, DLG_ACC_STR_INGW, ptr + strlen( field ), ptr_s - ptr - strlen( field ) );

		strcpy( field, "Request-URI:" );
		if( strstr( ptr, field ) == ptr )
			dlg_acc_set_str(pdai, DLG_ACC_STR_REQUEST_URI, ptr + strlen( field ), ptr_s - ptr - strlen( field ) );

		strcpy( field, "PrevDest-Info:" );
		if( strstr( ptr, field ) == ptr )
		{
			dlg_acc_set_str(pdai, DLG_ACC_STR_PREV_DEST_INFO+pdai->nb_prev_dest_info, ptr + strlen( field ), ptr_s - ptr - strlen( field ) );
			pdai->nb_prev_dest_info++;
		}

		strcpy( field, "Dest-Info:" );
		if( strstr( ptr, field ) == ptr )
			dlg_acc_set_str(pdai, DLG_ACC_STR_DEST_INFO, ptr + strlen( field ), ptr_s - ptr - strlen( field ) );

		strcpy( field, "PrevCause:" );
		if( strstr( ptr, field ) == ptr )
		{
			dlg_acc_set_str(pdai, DLG_ACC_STR_PREV_CAUSE+pdai->nb_prev_cause, ptr + strlen( field ), ptr_s - ptr - strlen( field ) );
			pdai->nb_prev_cause++;
		}

		strcpy( field, "RouteDesc:" );
		if( strstr( ptr, field ) == ptr )
			dlg_acc_set_str(pdai, DLG_ACC_STR_ROUTE_DESC, ptr + strlen( field ), ptr_s - ptr - strlen( field ) );

		strcpy( field, "From:" );
		if( strstr( ptr, field ) == ptr )
			dlg_acc_set_str(pdai, DLG_ACC_STR_FROM, ptr + strlen( field ), ptr_s - ptr - strlen( field ) );

		strcpy( field, "Contact:" );
		if( strstr( ptr, field ) == ptr )
			dlg_acc_set_str(pdai, DLG_ACC_STR_CONTACT, ptr + strlen( field ), ptr_s - ptr - strlen( field ) );

		strcpy( field, "Diversion:" );
		if( strstr( ptr, field ) == ptr )
			dlg_acc_set_str(pdai, DLG_ACC_STR_DIVERSION, ptr + strlen( field ), ptr_s - ptr - strlen( field ) );

		strcpy( field, "AccAVP:" );
		if( strstr( ptr, field ) == ptr )
		{
			dlg_acc_set_str(pdai, DLG_ACC_STR_ACCAVP+pdai->nb_accavp, ptr + strlen( field ), ptr_s - ptr - strlen( field ) );
			pdai->nb_accavp++;
		}

		strcpy( field, "Setup:" );
		if( strstr( ptr, field ) == ptr )
		{
			memset(value, 0, vlen);
			strncpy(value, ptr + strlen( field ), ptr_s - ptr - strlen( field ) );
			pdai->setup_ts.tv_sec = atoi( value );
		}

		strcpy( field, "Connect:" );
		if( strstr( ptr, field ) == ptr )
		{
			pdai->connected = 1;
			memset(value, 0, vlen);
			strncpy(value, ptr + strlen( field ), ptr_s - ptr - strlen( field ) );
			pdai->connect_ts.tv_sec = atoi( value );
		}

		strcpy( field, "Release:" );
		if( strstr( ptr, field ) == ptr )
		{
			memset(value, 0, vlen);
			strncpy(value, ptr + strlen( field ), ptr_s - ptr - strlen( field ) );
			pdai->release_ts.tv_sec = atoi( value );
		}

		strcpy( field, "Session:" );
		if( strstr( ptr, field ) == ptr )
		{
			memset(value, 0, vlen);
			strncpy(value, ptr + strlen( field ), ptr_s - ptr - strlen( field ) );
			pdai->session_ts.tv_sec = atoi( value );
		}

		strcpy( field, "SetupMs:" );
		if( strstr( ptr, field ) == ptr )
		{
			memset(value, 0, vlen);
			strncpy(value, ptr + strlen( field ), ptr_s - ptr - strlen( field ) );
			pdai->setup_ts.tv_usec = atoi( value ) * 1000;
		}

		strcpy( field, "ConnectMs:" );
		if( strstr( ptr, field ) == ptr )
		{
			pdai->connected = 1;
			memset(value, 0, vlen);
			strncpy(value, ptr + strlen( field ), ptr_s - ptr - strlen( field ) );
			pdai->connect_ts.tv_usec = atoi( value ) * 1000;
		}

		strcpy( field, "ReleaseMs:" );
		if( strstr( ptr, field ) == ptr )
		{
			memset(value, 0, vlen);
			strncpy(value, ptr + strlen( field ), ptr_s - ptr - strlen( field ) );
			pdai->release_ts.tv_usec = atoi( value ) * 1000;
		}

		strcpy( field, "SessionMs:" );
		if( strstr( ptr, field ) == ptr )
		{
			memset(value, 0, vlen);
			strncpy(value, ptr + strlen( field ), ptr_s - ptr - strlen( field ) );
			pdai->session_ts.tv_usec = atoi( value ) * 1000;
		}
		ptr = ptr_s + 1;
	}
}

