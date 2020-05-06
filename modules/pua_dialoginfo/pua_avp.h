#ifndef _PUA_AVP_INFO_H
#define _PUA_AVP_INFO_H

#include "../../sr_module.h"

#define AVP_INFO_STR_MAX 32

struct _pua_avp_info
{
	int nb_avp;
	str strings[AVP_INFO_STR_MAX];

	int buffer_size;
	int buffer_index;
	char *buffer;
};
typedef struct _pua_avp_info pua_avp_info;

int mod_init_avp_param(str *spec_param, char *param_name);
int pua_get_avp_info(pua_avp_info *infos);
void pua_avp_free( void *p );
pua_avp_info *pua_create_pua_avp_info( void );
int pua_set_avp_str( pua_avp_info *infos, int index, char *src, int len );

#endif
