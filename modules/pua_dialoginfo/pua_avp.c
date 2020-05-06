#include "pua_avp.h"

#include "../../mem/shm_mem.h"

static int initial_buffer_size = 128;
static int buffer_increment = 64;

static int     pua_avp_type;
static int     pua_avp_name;

int mod_init_avp_param(str *spec_param, char *param_name)
{
	pv_spec_t avp_spec;
	unsigned short avp_flags;
	if(spec_param->s) {
		spec_param->len = strlen(spec_param->s);
		if (pv_parse_spec(spec_param, &avp_spec)==0 || avp_spec.type!=PVT_AVP) {
			LM_ERR("malformed or non AVP %s AVP definition\n", param_name);
			return -1;
		}

		if(pv_get_avp_name(0, &avp_spec.pvp, &pua_avp_name, &avp_flags)!=0) {
			LM_ERR("[%s]- invalid AVP definition\n", param_name);
			return -1;
		}
		pua_avp_type = avp_flags;
	} else {
		pua_avp_name = 0;
		pua_avp_type = 0;
	}

	return 0;
}

int pua_get_avp_info(pua_avp_info *infos)
{
	// If already used: reset nb_avp and strings pointers
	// Should not happen
	if (infos->nb_avp > 0) {
		memset( infos, 0, sizeof(infos->strings) );
		infos->nb_avp = 0;
	}
	
	struct usr_avp *avp;
	int_str val_istr;
	
	avp = search_first_avp( pua_avp_type, pua_avp_name, &val_istr, 0 );
	while ( avp && infos->nb_avp < AVP_INFO_STR_MAX )
	{
		if ( avp->flags & AVP_VAL_STR ) {
			pua_set_avp_str( infos, infos->nb_avp, val_istr.s.s, val_istr.s.len );
			infos->nb_avp++;
		}

		avp = search_next_avp( avp, &val_istr );
	}

	return 0;
}

/*
 * Free pua_avp_info
 */
void pua_avp_free( void *p )
{
	pua_avp_info *infos = (pua_avp_info*)p;
	shm_free( infos->buffer );
	shm_free( infos );
}

/*
 * Create and initialize a new pua_avp_info struct
 */
pua_avp_info *pua_create_pua_avp_info( void )
{
	pua_avp_info *infos;

	infos = (pua_avp_info *)shm_malloc( sizeof(pua_avp_info) );
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
int pua_set_avp_str( pua_avp_info *infos, int index, char *src, int len )
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
			for ( i = 0; i < AVP_INFO_STR_MAX; i++ )
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
