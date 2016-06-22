
#include "icid.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#include "../../data_lump.h"
#include "../../mem/mem.h"
#include "../../parser/parser_f.h"  /* eat_space_end and so on */

#define DLG_ACC_HDR_ICID "P-Charging-Vector"
#define DLG_ACC_TAG_ICID "icid-value"
#define DLG_ACC_MAX_ICID_SIZE 64

/*
 * Extract icid-value from private header (rfc 3455)
 * On success, fill icid and return 1
 * On failure, return 0
 */
static int dlg_acc_parse_icid( str hdr_body, str *icid )
{
	char *buf;
	char *end;
	char *next_param;

	// Parsing header body
	// Read "icid-value"
	LM_INFO( "Parse ICID header : %.*s\n", hdr_body.len, hdr_body.s );
	end = hdr_body.s + hdr_body.len;

	if ( strncasecmp(hdr_body.s, DLG_ACC_TAG_ICID, sizeof(DLG_ACC_TAG_ICID)-1) != 0 )
	{
		LM_ERR("failed to parse icid in header '" DLG_ACC_HDR_ICID "'.\n");
		return 0;
	}

	// Read "="
	buf = eat_space_end( hdr_body.s + strlen(DLG_ACC_TAG_ICID), end );
	if ( *buf != '=' )
	{
		LM_ERR("failed to parse icid in header '" DLG_ACC_HDR_ICID "'.\n");
		return 0;
	}
	buf = eat_space_end( buf + 1, end );

	// Read value
	icid->s = buf;
	icid->len = end - buf;
	next_param = find_not_quoted( icid, ';' );
	if ( next_param != 0 )
	{
		icid->len = next_param - buf;
	}

	// Strip icid value
	while ( icid->len && ( (icid->s[icid->len-1] == ' ') | (icid->s[icid->len-1] == '\t') ) )
	{
		icid->len--;
	}

	// Strip "
	if ( (icid->len>2) && icid->s[0] == '"' && icid->s[icid->len-1] == '"' )
	{
		icid->s++;
		icid->len -= 2;
	}
	LM_INFO( "icid=%.*s\n", icid->len, icid->s );

	return 1;
}

/*
 * Generate an icid-value
 */
static void dlg_acc_generate_icid( struct sip_msg *msg, dlg_acc_info *infos )
{
	char icid_buffer[64];

	struct timeval tv;
	gettimeofday(&tv, NULL);
	sprintf( icid_buffer, "%08x%05x%04x@%.*s"
		, (int)tv.tv_sec
		, (int)tv.tv_usec
		, rand() & 0xffff
		, msg->rcv.bind_address->address_str.len, msg->rcv.bind_address->address_str.s );
	dlg_acc_set_str( infos, DLG_ACC_STR_ICID, icid_buffer, strlen( icid_buffer ) );
}

/*
 * Append the private header (rfc 3455) containing the icid
 */
static void dlg_acc_append_header_icid( struct sip_msg *msg, str icid )
{
	int static_header_len = strlen(DLG_ACC_HDR_ICID ": " DLG_ACC_TAG_ICID "=\"\"\r\n");
	struct lump* anchor = NULL;
	char *s = NULL;
	int len = 0;


	if (parse_headers(msg, HDR_EOH_F, 0) == -1) {
		LM_ERR("failed to parse headers in message.\n");
		return;
	}

	if ((anchor = anchor_lump(msg, msg->unparsed - msg->buf, 0, 0)) == 0) {
		LM_ERR("failed to get anchor to append header\n");
		return;
	}

	len = static_header_len + icid.len;
	if ((s = (char *)pkg_malloc(len)) == 0) {
		LM_ERR("No more pkg memory. (size requested = %d)\n", len);
		return;
	}
	strcpy( s, DLG_ACC_HDR_ICID ": " DLG_ACC_TAG_ICID "=\"" );
	strncat( s, icid.s, icid.len );
	strcat( s, "\"\r\n" );

	if (insert_new_lump_before(anchor, s, len, 0) == 0) {
		LM_ERR("failed to insert lump\n");
		pkg_free(s);
		return;
	}
	LM_DBG("Done appending header successfully.\n");
	return;
}

/*
 * Replace the current private header containing the icid with a new one
 * genrated localy.
 * Respect rules described in lump_struct.h:113
 */
static void dlg_acc_replace_header_icid( struct sip_msg *msg, struct hdr_field *hf, str icid )
{
	int static_header_len = strlen(DLG_ACC_HDR_ICID ": " DLG_ACC_TAG_ICID "=\"\"\r\n");
	struct lump* anchor = NULL;
	char *s = NULL;
	int len = 0;

	// Create new header
	len = static_header_len + icid.len;
	if (( s = (char *)pkg_malloc(len)) == 0) {
		LM_ERR("No more pkg memory. (size requested = %d)\n", len);
		return;
	}
	strcpy( s, DLG_ACC_HDR_ICID ": " DLG_ACC_TAG_ICID "=\"" );
	strncat( s, icid.s, icid.len );
	strcat( s, "\"\r\n" );

	// Delete old header
	anchor = del_lump( msg, hf->name.s - msg->buf, hf->len, 0 );

	// Add new header
	insert_new_lump_after( anchor, s, len, 0);
}

void dlg_acc_get_icid( struct sip_msg *msg, dlg_acc_info *infos )
{
	str icid;
	struct hdr_field *hf = NULL;

	// Try to read ICID from request msg
	icid.s = NULL;
	icid.len = 0;
	hf = get_header_by_static_name( msg, DLG_ACC_HDR_ICID );
	if ( hf )
	{
		// Header found, parse it
		if ( dlg_acc_parse_icid( hf->body, &icid ) && icid.len <= DLG_ACC_MAX_ICID_SIZE )
		{
			// Header OK, store read icid
			dlg_acc_set_str( infos, DLG_ACC_STR_ICID, icid.s, icid.len );
		}
		else
		{
			// Header NOT OK, generate a new one
			dlg_acc_generate_icid( msg, infos );
			dlg_acc_replace_header_icid( msg, hf, infos->strings[DLG_ACC_STR_ICID] );
			LM_ERR( "ICID too long, replace it : %.*s -> %.*s\n",
				icid.len, icid.s,
				infos->strings[DLG_ACC_STR_ICID].len, infos->strings[DLG_ACC_STR_ICID].s );
		}
	}
	else
	{
		// If no ICID found, generate it
		dlg_acc_generate_icid( msg, infos );
		dlg_acc_append_header_icid( msg, infos->strings[DLG_ACC_STR_ICID] );
	}
}


