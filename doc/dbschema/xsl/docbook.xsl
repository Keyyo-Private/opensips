<?xml version='1.0'?>
<!--
 * $Id$
 *
 * XSL converter script for docbook
 *
 * Copyright (C) 2001-2007 FhG Fokus
 *
 * This file is part of openser, a free SIP server.
 *
 * openser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * openser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */
-->


<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                version='1.0'
                xmlns:db="http://iptel.org/dbschema/docbook"
>
    <xsl:import href="common.xsl"/>

    <xsl:template match="/">
	<xsl:variable name="filename" select="concat($prefix, concat('/', 'dbschema.xml'))"/>
	<xsl:document href="{$filename}" method="xml" indent="yes"
	    omit-xml-declaration="no">
	    <xsl:element name="section">
		<xsl:element name="title">
		    <xsl:call-template name="get-name">
			<xsl:with-param name="select" select="database[1]"/>
		    </xsl:call-template>
		</xsl:element>
		<xsl:apply-templates select="/database[1]"/>
	    </xsl:element>
	</xsl:document>
    </xsl:template>

</xsl:stylesheet>
