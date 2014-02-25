/* extcap.h
 * Definitions for extcap external capture
 * Copyright 2013, Mike Ryan <mikeryan@lacklustre.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __EXTCAP_H__
#define __EXTCAP_H__

#include "config.h"

#include <glib.h>

#include "capture_ifinfo.h"
#include "capture_opts.h"

#ifdef HAVE_EXTCAP

#define EXTCAP_ARGUMENT_CONFIG 			"--extcap-config"
#define EXTCAP_ARGUMENT_LIST_INTERFACES	"--extcap-interfaces"
#define EXTCAP_ARGUMENT_INTERFACE		"--extcap-interface"
#define EXTCAP_ARGUMENT_LIST_DLTS		"--extcap-dlts"

#define EXTCAP_ARGUMENT_RUN_CAPTURE		"--capture"
#define EXTCAP_ARGUMENT_RUN_PIPE		"--fifo"


/* try to get if capbilities from extcap */
if_capabilities_t *
extcap_get_if_capabilities(const gchar *ifname, char **err_str);

/* get a list of all capture interfaces */
GList *
extcap_interface_list(char **err_str);

GList *
extcap_search_for_extcaps(const char * ifname);

gboolean
extcaps_init_initerfaces(capture_options *capture_opts);

gboolean
extcap_create_pipe(char ** fifo);

void
extcap_cleanup(capture_options * capture_opts _U_);

#endif

#endif

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
