/* logcat.h
 *
 * Copyright 2014, Michal Labedzki for Tieto Corporation
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
 *
 */

#ifndef __LOGCAT_TEXT_PROCESS_H__
#define __LOGCAT_TEXT_PROCESS_H__

#include <glib.h>

#include "wtap.h"

int      logcat_text_process_open(wtap *wth, int *err, gchar **err_info);

gboolean logcat_binary_dump_open(wtap_dumper *wdh, int *err);
gboolean logcat_text_brief_dump_open(wtap_dumper *wdh, int *err);
gboolean logcat_text_process_dump_open(wtap_dumper *wdh, int *err);
gboolean logcat_text_tag_dump_open(wtap_dumper *wdh, int *err);
gboolean logcat_text_time_dump_open(wtap_dumper *wdh, int *err);
gboolean logcat_text_thread_dump_open(wtap_dumper *wdh, int *err);
gboolean logcat_text_threadtime_dump_open(wtap_dumper *wdh, int *err);
gboolean logcat_text_long_dump_open(wtap_dumper *wdh, int *err);

int      logcat_text_process_dump_can_write_encap(int encap);

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
