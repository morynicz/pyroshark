/* logcat_text_brief.c
 *
 * Copyright 2014, Michal Orynicz for Tieto Corporation
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

#include "config.h"

#include <string.h>
#include <time.h>

#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"

#include "logcat_text_brief.h"

enum dump_type_t {
    DUMP_BINARY,
    DUMP_BRIEF,
    DUMP_PROCESS,
    DUMP_TAG,
    DUMP_TIME,
    DUMP_THREAD,
    DUMP_THREADTIME,
    DUMP_LONG
};

struct dumper_t {
    enum dump_type_t type;
};

static gchar get_priority(const guint8 *priority) {
    static gchar priorities[] = "??VDIWEFS";

    if (*priority >= (guint8) sizeof(priorities))
        return '?';

    return priorities[(int) *priority];
}

static gchar *logcat_text_brief_log(const struct dumper_t *dumper, guint32 seconds,
        gint microseconds, gint pid, gint tid, gchar priority, const gchar *tag,
        const gchar *log)
{
    gchar  time_buffer[15];
    time_t datetime;

    datetime = (time_t) seconds;

    switch (dumper->type) {
        case DUMP_BRIEF:
            return g_strdup_printf("%c/%s(%5i): %s\n",
                    priority, tag, pid, log);
        case DUMP_PROCESS:
            return g_strdup_printf("%c(%5i) %s  (%s)\n",
                    priority, pid, log, tag);
        case DUMP_TAG:
            return g_strdup_printf("%c/%s: %s\n",
                   priority, tag, log);
        case DUMP_THREAD:
            return g_strdup_printf("%c(%5i:%5i) %s\n",
                    priority, pid, tid, log);
        case DUMP_TIME:
            strftime(time_buffer, sizeof(time_buffer), "%m-%d %H:%M:%S",
                    gmtime(&datetime));
            return g_strdup_printf("%s.%03i %c/%s(%5i): %s\n",
                    time_buffer, microseconds, priority, tag, pid, log);
        case DUMP_THREADTIME:
            strftime(time_buffer, sizeof(time_buffer), "%m-%d %H:%M:%S",
                    gmtime(&datetime));
            return g_strdup_printf("%s.%03i %5i:%5i %c %s: %s\n",
                    time_buffer, microseconds, pid, tid, priority, tag, log);
        case DUMP_LONG:
            strftime(time_buffer, sizeof(time_buffer), "%m-%d %H:%M:%S",
                    gmtime(&datetime));
            return g_strdup_printf("[ %s.%03i %5i:%5i %c/%s ]\n%s\n\n",
                    time_buffer, microseconds, pid, tid, priority, tag, log);
        default:
            return NULL;
    }

}

static gboolean logcat_text_brief_read_packet(struct logcat_phdr *logcat, FILE_T fh,
    struct wtap_pkthdr *phdr, Buffer *buf, int *err, gchar **err_info)
{
    gint8                *pd;
	gchar                cbuff[WTAP_MAX_PACKET_SIZE];

	if(file_eof(fh)) {
		return FALSE;
	}
	file_gets(cbuff,WTAP_MAX_PACKET_SIZE,fh);

    buffer_assure_space(buf, strlen(cbuff)+1);
    pd = buffer_start_ptr(buf);

	memcpy(pd,cbuff,strlen(cbuff)+1);

    phdr->presence_flags = 0;
    phdr->ts.secs = (time_t) 0;
    phdr->ts.nsecs = (int) 0;
    phdr->caplen = strlen(cbuff);
    phdr->len = strlen(cbuff);
/*    phdr->pseudo_header.logcat.version = logcat->version; */

    return TRUE;
}

static gboolean logcat_text_brief_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset)
{
    *data_offset = file_tell(wth->fh);

    return logcat_text_brief_read_packet((struct logcat_phdr *) wth->priv, wth->fh,
        &wth->phdr, wth->frame_buffer, err, err_info);
}

static gboolean logcat_text_brief_seek_read(wtap *wth, gint64 seek_off,
    struct wtap_pkthdr *phdr, Buffer *buf,
    int *err, gchar **err_info)
{
    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
        return FALSE;

    if (!logcat_text_brief_read_packet((struct logcat_phdr *) wth->priv, wth->random_fh,
         phdr, buf, err, err_info)) {
        if (*err == 0)
            *err = WTAP_ERR_SHORT_READ;
        return FALSE;
    }
    return TRUE;
}

int logcat_text_brief_open(wtap *wth, int *err, gchar **err_info)
{
	gchar cbuff[WTAP_MAX_PACKET_SIZE];

	if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
	return -1;

	do {
		file_gets(cbuff,WTAP_MAX_PACKET_SIZE, wth->fh);
	}while (g_regex_match_simple("[-]+\\sbeginning\\sof\\s\\/",cbuff,0,0));

	if(!g_regex_match_simple("[IVDWE]/.*\\(\\s*[0-9]*\\):\\s.*",cbuff,0,0)) {
		return -1;
	}

	if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
	return -1;

	wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_LOGCAT_BRIEF;
	wth->file_encap = WTAP_ENCAP_LOGCAT_BRIEF;
	wth->snapshot_length = 0;

	wth->subtype_read = logcat_text_brief_read;
	wth->subtype_seek_read = logcat_text_brief_seek_read;
	wth->tsprecision = WTAP_FILE_TSPREC_USEC;
	fprintf(stderr,"go\n");
	return 1;
}

int logcat_text_brief_dump_can_write_encap(int encap)
{
    if (encap == WTAP_ENCAP_PER_PACKET)
        return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;

    if (encap != WTAP_ENCAP_LOGCAT)
        return WTAP_ERR_UNSUPPORTED_ENCAP;

    return 0;
}

static gboolean logcat_text_brief_binary_dump(wtap_dumper *wdh,
    const struct wtap_pkthdr *phdr,
    const guint8 *pd, int *err)
{
    if (!wtap_dump_file_write(wdh, pd, phdr->caplen, err))
        return FALSE;

    wdh->bytes_dumped += phdr->caplen;

    return TRUE;
}

gboolean logcat_text_brief_binary_dump_open(wtap_dumper *wdh, int *err)
{
    wdh->subtype_write = logcat_text_brief_binary_dump;
    wdh->subtype_close = NULL;

    switch (wdh->file_type_subtype) {
        case WTAP_FILE_TYPE_SUBTYPE_LOGCAT:
            wdh->tsprecision = WTAP_FILE_TSPREC_USEC;
            break;

        default:
            *err = WTAP_ERR_UNSUPPORTED_FILE_TYPE;
            return FALSE;
    }

    return TRUE;
}

static gboolean logcat_text_brief_dump_text(wtap_dumper *wdh,
    const struct wtap_pkthdr *phdr,
    const guint8 *pd, int *err)
{
    gchar                          *buf;
    gint                            length;
    gchar                           priority;
    const gchar                    *tag;
    const gint                     *pid;
    const gint                     *tid;
    const gchar                    *log;
    gchar                          *log_part;
    const gchar                    *str_begin;
    const gchar                    *str_end;
    const guint32                  *datetime;
    const guint32                  *nanoseconds;
    const union wtap_pseudo_header *pseudo_header = &phdr->pseudo_header;
    const struct dumper_t          *dumper        = (const struct dumper_t *) wdh->priv;

    if (pseudo_header->logcat.version == 1) {
        pid = (const gint *) (pd + 4);
        tid = (const gint *) (pd + 2 * 4);
        datetime = (const guint32 *) (pd + 3 * 4);
        nanoseconds = (const guint32 *) (pd + 4 * 4);
        priority = get_priority((const guint8 *) (pd + 5 * 4));
        tag = (const gchar *) (pd + 5 * 4 + 1);
        log = tag + strlen(tag) + 1;
    } else if (pseudo_header->logcat.version == 2) {
        pid = (const gint *) (pd + 4);
        tid = (const gint *) (pd + 2 * 4);
        datetime = (const guint32 *) (pd + 3 * 4);
        nanoseconds = (const guint32 *) (pd + 4 * 4);
        priority = get_priority((const guint8 *) (pd + 6 * 4));
        tag = (const char *) (pd + 6 * 4 + 1);
        log = tag + strlen(tag) + 1;
    } else {
        *err = WTAP_ERR_UNSUPPORTED;
        return FALSE;
    }

    str_begin = str_end = log;
    while (dumper->type != DUMP_LONG && (str_end = strchr(str_begin, '\n'))) {
        log_part = (gchar *) g_malloc(str_end - str_begin + 1);
        g_strlcpy(log_part, str_begin, str_end - str_begin);
        log_part[str_end - str_begin] = '\0';
        str_begin = str_end + 1;

        buf = logcat_text_brief_log(dumper, *datetime, *nanoseconds / 1000000, *pid, *tid,
                priority, tag, log_part);
        if (!buf) {
            g_free(log_part);
            return FALSE;
        }
        g_free(log_part);
        length = (guint32)strlen(buf);

        if (!wtap_dump_file_write(wdh, buf, length, err)) {
            g_free(buf);
            return FALSE;
        }

        wdh->bytes_dumped += length;

        g_free(buf);
    }

    if (*str_begin != '\0') {
        log_part = (gchar *) g_malloc(strlen(str_begin) + 1);
        g_strlcpy(log_part, str_begin, strlen(str_begin));
        log_part[strlen(str_begin)] = '\0';

        buf = logcat_text_brief_log(dumper, *datetime, *nanoseconds / 1000000, *pid, *tid,
                priority, tag, log_part);
        if (!buf) {
            g_free(log_part);
            return FALSE;
        }
        g_free(log_part);
        length = (guint32)strlen(buf);

        if (!wtap_dump_file_write(wdh, buf, length, err)) {
            g_free(buf);
            return FALSE;
        }

        wdh->bytes_dumped += length;
        g_free(buf);
    }

    return TRUE;
}

gboolean logcat_text_brief_text_brief_dump_open(wtap_dumper *wdh, int *err _U_)
{
    struct dumper_t *dumper;

    dumper = (struct dumper_t *) g_malloc(sizeof(struct dumper_t));
    dumper->type = DUMP_BRIEF;

    wdh->priv = dumper;
    wdh->subtype_write = logcat_text_brief_dump_text;
    wdh->subtype_close = NULL;

    return TRUE;
}

gboolean logcat_text_brief_text_process_dump_open(wtap_dumper *wdh, int *err _U_)
{
    struct dumper_t *dumper;

    dumper = (struct dumper_t *) g_malloc(sizeof(struct dumper_t));
    dumper->type = DUMP_PROCESS;

    wdh->priv = dumper;
    wdh->subtype_write = logcat_text_brief_dump_text;
    wdh->subtype_close = NULL;

    return TRUE;
}

gboolean logcat_text_brief_text_tag_dump_open(wtap_dumper *wdh, int *err _U_)
{
    struct dumper_t *dumper;

    dumper = (struct dumper_t *) g_malloc(sizeof(struct dumper_t));
    dumper->type = DUMP_TAG;

    wdh->priv = dumper;
    wdh->subtype_write = logcat_text_brief_dump_text;
    wdh->subtype_close = NULL;

    return TRUE;
}

gboolean logcat_text_brief_text_time_dump_open(wtap_dumper *wdh, int *err _U_)
{
    struct dumper_t *dumper;

    dumper = (struct dumper_t *) g_malloc(sizeof(struct dumper_t));
    dumper->type = DUMP_TIME;

    wdh->priv = dumper;
    wdh->subtype_write = logcat_text_brief_dump_text;
    wdh->subtype_close = NULL;

    return TRUE;
}

gboolean logcat_text_brief_text_thread_dump_open(wtap_dumper *wdh, int *err _U_)
{
    struct dumper_t *dumper;

    dumper = (struct dumper_t *) g_malloc(sizeof(struct dumper_t));
    dumper->type = DUMP_THREAD;

    wdh->priv = dumper;
    wdh->subtype_write = logcat_text_brief_dump_text;
    wdh->subtype_close = NULL;

    return TRUE;
}

gboolean logcat_text_brief_text_threadtime_dump_open(wtap_dumper *wdh, int *err _U_)
{
    struct dumper_t *dumper;

    dumper = (struct dumper_t *) g_malloc(sizeof(struct dumper_t));
    dumper->type = DUMP_THREADTIME;

    wdh->priv = dumper;
    wdh->subtype_write = logcat_text_brief_dump_text;
    wdh->subtype_close = NULL;

    return TRUE;
}

gboolean logcat_text_brief_text_long_dump_open(wtap_dumper *wdh, int *err _U_)
{
    struct dumper_t *dumper;

    dumper = (struct dumper_t *) g_malloc(sizeof(struct dumper_t));
    dumper->type = DUMP_LONG;

    wdh->priv = dumper;
    wdh->subtype_write = logcat_text_brief_dump_text;
    wdh->subtype_close = NULL;

    return TRUE;
}

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
