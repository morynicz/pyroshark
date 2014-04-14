/* extdumpcap.h
 * Extdumpcap is extcap tool
 *
 * Copyright 2014, Michal Labedzki for Tieto Corporation
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

/*------------------------------------------------------------------------------
TODO:
1. Try to detect that *fifo is closed, than die
2. Add dissectors for udev-monitor and fanotify, also fix logcat dissector to support logcat events
3. Stabilize interfaces
4. Split interfaces to separated executables or
   like busybox argv[0] has prefix "inotify" then show only infotify interface
   It will be useful for "generic interfaces" like "inotify", so user can simple
   copy binary to have additional interface. On the other side is specified 
   interfaces like Android Logcats" where this is useless
5. Using "exported_pdu" aka "Upper PDU" is ok?

------------------------------------------------------------------------------*/

#define _GNU_SOURCE     /* Needed to get O_LARGEFILE definition for FANOTIFY */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>

#include <errno.h>

#include <sys/sysinfo.h>
#include <arpa/inet.h>
#include <linux/netlink.h>

#include <pcap.h>
#include <pcap-bpf.h>
#include <pcap/bluetooth.h>

#define INTERFACE_BLUETOOTH_BLUEDROID     "bluetooth-bluedroid"
#define INTERFACE_ANDROID_LOGCAT_MAIN     "android-logcat-main"
#define INTERFACE_ANDROID_LOGCAT_SYSTEM   "android-logcat-system"
#define INTERFACE_ANDROID_LOGCAT_RADIO    "android-logcat-radio"
#define INTERFACE_ANDROID_LOGCAT_EVENTS   "android-logcat-events"
#define INTERFACE_LINUX_KMSG              "linux-kmsg"
#define INTERFACE_LINUX_BLUETOOTH_MONITOR "bluetooth-monitor"
#define INTERFACE_LINUX_UDEV_MONITOR      "udev-monitor"
#define INTERFACE_LINUX_FANOTIFY          "fanotify"
#define INTERFACE_LINUX_INOTIFY           "inotify"

#define VERSION_MAJOR    0
#define VERSION_MINOR    1
#define VERSION_RELEASE  0

#define PACKET_LENGTH 65535

#define HAVE_FANOTIFY

/*----------------------------------------------------------------------------*/
/* NOTE: internal, should not to be used by interfaces */
/*----------------------------------------------------------------------------*/

enum {
    OPT_HELP = 1,
    OPT_VERSION,
    OPT_LIST_INTERFACES,
    OPT_LIST_DLTS,
    OPT_INTERFACE,
    OPT_CONFIG,
    OPT_CAPTURE,
    OPT_FIFO,
    OPT_CONFIG_SERVER_IP,
    OPT_CONFIG_SERVER_TCP_PORT,
    OPT_CONFIG_LOCAL_TCP_PORT,
    OPT_CONFIG_PATH
};

static struct option longopts[] = {
    { "help",              no_argument,       NULL, OPT_HELP},
    { "version",           no_argument,       NULL, OPT_VERSION},
    { "extcap-interfaces", no_argument,       NULL, OPT_LIST_INTERFACES},
    { "extcap-dlts",       no_argument,       NULL, OPT_LIST_DLTS},
    { "extcap-interface",  required_argument, NULL, OPT_INTERFACE},
    { "extcap-config",     no_argument,       NULL, OPT_CONFIG},
    { "capture",           no_argument,       NULL, OPT_CAPTURE},
    { "fifo",              required_argument, NULL, OPT_FIFO},
    { "server-ip",         required_argument, NULL, OPT_CONFIG_SERVER_IP},
    { "server-tcp-port",   required_argument, NULL, OPT_CONFIG_SERVER_TCP_PORT},
    { "local-tcp-port",    required_argument, NULL, OPT_CONFIG_LOCAL_TCP_PORT},
    { "path",              required_argument, NULL, OPT_CONFIG_PATH},
    { 0, 0, 0, 0 }
};

/*----------------------------------------------------------------------------*/
/* NOTE: common */
/*----------------------------------------------------------------------------*/

struct interface_t {
    char                *display_name;
    char                *interface_name;
    struct interface_t  *next;
};

struct exported_pdu_header {
    uint16_t  tag;
    uint16_t  length;
/*  unsigned char value[0]; */
};

static int verbose = 0;

static inline int is_specified_interface(char *interface, char *interface_prefix) {
    return !strncmp(interface, interface_prefix, strlen(interface_prefix));
}

/*----------------------------------------------------------------------------*/
/* Kmsg */
/*----------------------------------------------------------------------------*/

static time_t get_boot_time()
{
    struct sysinfo  info;
    struct timeval  tv;

    if (sysinfo(&info) != 0)
        return 0;

    if (gettimeofday(&tv, NULL) != 0)
        return 0;

    return tv.tv_sec - info.uptime;
}


static int capture_linux_kmsg(char *fifo) {
    pcap_t               *pcap;
    pcap_dumper_t        *dumper;
    struct pcap_pkthdr    pcap_header;
    int                   fd_kmsg;
    static const char    *device_kmsg = "/dev/kmsg";
    static unsigned char  buffer[PACKET_LENGTH];
    static const char    *wireshark_protocol_linux_kmsg = "linux_kmsg";
    int                   exported_pdu_headers_size = 0;
    struct pcap_pkthdr    pkth;
    ssize_t               length;
    time_t                ts;
    int                   i;
    int                   i_char;
    int                   start_i;
    uint64_t              multiplier = 1;

    struct exported_pdu_header exported_pdu_header_protocol;
    struct exported_pdu_header exported_pdu_header_end = {0, 0};

    pcap = pcap_open_dead(DLT_WIRESHARK_UPPER_PDU, PACKET_LENGTH);
    dumper = pcap_dump_open(pcap, fifo);
    pcap_dump_flush(dumper);

    exported_pdu_header_protocol.tag = htons(0x000C);
    exported_pdu_header_protocol.length = htons(strlen(wireshark_protocol_linux_kmsg) + 2);

    fd_kmsg = open(device_kmsg, O_RDONLY);
    if (fd_kmsg == -1) {
        printf("ERROR: Cannot open /dev/kmsg: %s\n",
            pcap_strerror(errno));
        return -1;
    }

    if (!read(fd_kmsg, buffer, PACKET_LENGTH) && errno == EINVAL) {
        printf("ERROR: Cannot read /dev/kmsg: %s\n",
            pcap_strerror(errno));
        return -1;
    } else {
        lseek(fd_kmsg, 0, SEEK_DATA);
    }

    memcpy(buffer + exported_pdu_headers_size, &exported_pdu_header_protocol, sizeof(struct exported_pdu_header));
    exported_pdu_headers_size += sizeof(struct exported_pdu_header);

    memcpy(buffer + exported_pdu_headers_size, wireshark_protocol_linux_kmsg, ntohs(exported_pdu_header_protocol.length) - 2);
    exported_pdu_headers_size += ntohs(exported_pdu_header_protocol.length);

    buffer[exported_pdu_headers_size - 1] = 0;
    buffer[exported_pdu_headers_size - 2] = 0;

    memcpy(buffer + exported_pdu_headers_size, &exported_pdu_header_end, sizeof(struct exported_pdu_header));
    exported_pdu_headers_size += sizeof(struct exported_pdu_header) + ntohs(exported_pdu_header_end.length);

    while (1) {
        errno = 0;
        length = read(fd_kmsg, buffer + exported_pdu_headers_size, PACKET_LENGTH - exported_pdu_headers_size);
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EPIPE) continue;
        else if (errno != 0) {
            printf("ERROR capture: %s\n", strerror(errno));
            return 100;
        }

        if (length <= 0) continue;

        i = exported_pdu_headers_size;

        pcap_header.caplen = exported_pdu_headers_size + length;
        pcap_header.len = exported_pdu_headers_size + length;

        /* skip priority */
        while (i + 1 <= length && buffer[i] != ',')
        {
            i += 1;
        }
        i += 1;

        /* skip sequence number */
        while (i + 1 <= length && buffer[i] != ',')
        {
            i += 1;
        }
        i += 1;

        /* get timestamp */
        start_i = i;
        while (i + 1 <= length && buffer[i] != ',')
        {
            i += 1;
        }

        /* get timestamp - microseconds */
        pkth.ts.tv_usec = 0;
        multiplier = 1;
        for (i_char = i - 1; i_char >= start_i && i_char >  i - 1 - 6  ; i_char -= 1)
        {

            pkth.ts.tv_usec += (buffer[i_char] - 0x30) * multiplier;
            multiplier *= 10;
        }

        /* get timestamp - seconds */
        pkth.ts.tv_sec = 0;
        multiplier  = 1;
        for (; i_char >= start_i ; i_char -= 1)
        {
            pkth.ts.tv_sec += (buffer[i_char] - 0x30) * multiplier;
            multiplier *= 10;
        }

        /* try to get real system datetime */
        ts = get_boot_time();
        pkth.ts.tv_sec += ts;

        pcap_dump((u_char *)dumper, &pcap_header, buffer);
        pcap_dump_flush(dumper);
    }

    return 0;
}

/*----------------------------------------------------------------------------*/
/* Bluetooth Monitor */
/*----------------------------------------------------------------------------*/

/* Start of copy of unexported Linux Kernel headers */

#ifndef AF_BLUETOOTH
#define AF_BLUETOOTH    31
#endif

#define BTPROTO_HCI 1

#define HCI_CHANNEL_MONITOR 2

#define HCI_DEV_NONE    0xffff

struct sockaddr_hci {
    sa_family_t    hci_family;
    unsigned short hci_dev;
    unsigned short hci_channel;
};

struct mgmt_hdr {
    uint16_t  opcode;
    uint16_t  index;
    uint16_t  len;
};

#define MGMT_HDR_SIZE   sizeof(struct mgmt_hdr)
/* End of copy of unexported Linux Kernel headers */

#ifndef DLT_BLUETOOTH_HCI_H4_WITH_PHDR
#define DLT_BLUETOOTH_HCI_H4_WITH_PHDR  201
#endif

/* Start of copy of LIBPCAP headers */
typedef struct _own_pcap_bluetooth_h4_header {
    u_int32_t direction; /* if first bit is set direction is incoming */
} own_pcap_bluetooth_h4_header;

#ifndef DLT_BLUETOOTH_LINUX_MONITOR
#define DLT_BLUETOOTH_LINUX_MONITOR 254
#endif


typedef struct _own_pcap_bluetooth_linux_monitor_header {
    u_int16_t adapter_id;
    u_int16_t opcode;
} own_pcap_bluetooth_linux_monitor_header;
/* End of copy of LIBPCAP headers */

#define BT_CONTROL_SIZE 32


static int capture_linux_bluetooth_monitor(char *fifo) {
    static unsigned char buffer[PACKET_LENGTH];
    pcap_t              *pcap;
    pcap_dumper_t       *dumper;
    struct pcap_pkthdr   pcap_header;
    int                  sock;
    struct sockaddr_hci  addr;
    int                  opt = 1;
    struct cmsghdr      *cmsg;
    struct msghdr        msg;
    struct mgmt_hdr      hdr;
    struct iovec         iv[2];
    ssize_t              ret;
    own_pcap_bluetooth_linux_monitor_header *bthdr;

    pcap = pcap_open_dead_with_tstamp_precision(DLT_BLUETOOTH_LINUX_MONITOR, PACKET_LENGTH, PCAP_TSTAMP_PRECISION_MICRO);
    dumper = pcap_dump_open(pcap, fifo);
    pcap_dump_flush(dumper);

    sock = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
    if (sock < 0) {
        printf("ERROR: Cannot create raw socket: %s", strerror(errno));
        return 1;
    }

    addr.hci_family = AF_BLUETOOTH;
    addr.hci_dev = HCI_DEV_NONE;
    addr.hci_channel = HCI_CHANNEL_MONITOR;

    if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        printf("ERROR: Cannot attach to interface: %s", strerror(errno));
        return 2;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_TIMESTAMP, &opt, sizeof(opt)) < 0) {
        printf("ERROR: Cannot enable time stamp: %s", strerror(errno));
        return 3;
    }

    bthdr = (own_pcap_bluetooth_linux_monitor_header*) &buffer[BT_CONTROL_SIZE];

    iv[0].iov_base = &hdr;
    iv[0].iov_len = MGMT_HDR_SIZE;
    iv[1].iov_base = &buffer[BT_CONTROL_SIZE + sizeof(own_pcap_bluetooth_linux_monitor_header)];
    iv[1].iov_len = PACKET_LENGTH;

    memset(&pcap_header.ts, 0, sizeof(pcap_header.ts));
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = iv;
    msg.msg_iovlen = 2;
    msg.msg_control = buffer;
    msg.msg_controllen = BT_CONTROL_SIZE;

    while(1) {
        ret = recvmsg(sock, &msg, 0);
        if (((ret == -1) && (errno == EINTR))) continue;

        pcap_header.caplen = ret - MGMT_HDR_SIZE + sizeof(own_pcap_bluetooth_linux_monitor_header);
        pcap_header.len = pcap_header.caplen;

        for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            if (cmsg->cmsg_level != SOL_SOCKET) continue;

            if (cmsg->cmsg_type == SCM_TIMESTAMP) {
                memcpy(&pcap_header.ts, CMSG_DATA(cmsg), sizeof(pcap_header.ts));
            }
        }

        bthdr->adapter_id = htons(hdr.index);
        bthdr->opcode = htons(hdr.opcode);

        pcap_dump((u_char *)dumper, &pcap_header, buffer + BT_CONTROL_SIZE);
        pcap_dump_flush(dumper);

    }

    if (ret < 0) {
        printf("ERROR: Cannot receive packet: %s", strerror(errno));
        return 4;
    }

    return 0;
}

/*----------------------------------------------------------------------------*/
/* Udev */
/*----------------------------------------------------------------------------*/

static int capture_linux_udev_monitor(char *fifo) {
    int                         sock;
    struct sockaddr_nl          addr;
    static unsigned char        buffer[PACKET_LENGTH];
    pcap_t                     *pcap;
    pcap_dumper_t              *dumper;
    struct pcap_pkthdr          pcap_header;
    int                         exported_pdu_headers_size = 0;
    int                         length;
    const int                   opt = 1;
    struct exported_pdu_header  exported_pdu_header_protocol;
    struct exported_pdu_header  exported_pdu_header_end = {0, 0};
    static const char          *wireshark_protocol_data_text = "data-text-lines";

    pcap = pcap_open_dead_with_tstamp_precision(DLT_WIRESHARK_UPPER_PDU, PACKET_LENGTH, PCAP_TSTAMP_PRECISION_NANO);
    dumper = pcap_dump_open(pcap, fifo);
    pcap_dump_flush(dumper);

    exported_pdu_header_protocol.tag = htons(0x000C);
    exported_pdu_header_protocol.length = htons(strlen(wireshark_protocol_data_text) + 2);

    memset(&addr, 0x00, sizeof(struct sockaddr_nl));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    addr.nl_groups = 1;

    sock = socket(PF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_KOBJECT_UEVENT);
    if (sock < 0) {
        printf("ERROR: Cannot open system NETLINK socket: %s\n", strerror(errno));
        return 1;
    }

    if (bind(sock, (struct sockaddr *) &addr, sizeof(struct sockaddr_nl)) == -1) {
        printf("ERROR: Cannot bind to udev socket: %s\n", strerror(errno));
        return 2;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_PASSCRED, &opt, sizeof(opt)) == -1) {
        printf("ERROR: Cannot setsockopt to udev socket: %s\n", strerror(errno));
        return 2;
    }

    memcpy(buffer + exported_pdu_headers_size, &exported_pdu_header_protocol, sizeof(struct exported_pdu_header));
    exported_pdu_headers_size += sizeof(struct exported_pdu_header);

    memcpy(buffer + exported_pdu_headers_size, wireshark_protocol_data_text, ntohs(exported_pdu_header_protocol.length) - 2);
    exported_pdu_headers_size += ntohs(exported_pdu_header_protocol.length);

    buffer[exported_pdu_headers_size - 1] = 0;
    buffer[exported_pdu_headers_size - 2] = 0;

    memcpy(buffer + exported_pdu_headers_size, &exported_pdu_header_end, sizeof(struct exported_pdu_header));
    exported_pdu_headers_size += sizeof(struct exported_pdu_header) + ntohs(exported_pdu_header_end.length);

    while (1) {
        errno = 0;
        length = recv(sock, buffer + exported_pdu_headers_size,  PACKET_LENGTH - exported_pdu_headers_size , 0);
        if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
        else if (errno != 0) {
            printf("ERROR capture: %s\n", strerror(errno));
            return 100;
        }

        if (length <= 0) continue;

        pcap_header.caplen = exported_pdu_headers_size + length;
        pcap_header.len = exported_pdu_headers_size + length;
        gettimeofday(&pcap_header.ts, NULL);

        pcap_dump((u_char *)dumper, &pcap_header, buffer);
        pcap_dump_flush(dumper);
    }

    return 0;
}


/*----------------------------------------------------------------------------*/
/* Linux Fanotify */
/*----------------------------------------------------------------------------*/
#ifdef HAVE_FANOTIFY

#include <sys/fanotify.h>
#include <fcntl.h>

#define FANOTIFY_EVENT_SIZE 24

static int capture_linux_fanotify(char *fifo, char *path) {
    unsigned char                  buffer[PACKET_LENGTH];
    int                            length;
    int                            used_buffer_length = 0;
    int                            fd_fanotify;
    pcap_t                        *pcap;
    pcap_dumper_t                 *dumper;
    struct pcap_pkthdr             pcap_header;
    uint32_t                      *length_event;
    int                            exported_pdu_headers_size = 0;
    struct exported_pdu_header     exported_pdu_header_protocol;
    struct exported_pdu_header     exported_pdu_header_end = {0, 0};
    static const char             *wireshark_protocol_fanotify = "fanotify";

    pcap = pcap_open_dead_with_tstamp_precision(DLT_WIRESHARK_UPPER_PDU, PACKET_LENGTH, PCAP_TSTAMP_PRECISION_NANO);
    dumper = pcap_dump_open(pcap, fifo);
    pcap_dump_flush(dumper);

    if (!path)
        path = ".";

    exported_pdu_header_protocol.tag = htons(0x000C);
    exported_pdu_header_protocol.length = htons(strlen(wireshark_protocol_fanotify) + 2);

    memcpy(buffer + exported_pdu_headers_size, &exported_pdu_header_protocol, sizeof(struct exported_pdu_header));
    exported_pdu_headers_size += sizeof(struct exported_pdu_header);

    memcpy(buffer + exported_pdu_headers_size, wireshark_protocol_fanotify, ntohs(exported_pdu_header_protocol.length) - 2);
    exported_pdu_headers_size += ntohs(exported_pdu_header_protocol.length);

    buffer[exported_pdu_headers_size - 1] = 0;
    buffer[exported_pdu_headers_size - 2] = 0;

    memcpy(buffer + exported_pdu_headers_size, &exported_pdu_header_end, sizeof(struct exported_pdu_header));
    exported_pdu_headers_size += sizeof(struct exported_pdu_header) + ntohs(exported_pdu_header_end.length);

    length_event = (uint32_t *) (buffer + exported_pdu_headers_size);
    fd_fanotify = fanotify_init(FAN_CLOEXEC | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS /*| FAN_CLASS_CONTENT */ /*| FAN_NONBLOCK*/, O_RDONLY | O_LARGEFILE);
    if (fd_fanotify == -1) {
        printf("ERROR: init fd_fanotify=%i: %s", fd_fanotify, strerror(errno));
        return 1;
    }

    if (fanotify_mark(fd_fanotify, FAN_MARK_ADD | FAN_MARK_MOUNT,
            FAN_CLOSE | FAN_ACCESS | FAN_MODIFY | FAN_OPEN | FAN_ONDIR  | FAN_EVENT_ON_CHILD , -1,
            path) == -1) {
        printf("ERROR: mark");
        return 2;
    }

    while(1) {
        errno = 0;
        length = read(fd_fanotify, buffer + exported_pdu_headers_size + used_buffer_length, PACKET_LENGTH - exported_pdu_headers_size - used_buffer_length);
        if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
        else if (errno != 0 && errno != 75) {
            printf("ERROR capture: %s\n", strerror(errno));
            return 100;
        }

        if (errno != 0)
            printf("WARNING capture: %s\n", strerror(errno));

        if (length <= 0) continue;

        used_buffer_length += length;

        while (used_buffer_length >=  FANOTIFY_EVENT_SIZE && *length_event <= (uint32_t) used_buffer_length) {
            length = *length_event;
            pcap_header.caplen = exported_pdu_headers_size + length;
            pcap_header.len = exported_pdu_headers_size + length;
            gettimeofday(&pcap_header.ts, NULL);

            pcap_dump((u_char *)dumper, &pcap_header, buffer);
            pcap_dump_flush(dumper);

            used_buffer_length -= length;
            memmove(buffer + exported_pdu_headers_size, buffer + exported_pdu_headers_size + length, used_buffer_length);
        }
    }

    return 0;
}

#endif

/*----------------------------------------------------------------------------*/
/* Linux inotify */
/*----------------------------------------------------------------------------*/
#include <sys/inotify.h>

#define INOTIFY_EVENT_SIZE 16

static int capture_linux_inotify(char *fifo, char *path) {
    unsigned char                  buffer[PACKET_LENGTH];
    int                            length;
    int                            used_buffer_length = 0;
    int                            fd_inotify;
    pcap_t                        *pcap;
    pcap_dumper_t                 *dumper;
    struct pcap_pkthdr             pcap_header;
    uint32_t                      *length_name;
    int                            exported_pdu_headers_size = 0;
    struct exported_pdu_header     exported_pdu_header_protocol;
    struct exported_pdu_header     exported_pdu_header_end = {0, 0};
    static const char             *wireshark_protocol_inotify = "inotify";

    pcap = pcap_open_dead_with_tstamp_precision(DLT_WIRESHARK_UPPER_PDU, PACKET_LENGTH, PCAP_TSTAMP_PRECISION_NANO);
    dumper = pcap_dump_open(pcap, fifo);
    pcap_dump_flush(dumper);

    if (!path)
        path = ".";

    exported_pdu_header_protocol.tag = htons(0x000C);
    exported_pdu_header_protocol.length = htons(strlen(wireshark_protocol_inotify) + 2);

    memcpy(buffer + exported_pdu_headers_size, &exported_pdu_header_protocol, sizeof(struct exported_pdu_header));
    exported_pdu_headers_size += sizeof(struct exported_pdu_header);

    memcpy(buffer + exported_pdu_headers_size, wireshark_protocol_inotify, ntohs(exported_pdu_header_protocol.length) - 2);
    exported_pdu_headers_size += ntohs(exported_pdu_header_protocol.length);

    buffer[exported_pdu_headers_size - 1] = 0;
    buffer[exported_pdu_headers_size - 2] = 0;

    memcpy(buffer + exported_pdu_headers_size, &exported_pdu_header_end, sizeof(struct exported_pdu_header));
    exported_pdu_headers_size += sizeof(struct exported_pdu_header) + ntohs(exported_pdu_header_end.length);

    length_name = (uint32_t *) (buffer + exported_pdu_headers_size + 12);
    fd_inotify = inotify_init1(IN_CLOEXEC);
    if (fd_inotify == -1) {
        printf("ERROR: init fd_inotify=%i: %s\n", fd_inotify, strerror(errno));
        return 1;
    }

    if (inotify_add_watch(fd_inotify, path, IN_ALL_EVENTS) == -1) {
        printf("ERROR: inotify_add_watch: %s\n", strerror(errno));
        return 2;
    }

    while(1) {
        errno = 0;
        length = read(fd_inotify, buffer + exported_pdu_headers_size + used_buffer_length, PACKET_LENGTH - exported_pdu_headers_size - used_buffer_length);
        if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
        else if (errno != 0) {
            printf("ERROR capture: %s\n", strerror(errno));
            return 100;
        }
        if (length <= 0) continue;

        used_buffer_length += length;

        while (used_buffer_length >=  INOTIFY_EVENT_SIZE && INOTIFY_EVENT_SIZE + *length_name <= (uint32_t) used_buffer_length) {
            length = INOTIFY_EVENT_SIZE + *length_name;
            pcap_header.caplen = exported_pdu_headers_size + length;
            pcap_header.len = exported_pdu_headers_size + length;
            gettimeofday(&pcap_header.ts, NULL);

            pcap_dump((u_char *)dumper, &pcap_header, buffer);
            pcap_dump_flush(dumper);

            used_buffer_length -= INOTIFY_EVENT_SIZE + *length_name;
            memmove(buffer + exported_pdu_headers_size, buffer + exported_pdu_headers_size + length, used_buffer_length);
        }
    }

    return 0;
}


/*----------------------------------------------------------------------------*/
/* Logger / Logcat */
/*----------------------------------------------------------------------------*/

static int capture_android_logcat(char *interface, char *fifo,
        char *server_ip, unsigned short *server_tcp_port) {
    static unsigned char        packet[PACKET_LENGTH];
    int                         length;
    int                         used_buffer_length = 0;
    int                         sock;
    struct sockaddr_in          server;
    char                       *default_server_ip = "127.0.0.1";
    unsigned short              default_server_tcp_port = 5037;
    pcap_t                     *pcap;
    pcap_dumper_t              *dumper;
    struct pcap_pkthdr          pcap_header;
    const char                 *protocol_name;
    int                         exported_pdu_headers_size = 0;
    struct exported_pdu_header  exported_pdu_header_protocol_events;
    struct exported_pdu_header  exported_pdu_header_protocol_normal;
    struct exported_pdu_header *exported_pdu_header_protocol;
    struct exported_pdu_header  exported_pdu_header_end = {0, 0};
    static const char          *wireshark_protocol_logcat = "logcat";
    static const char          *wireshark_protocol_logcat_events = "logcat_events";
    char                       *adb_transport  = "0012""host:transport-any";
    char                       *adb_log_main   = "0008""log:main";
    char                       *adb_log_system = "000A""log:system";
    char                       *adb_log_radio  = "0009""log:radio";
    char                       *adb_log_events = "000A""log:events";
    char                       *adb_transport_serial_templace = "%04x""host:transport:%s";
    char                       *adb_command;
    uint16_t                   *payload_length;
    uint16_t                   *try_header_size;
    uint32_t                   *timestamp_secs;
    uint32_t                   *timestamp_nsecs;
    uint16_t                    header_size;
    int                         result;
    char                       *serial_number = NULL;

    pcap = pcap_open_dead_with_tstamp_precision(DLT_WIRESHARK_UPPER_PDU, PACKET_LENGTH, PCAP_TSTAMP_PRECISION_NANO);
    dumper = pcap_dump_open(pcap, fifo);
    pcap_dump_flush(dumper);

    if (!server_ip)
        server_ip = default_server_ip;

    if (!server_tcp_port)
        server_tcp_port = &default_server_tcp_port;

    exported_pdu_header_protocol_events.tag = htons(0x000C);
    exported_pdu_header_protocol_events.length = htons(strlen(wireshark_protocol_logcat_events) + 2);

    exported_pdu_header_protocol_normal.tag = htons(0x000C);
    exported_pdu_header_protocol_normal.length = htons(strlen(wireshark_protocol_logcat) + 2);

    if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        printf("ERROR: Cannot open system TCP socket: %s\n", strerror(errno));
        return 1;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(*server_tcp_port);
    server.sin_addr.s_addr = inet_addr(server_ip);

    if (connect(sock, (struct sockaddr *) &server, sizeof(server)) < 0) {
        printf("ERROR: %s\n", strerror(errno));
        printf("INFO: Please check that adb daemon is running.\n");
        return 2;
    }

    if (verbose) {
        struct sockaddr_in  client;

        length = sizeof(client);
        if (getsockname(sock, (struct sockaddr *) &client, (socklen_t *) &length)) {
            printf("ERROR getsockname: %s\n", strerror(errno));
            return 3;
        }

        if (length != sizeof(client)) {
            printf("ERROR: incorrect length\n");
            return 4;
        }

        printf("Client port %u\n", ntohs(client.sin_port));
    }

    if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_MAIN) && strlen(interface) > strlen(INTERFACE_ANDROID_LOGCAT_MAIN) + 1) {
        serial_number = interface + strlen(INTERFACE_ANDROID_LOGCAT_MAIN) + 1;
    } else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_SYSTEM) && strlen(interface) > strlen(INTERFACE_ANDROID_LOGCAT_SYSTEM) + 1) {
        serial_number = interface + strlen(INTERFACE_ANDROID_LOGCAT_SYSTEM) + 1;
    } else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_RADIO) && strlen(interface) > strlen(INTERFACE_ANDROID_LOGCAT_RADIO) + 1) {
        serial_number = interface + strlen(INTERFACE_ANDROID_LOGCAT_RADIO) + 1;
    } else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_EVENTS) && strlen(interface) > strlen(INTERFACE_ANDROID_LOGCAT_EVENTS) + 1) {
        serial_number = interface + strlen(INTERFACE_ANDROID_LOGCAT_EVENTS) + 1;
    }

    if (!serial_number) {
        result = send(sock, adb_transport, strlen(adb_transport), 0);
        if (result != (int) strlen(adb_transport)) {
            printf("ERROR: Error while connecting/sending by ADB\n");
            return 1;
        }

        result = recv(sock, packet,  PACKET_LENGTH, 0);
        if (result <= 0) {
            printf("ERROR: Error while connecting/receiving by ADB\n");
            return 1;
        }
    } else {
        sprintf((char *) packet, adb_transport_serial_templace, 15 + strlen(serial_number), serial_number);
        result = send(sock, packet, strlen(adb_transport_serial_templace) - 2 + strlen(serial_number), 0);

        if (result != (int) (strlen(adb_transport_serial_templace) - 2 + strlen(serial_number))) {
            printf("ERROR: Error while connecting/sending by ADB\n");
            return 1;
        }

        result = recv(sock, packet,  PACKET_LENGTH, 0);
        if (result < 4 || (result >= 4 && memcmp(packet, "OKAY", 4))) {
            printf("ERROR: Error while connecting/receiving by ADB\n");
            return 1;
        }
    }

    if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_MAIN))
        adb_command = adb_log_main;
    else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_SYSTEM))
        adb_command = adb_log_system;
    else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_RADIO))
        adb_command = adb_log_radio;
    else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_EVENTS))
        adb_command = adb_log_events;
    else {
        printf("ERROR: Unknown interface: <%s>\n", interface);
        return -1;
    }

    result = send(sock, adb_command, strlen(adb_command), 0);
    if (result != (int) strlen(adb_command)) {
        printf("ERROR: Error while connecting/sending by ADB\n");
        return 1;
    }

    result = recv(sock, packet,  PACKET_LENGTH, 0);
    if (result <= 0) {
        printf("ERROR: Error while connecting/receiving by ADB\n");
        return 1;
    }

    if (!memcpy(packet, "FAIL", 4)) {
        printf("ERROR: Cannot connect to device\n");
        return 1;
    }

    if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_EVENTS))
    {
        protocol_name = wireshark_protocol_logcat_events;
        exported_pdu_header_protocol = &exported_pdu_header_protocol_events;
    } else {
        protocol_name = wireshark_protocol_logcat;
        exported_pdu_header_protocol = &exported_pdu_header_protocol_normal;
    }

    memcpy(packet + exported_pdu_headers_size, exported_pdu_header_protocol, sizeof(struct exported_pdu_header));
    exported_pdu_headers_size += sizeof(struct exported_pdu_header);

    memcpy(packet + exported_pdu_headers_size, protocol_name, ntohs(exported_pdu_header_protocol->length) - 2);
    exported_pdu_headers_size += ntohs(exported_pdu_header_protocol->length);

    packet[exported_pdu_headers_size - 1] = 0;
    packet[exported_pdu_headers_size - 2] = 0;

    memcpy(packet + exported_pdu_headers_size, &exported_pdu_header_end, sizeof(struct exported_pdu_header));
    exported_pdu_headers_size += sizeof(struct exported_pdu_header) + ntohs(exported_pdu_header_end.length);

    payload_length  = (uint16_t *) &packet[exported_pdu_headers_size];
    try_header_size = (uint16_t *) &packet[exported_pdu_headers_size + 2];
    timestamp_secs  = (uint32_t *) &packet[exported_pdu_headers_size + 12];
    timestamp_nsecs = (uint32_t *) &packet[exported_pdu_headers_size + 16];

    while (1) {
        errno = 0;
        length = recv(sock, packet + exported_pdu_headers_size + used_buffer_length,  PACKET_LENGTH - exported_pdu_headers_size - used_buffer_length , 0);
        if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
        else if (errno != 0) {
            printf("ERROR capture: %s\n", strerror(errno));
            return 100;
        }

        if (length <= 0) {
            printf("WARNING: Broken socket connection. Try reconnect.\n");
            close(sock);

            if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
                printf("ERROR: Cannot open system TCP socket: %s\n", strerror(errno));
                return 1;
            }
            memset(&server, 0, sizeof(server));

            server.sin_family = AF_INET;
            server.sin_port = htons(5037);
            server.sin_addr.s_addr = inet_addr("127.0.0.1");

            if (connect(sock, (struct sockaddr *) &server, sizeof(server)) < 0) {
                printf("ERROR: %s\n", strerror(errno));
                printf("INFO: Please check that adb daemon is running.\n");
                return 2;
            }

            result = send(sock, adb_transport, strlen(adb_transport), 0);
            if (result != (int) strlen(adb_transport)) {
                printf("WARNING: Error while connecting/sending by ADB\n");
                continue;
            }

            result = recv(sock, packet,  PACKET_LENGTH, 0);
            if (result <= 0) {
                printf("WARNING: Error while connecting/receiving by ADB\n");
                continue;
            }

            if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_MAIN))
                adb_command = adb_log_main;
            else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_SYSTEM))
                adb_command = adb_log_system;
            else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_RADIO))
                adb_command = adb_log_radio;
            else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_EVENTS))
                adb_command = adb_log_events;
            else {
                printf("ERROR: Unknown interface: <%s>\n", interface);
                return 1;
            }

            result = send(sock, adb_command, strlen(adb_command), 0);
            if (result != (int) strlen(adb_command)) {
                printf("WARNING: Error while connecting/sending by ADB\n");
                continue;
            }

            result = recv(sock, packet,  PACKET_LENGTH, 0);
            if (result <= 0) {
                printf("WARNING: Error while connecting/receiving by ADB\n");
                continue;
            }

            if (!memcpy(packet, "FAIL", 4)) {
                printf("WARNING: Cannot connect to device\n");
                continue;
            }

            continue;
        }

        used_buffer_length += length + exported_pdu_headers_size;

        if (*try_header_size == 0 || *try_header_size != 24)
            header_size = 20;
        else
            header_size = *try_header_size;

        length = (*payload_length) + header_size +  exported_pdu_headers_size;

        while (used_buffer_length >= exported_pdu_headers_size + header_size && length <= used_buffer_length) {
            pcap_header.caplen = length;
            pcap_header.len = pcap_header.caplen;
            pcap_header.ts.tv_sec = *timestamp_secs;
            pcap_header.ts.tv_usec = *timestamp_nsecs;

            pcap_dump((u_char *)dumper, &pcap_header, packet);
            pcap_dump_flush(dumper);

            memmove(packet + exported_pdu_headers_size, packet + length, used_buffer_length - length);
            used_buffer_length -= length;
            used_buffer_length += exported_pdu_headers_size;


            length = (*payload_length) + header_size +  exported_pdu_headers_size;

            if (*try_header_size == 0 || *try_header_size != 24)
                header_size = 20;
            else
                header_size = *try_header_size;
        }
        used_buffer_length -= exported_pdu_headers_size;
    }

    return 0;
}

/*----------------------------------------------------------------------------*/
/* Bluedroid */
/*----------------------------------------------------------------------------*/

#define BLUEDROID_H4_PACKET_TYPE  0
#define BLUEDROID_TIMESTAMP_SIZE  8
#define BLUEDROID_H4_SIZE  1

static const uint64_t BLUEDROID_TIMESTAMP_BASE = 0x00dcddb30f2f8000UL;

#define BLUEDROID_H4_PACKET_TYPE_HCI_CMD  0x01
#define BLUEDROID_H4_PACKET_TYPE_ACL      0x02
#define BLUEDROID_H4_PACKET_TYPE_SCO      0x03
#define BLUEDROID_H4_PACKET_TYPE_HCI_EVT  0x04

#define BLUEDROID_DIRECTION_SENT  0
#define BLUEDROID_DIRECTION_RECV  1

static int adb_forward(unsigned short local_tcp_port, unsigned short server_tcp_port) {
    int                  sock;
    struct sockaddr_in   server = {0};
    static const char   *adb_transport = "0012""host:transport-any";
    static const char   *adb_forward_template = "0020""host:forward:tcp:%05u;tcp:%05u";
    char                 adb_forward[37];
    static unsigned char packet[PACKET_LENGTH];
    unsigned int         length;

    if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        return 1;

    server.sin_family = AF_INET;
    server.sin_port = htons(5037);
    server.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (snprintf(adb_forward, 37, adb_forward_template, local_tcp_port, server_tcp_port) < 36)
        return 2;

    if (connect(sock, (struct sockaddr *) &server, sizeof(server)) < 0)
        return 3;

    length = send(sock, adb_transport, strlen(adb_transport), 0);
    if (length != strlen(adb_transport))
        return 4;
/* TODO: Check answer */
    recv(sock, packet, PACKET_LENGTH, 0);

    send(sock, adb_forward, strlen(adb_forward), 0);
    if (length != strlen(adb_transport))
        return 5;
/* TODO: Check answer */
    recv(sock, packet, PACKET_LENGTH, 0);

    close(sock);
    return 0;
}


static int capture_bluetooth_bluedroid(char *fifo, char *server_ip,
        unsigned short *server_tcp_port, unsigned short *local_tcp_port) {
    unsigned char                  buffer[PACKET_LENGTH];
    uint64_t                      *timestamp = (uint64_t *) buffer;
    unsigned char                 *packet = buffer + BLUEDROID_TIMESTAMP_SIZE - sizeof(own_pcap_bluetooth_h4_header); /* skip timestamp (8 bytes) and reuse its space for header */
    own_pcap_bluetooth_h4_header  *h4_header = (own_pcap_bluetooth_h4_header *) packet;
    unsigned char                 *payload = packet + sizeof(own_pcap_bluetooth_h4_header);
    int                            length;
    int                            used_buffer_length = 0;
    uint64_t                       ts;
    int                            sock;
    struct sockaddr_in             server;
    char                          *default_server_ip = "127.0.0.1";
    unsigned short                 default_server_tcp_port = 4330;
    unsigned short                 default_local_tcp_port  = 4330; /* TODO: Temporary 4330, but should be 0 and parameter --local-tcp-port in use */
    pcap_t                        *pcap;
    pcap_dumper_t                 *dumper;
    struct pcap_pkthdr             pcap_header;

    pcap = pcap_open_dead(DLT_BLUETOOTH_HCI_H4_WITH_PHDR, PACKET_LENGTH);
    dumper = pcap_dump_open(pcap, fifo);
    pcap_dump_flush(dumper);

    if (!server_ip)
        server_ip = default_server_ip;

    if (!server_tcp_port)
        server_tcp_port = &default_server_tcp_port;

    if (!local_tcp_port)
        local_tcp_port = &default_local_tcp_port;

    if ((sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP)) < 0) {
        printf("ERROR: Cannot open system TCP socket: %s\n", strerror(errno));
        return 1;
    }

    printf("Using config: Server IP=%s, Server TCP Port=%u, Local TCP Port=%u\n",
            server_ip, *server_tcp_port, *local_tcp_port);

    if (*local_tcp_port != 0) {
        int result;

        result = adb_forward(*local_tcp_port, *server_tcp_port);
        printf("DO: adb forward tcp:%u (local) tcp:%u (remote) result=%i\n",
                *local_tcp_port, *server_tcp_port, result);
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(*local_tcp_port);
    server.sin_addr.s_addr = inet_addr(server_ip);

    if (connect(sock, (struct sockaddr *) &server, sizeof(server)) < 0) {
        printf("ERROR: %s\n", strerror(errno));
        printf("INFO: Please check that adb daemon is running.\n");
        return 2;
    }

    if (verbose) {
        struct sockaddr_in  client;

        length = sizeof(client);
        if (getsockname(sock, (struct sockaddr *) &client, (socklen_t *) &length)) {
            printf("ERROR getsockname: %s\n", strerror(errno));
            return 3;
        }

        if (length != sizeof(client)) {
            printf("ERROR: incorrect length\n");
            return 4;
        }

        printf("Client port %u\n", ntohs(client.sin_port));
    }

    while (1) {
        errno = 0;
        length = recv(sock, buffer + used_buffer_length,  PACKET_LENGTH - used_buffer_length, 0);
        if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
        else if (errno != 0) {
            printf("ERROR capture: %s\n", strerror(errno));
            return 100;
        }

        if (length <= 0) {
            /* NOTE: Workaround... It seems that Bluedroid is slower and we can connect to socket that are not really ready... */
            printf("WARNING: Broken socket connection. Try reconnect.\n");
            close(sock);

            if ((sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP)) < 0) {
                printf("ERROR1: %s\n", strerror(errno));
                return 1;
            }

            server.sin_family = AF_INET;
            server.sin_port = htons(*local_tcp_port);
            server.sin_addr.s_addr = inet_addr(server_ip);

            if (connect(sock, (struct sockaddr *) &server, sizeof(server)) < 0) {
                printf("ERROR reconnect: %s\n", strerror(errno));
                printf("INFO: Please check that adb daemon is running.\n");
                return 2;
            }

            continue;
        }

        used_buffer_length += length;

        if (verbose) printf("Received: length=%i\n", length);

        while (((payload[BLUEDROID_H4_PACKET_TYPE] == BLUEDROID_H4_PACKET_TYPE_HCI_CMD || payload[BLUEDROID_H4_PACKET_TYPE] == BLUEDROID_H4_PACKET_TYPE_SCO) &&
                    used_buffer_length >= BLUEDROID_TIMESTAMP_SIZE + BLUEDROID_H4_SIZE + 2 + 1 &&
                    BLUEDROID_TIMESTAMP_SIZE + BLUEDROID_H4_SIZE + 2 + payload[BLUEDROID_H4_SIZE + 2] + 1 <= used_buffer_length) ||
                (payload[BLUEDROID_H4_PACKET_TYPE] == BLUEDROID_H4_PACKET_TYPE_ACL &&
                    used_buffer_length >= BLUEDROID_TIMESTAMP_SIZE + BLUEDROID_H4_SIZE + 2 + 2 &&
                    BLUEDROID_TIMESTAMP_SIZE + BLUEDROID_H4_SIZE + 2 + payload[BLUEDROID_H4_SIZE + 2] + (payload[BLUEDROID_H4_SIZE + 2 + 1] << 8) + 2 <= used_buffer_length) ||
                (payload[BLUEDROID_H4_PACKET_TYPE] == BLUEDROID_H4_PACKET_TYPE_HCI_EVT &&
                    used_buffer_length >= BLUEDROID_TIMESTAMP_SIZE + BLUEDROID_H4_SIZE + 1 + 1 &&
                    BLUEDROID_TIMESTAMP_SIZE + BLUEDROID_H4_SIZE + 1 + payload[BLUEDROID_H4_SIZE + 1] + 1 <= used_buffer_length)) {

            ts = be64toh(*timestamp);

            switch (payload[BLUEDROID_H4_PACKET_TYPE]) {
            case BLUEDROID_H4_PACKET_TYPE_HCI_CMD:
                h4_header->direction = htonl(BLUEDROID_DIRECTION_SENT);

                pcap_header.caplen = sizeof(own_pcap_bluetooth_h4_header) + payload[3] + 4;
                pcap_header.len = pcap_header.caplen;

                length = sizeof(own_pcap_bluetooth_h4_header) + BLUEDROID_H4_SIZE + 2 + 1 + payload[3];

                break;
            case BLUEDROID_H4_PACKET_TYPE_ACL:
                h4_header->direction = (payload[2] & 0x80) ? htonl(BLUEDROID_DIRECTION_RECV) : htonl(BLUEDROID_DIRECTION_SENT);

                pcap_header.caplen = sizeof(own_pcap_bluetooth_h4_header) + payload[3] + (payload[3 + 1] << 8) + 5;
                pcap_header.len = pcap_header.caplen;

                length = sizeof(own_pcap_bluetooth_h4_header) + BLUEDROID_H4_SIZE + 2 + 2 + payload[3] + (payload[3 + 1] << 8);

                break;
            case BLUEDROID_H4_PACKET_TYPE_SCO:
                h4_header->direction = (payload[2] & 0x80) ? htonl(BLUEDROID_DIRECTION_RECV) : htonl(BLUEDROID_DIRECTION_SENT);

                pcap_header.caplen = sizeof(own_pcap_bluetooth_h4_header) + payload[3] + 4;
                pcap_header.len = pcap_header.caplen;

                length = sizeof(own_pcap_bluetooth_h4_header) + BLUEDROID_H4_SIZE + 2 + 1 + payload[3];

                break;
            case BLUEDROID_H4_PACKET_TYPE_HCI_EVT:
                h4_header->direction = htonl(BLUEDROID_DIRECTION_RECV);

                pcap_header.caplen = sizeof(own_pcap_bluetooth_h4_header) + payload[2] + 3;
                pcap_header.len = pcap_header.caplen;

                length = sizeof(own_pcap_bluetooth_h4_header) + BLUEDROID_H4_SIZE + 1 + 1 + payload[2];

                break;
            default:
                printf("ERROR: Invalid stream\n");
                return 1;
            }

            ts -= BLUEDROID_TIMESTAMP_BASE;

            pcap_header.ts.tv_sec = (uint32_t)(ts / 1000000);
            pcap_header.ts.tv_usec = (uint32_t)(ts % 1000000);

            pcap_dump((u_char *)dumper, &pcap_header, packet);
            pcap_dump_flush(dumper);

            used_buffer_length -= length - sizeof(own_pcap_bluetooth_h4_header) + BLUEDROID_TIMESTAMP_SIZE;
            if (used_buffer_length < 0) {
                printf("ERROR: Internal error: Negative used buffer length.");
                return 1;
            }
            memmove(buffer, packet + length, used_buffer_length);
        }
    }

    return 0;
}

/*----------------------------------------------------------------------------*/

int interface_add_android_logcat(struct interface_t *i_interface_list)
{
    static unsigned char   packet[PACKET_LENGTH];
    int                    length;
    int                    sock;
    struct sockaddr_in     server;
    char                  *default_server_ip = "127.0.0.1";
    unsigned short         default_server_tcp_port = 5037;
    char                  *adb_devices =    "000C""host:devices";
    char                  *serial_number;
    int                    result;
    char                  *interface_name;
    char                  *pos;
    char                  *prev_pos;

    if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        fprintf(stderr, "ERROR: Cannot open system TCP socket: %s\n", strerror(errno));
        return 1;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(default_server_tcp_port);
    server.sin_addr.s_addr = inet_addr(default_server_ip);

    if (connect(sock, (struct sockaddr *) &server, sizeof(server)) < 0) {
        fprintf(stderr, "ERROR: %s\n", strerror(errno));
        fprintf(stderr, "INFO: Please check that adb daemon is running.\n");
        return 2;
    }

    if (verbose) {
        struct sockaddr_in  client;

        length = sizeof(client);
        if (getsockname(sock, (struct sockaddr *) &client, (socklen_t *) &length)) {
            fprintf(stderr, "ERROR getsockname: %s\n", strerror(errno));
            return 3;
        }

        if (length != sizeof(client)) {
            fprintf(stderr, "ERROR: incorrect length\n");
            return 4;
        }

        fprintf(stderr, "Client port %u\n", ntohs(client.sin_port));
    }

    /* NOTE: It seems that "adb devices" close connection so cannot send
             next command after it, for list interfaces it is ok */
    result = send(sock, adb_devices, strlen(adb_devices), 0);
    if (result != (int) strlen(adb_devices)) {
        fprintf(stderr, "ERROR: Error while connecting/sending by ADB\n");
        return 1;
    }

    length = recv(sock, packet,  PACKET_LENGTH, 0);
    if (length < 4 || (length >= 4 && memcmp(packet, "OKAY", 4))) {
        fprintf(stderr, "ERROR: Error while connecting/receiving by ADB\n");
        return 1;
    }

    packet[length] = '\0';
    pos = (char *) (packet + 4 + 4);

    while (pos < (char *) (packet + length)) {
        prev_pos = pos;
        pos = strchr(pos, '\t');
        result = pos - prev_pos;
        serial_number = (char *) malloc(result + 1);
        memcpy(serial_number, prev_pos, result);
        serial_number[result] = '\0';
        pos = strchr(pos, '\n') + 1;

        interface_name = malloc(strlen(INTERFACE_ANDROID_LOGCAT_MAIN) + 1 + strlen(serial_number));
        interface_name[0]= '\0';
        strcat(interface_name, INTERFACE_ANDROID_LOGCAT_MAIN);
        strcat(interface_name, "-");
        strcat(interface_name, serial_number);
        i_interface_list->next = malloc(sizeof(struct interface_t));
        i_interface_list = i_interface_list->next;
        i_interface_list->display_name = "Android Logcat Main";
        i_interface_list->interface_name = interface_name;
        i_interface_list->next = NULL;


        interface_name = malloc(strlen(INTERFACE_ANDROID_LOGCAT_SYSTEM) + 1 + strlen(serial_number));
        interface_name[0]= '\0';
        strcat(interface_name, INTERFACE_ANDROID_LOGCAT_SYSTEM);
        strcat(interface_name, "-");
        strcat(interface_name, serial_number);
        i_interface_list->next = malloc(sizeof(struct interface_t));
        i_interface_list = i_interface_list->next;
        i_interface_list->display_name = "Android Logcat System";
        i_interface_list->interface_name = interface_name;
        i_interface_list->next = NULL;

        interface_name = malloc(strlen(INTERFACE_ANDROID_LOGCAT_RADIO) + 1 + strlen(serial_number));
        interface_name[0]= '\0';
        strcat(interface_name, INTERFACE_ANDROID_LOGCAT_RADIO);
        strcat(interface_name, "-");
        strcat(interface_name, serial_number);
        i_interface_list->next = malloc(sizeof(struct interface_t));
        i_interface_list = i_interface_list->next;
        i_interface_list->display_name = "Android Logcat Radio";
        i_interface_list->interface_name = interface_name;
        i_interface_list->next = NULL;

        interface_name = malloc(strlen(INTERFACE_ANDROID_LOGCAT_EVENTS) + 1 + strlen(serial_number));
        interface_name[0]= '\0';
        strcat(interface_name, INTERFACE_ANDROID_LOGCAT_EVENTS);
        strcat(interface_name, "-");
        strcat(interface_name, serial_number);
        i_interface_list->next = malloc(sizeof(struct interface_t));
        i_interface_list = i_interface_list->next;
        i_interface_list->display_name = "Android Logcat Events";
        i_interface_list->interface_name = interface_name;
        i_interface_list->next = NULL;
    }

    close(sock);
    return 0;
}

static void list_interfaces() {
    struct interface_t *interface_list;
    struct interface_t *i_interface_list;
    struct interface_t *i_interface;

    interface_list = malloc(sizeof(struct interface_t));
    interface_list->display_name = "Bluetooth Bluedroid";
    interface_list->interface_name = INTERFACE_BLUETOOTH_BLUEDROID;
    interface_list->next = NULL;

    interface_list->next = malloc(sizeof(struct interface_t));
    i_interface_list = interface_list->next;
    i_interface_list->display_name = "Linux Kernel Messages";
    i_interface_list->interface_name = INTERFACE_LINUX_KMSG;
    i_interface_list->next = NULL;

    i_interface_list->next = malloc(sizeof(struct interface_t));
    i_interface_list = i_interface_list->next;
    i_interface_list->display_name = "Linux Bluetooth Monitor";
    i_interface_list->interface_name = INTERFACE_LINUX_BLUETOOTH_MONITOR;
    i_interface_list->next = NULL;

    i_interface_list->next = malloc(sizeof(struct interface_t));
    i_interface_list = i_interface_list->next;
    i_interface_list->display_name = "Linux udev Monitor";
    i_interface_list->interface_name = INTERFACE_LINUX_UDEV_MONITOR;
    i_interface_list->next = NULL;

#ifdef HAVE_FANOTIFY
    i_interface_list->next = malloc(sizeof(struct interface_t));
    i_interface_list = i_interface_list->next;
    i_interface_list->display_name = "Linux Filesystem wide access notification";
    i_interface_list->interface_name = INTERFACE_LINUX_FANOTIFY;
    i_interface_list->next = NULL;
#endif

    i_interface_list->next = malloc(sizeof(struct interface_t));
    i_interface_list = i_interface_list->next;
    i_interface_list->display_name = "Linux Filesystem events";
    i_interface_list->interface_name = INTERFACE_LINUX_INOTIFY;
    i_interface_list->next = NULL;

    interface_add_android_logcat(i_interface_list);

    for (i_interface = interface_list; i_interface; i_interface = i_interface->next)
        printf("interface {display=%s}{value=%s}\n",
                i_interface->display_name,
                i_interface->interface_name);
}


static int list_dlts(char *interface) {
    if (!interface) {
        fprintf(stderr, "ERROR: No interface specified.\n");
        return 1;
    }

    if (is_specified_interface(interface, INTERFACE_BLUETOOTH_BLUEDROID)) {
        printf("dlt {number=99}{name=BluetoothH4}{display=Bluetooth HCI UART transport layer plus pseudo-header}\n");
        return 0;
    } else if (is_specified_interface(interface, INTERFACE_LINUX_BLUETOOTH_MONITOR)) {
        printf("dlt {number=254}{name=BluetoothLinuxMonitor}{display=Bluetooth Linux Monitor}\n");
        return 0;
    } else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_MAIN) ||
            is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_MAIN) ||
            is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_SYSTEM) ||
            is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_RADIO) ||
            is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_EVENTS) ||
            is_specified_interface(interface, INTERFACE_LINUX_FANOTIFY) ||
            is_specified_interface(interface, INTERFACE_LINUX_INOTIFY) ||
            is_specified_interface(interface, INTERFACE_LINUX_KMSG) ||
            is_specified_interface(interface, INTERFACE_LINUX_UDEV_MONITOR)) {
        printf("dlt {number=252}{name=Upper PDU}{display=Upper PDU}\n");
        return 0;
    }

    fprintf(stderr, "ERROR: Invalid interface: <%s>\n", interface);
    return 1;
}


static int list_config(char *interface) {
    if (!interface) {
        fprintf(stderr, "ERROR: No interface specified.\n");
        return 1;
    }

    if (is_specified_interface(interface, INTERFACE_BLUETOOTH_BLUEDROID)) {
        printf("arg {number=0}{call=--server-ip}{display=Server IP Address}{type=string}{default=127.0.0.1}\n"
                "arg {number=1}{call=--server-tcp-port}{display=Server TCP Port}{type=integer}{range=0,65535}{default=4330}\n"
                "arg {number=2}{call=--local-tcp-port}{display=Local TCP Port}{type=integer}{range=0,65535}{default=4330}{tooltip=Used to do \"adb forward tcp:LOCAL_TCP_PORT tcp:SERVER_TCP_PORT\"}\n");
        return 0;
    } else if (is_specified_interface(interface, INTERFACE_LINUX_INOTIFY) ||
            is_specified_interface(interface, INTERFACE_LINUX_FANOTIFY)) {
        printf("arg {number=0}{call=--path}{display=Path}{type=string}{default=.}{tooltip=Path to directory or file to be monitored. Default to \".\"}\n");
        return 0;
    } else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_MAIN) ||
            is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_MAIN) ||
            is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_SYSTEM) ||
            is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_RADIO) ||
            is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_EVENTS) ||
            is_specified_interface(interface, INTERFACE_LINUX_KMSG) ||
            is_specified_interface(interface, INTERFACE_LINUX_BLUETOOTH_MONITOR) ||
            is_specified_interface(interface, INTERFACE_LINUX_UDEV_MONITOR)) {
        /* No configs */
        printf("\n");
        return 0;
    }

    fprintf(stderr, "ERROR: Invalid interface: <%s>\n", interface);
    return 1;
}


static void help() {
    unsigned int  i_opt;

    printf("Help\n");
    printf(" Usage:\n"
        " extdumpcap --extcap-interfaces\n"
        " extdumpcap --extcap-interface=INTERFACE --extcap-dlts\n"
        " extdumpcap --extcap-interface=INTERFACE --extcap-config\n"
        " extdumpcap --extcap-interface=INTERFACE --fifo=PATH_FILENAME --capture \n");

    printf("\n Parameters:\n");
    for (i_opt = 0; i_opt < (sizeof(longopts) / sizeof(longopts[0])) - 1; i_opt += 1) {
        printf("  --%s%s\n", longopts[i_opt].name,
            (longopts[i_opt].has_arg == required_argument) ? "=<arg>" :
            ((longopts[i_opt].has_arg == optional_argument) ? "[=arg]" : ""));
    }

}


int main(int argc, char **argv) {
    int              option_idx = 0;
    int              do_capture = 0;
    int              do_config = 0;
    int              do_dlts = 0;
    int              result;
    char            *fifo = NULL;
    char            *interface = NULL;
    char            *server_ip = NULL;
    unsigned short  *server_tcp_port = NULL;
    unsigned short  *local_tcp_port = NULL;
    char            *path = NULL;

    opterr = 0;
    optind = 0;

    {
        int j = 0;
        while(j < argc) {
            fprintf(stderr, "%s ", argv[j]);
            j += 1;
        }
        fprintf(stderr, "\n");
    }

    if (argc == 1) {
        help();
        return 0;
    }

    while ((result = getopt_long(argc, argv, "", longopts, &option_idx)) != -1) {
        switch (result) {

        case OPT_VERSION:
            printf("%u.%u.%u\n", VERSION_MAJOR, VERSION_MINOR, VERSION_RELEASE);
            return 0;
        case OPT_LIST_INTERFACES:
            list_interfaces();
            return 0;
        case OPT_LIST_DLTS:
            do_dlts = 1;
            break;
        case OPT_INTERFACE:
            interface = strdup(optarg);
            break;
        case OPT_CONFIG:
            do_config = 1;
            break;
        case OPT_CAPTURE:
            do_capture = 1;
            break;
        case OPT_FIFO:
            fifo = strdup(optarg);
            break;
        case OPT_HELP:
            help();
            return 0;
        case OPT_CONFIG_SERVER_IP:
            server_ip = strdup(optarg);
            break;
        case OPT_CONFIG_SERVER_TCP_PORT:
            server_tcp_port = malloc(sizeof(server_tcp_port));
            *server_tcp_port = (unsigned short) strtoul(optarg, NULL, 10);
            break;
        case OPT_CONFIG_LOCAL_TCP_PORT:
            local_tcp_port = malloc(sizeof(local_tcp_port));
            *local_tcp_port = (unsigned short) strtoul(optarg, NULL, 10);
            break;
        case OPT_CONFIG_PATH:
            path = strdup(optarg);
            break;
        default:
            printf("Invalid argument <%s>. Try --help.\n", argv[optind - 1]);
            return -1;
        }
    }

    if (do_config) {
        return list_config(interface);
    }

    if (do_dlts) {
        return list_dlts(interface);
    }

    if (fifo == NULL) {
        printf("ERROR: No FIFO or file specified\n");
        return 1;
    }

    if (do_capture) {
        if (interface && strcmp(interface, INTERFACE_BLUETOOTH_BLUEDROID) == 0)
            return capture_bluetooth_bluedroid(fifo, server_ip, server_tcp_port, local_tcp_port);
        else if (interface && (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_MAIN) ||
                is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_SYSTEM) ||
                is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_RADIO) ||
                is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_EVENTS)))
            return capture_android_logcat(interface, fifo, server_ip, server_tcp_port);
#ifdef HAVE_FANOTIFY
        else if (interface && strcmp(interface, INTERFACE_LINUX_FANOTIFY) == 0)
            return capture_linux_fanotify(fifo, path);
#endif
        else if (interface && strcmp(interface, INTERFACE_LINUX_INOTIFY) == 0)
            return capture_linux_inotify(fifo, path);
        else if (interface && strcmp(interface, INTERFACE_LINUX_KMSG) == 0)
            return capture_linux_kmsg(fifo);
        else if (interface && strcmp(interface, INTERFACE_LINUX_UDEV_MONITOR) == 0)
            return capture_linux_udev_monitor(fifo);
        else if (interface && strcmp(interface, INTERFACE_LINUX_BLUETOOTH_MONITOR) == 0)
            return capture_linux_bluetooth_monitor(fifo);
        else
            return 2;
    }

    return 0;
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
