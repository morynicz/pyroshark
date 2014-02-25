/*
 * extcap_example.c
 *
 *  Example for an extcap parser written in C
 *  For an example in Python go to
 *   https://github.com/greatscottgadgets/ubertooth/blob/master/host/python/extcap/btle-extcap.py
 *
 * To Run:
 *   1. Compile with: gcc -o extcap_example extcap_example.c
 *   2. Gopy to extcap directory path (is being dumped via debug log)
 *
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

#include <stdio.h>
#include <getopt.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

void list_interfaces() {
	printf("interface {display=TCPTEST}{value=tcptest}\n");
}

void list_dlts() {
	printf("dlt {number=1}{name=EN10MB}{display=Ethernet}\n");
}

void show_config() {
	printf("arg {number=0}{call=--packetlen}{display=Packet Length}{type=integer}{range=0,65535}{default=65535}{tooltip=Min. packet length for capture}\n"
		   "arg {number=1}{call=--verifychecksum}{display=Verify Checksums}{type=boolean}{default=true}{tooltip=Verify IP, TCP and UDP checksums}\n"
		   "arg {number=2}{call=--compress}{display=Selector}{type=selector}{tooltip=Choose output compression}\n"
		   "arg {number=3}{call=--verbose}{display=Verbose output}{type=radio}{tooltip=Verbose output}\n");
		   //"arg {number=4}{call=checklist}{display=Checklist}{type=multicheck}{tooltip=Checklist}\n"
	/* Values for compression */
	printf("value {arg=2}{value=none}{display=none}{default=true}\n"
		   "value {arg=2}{value=gzip}{display=gzip}\n"
		   "value {arg=2}{value=bzip2}{display=bzip2}\n");
	/* Values for radio output */
	printf("value {arg=3}{value=none}{display=Silent}{default=true}\n"
		   "value {arg=3}{value=v}{display=Verbosity Level 1}\n"
		   "value {arg=3}{value=vv}{display=Verbosity Level 2}\n");
	/*printf("value {arg=4}{value=1}{display=One}\n"
		   "value {arg=4}{value=2}{display=Two}\n"
		   "value {arg=4}{value=3}{display=Three}{enabled=true}\n"
		   "value {arg=4}{value=4}{display=Four}{enabled=true}\n"
		   "value {arg=4}{value=5}{display=Five}\n"
		   "value {arg=4}{value=6}{display=Six}\n"
		   "value {arg=4}{value=7}{display=Seven}\n"
		   "value {arg=4}{value=8}{display=Eight}\n"
		   "value {arg=4}{value=9}{display=Nine}\n"
		   "value {arg=4}{value=0}{display=Zero}\n");*/

}

void spawn_tcpdump(char *fifo, uint16_t packetlen, uint8_t verify ) {
	execlp("tcpdump", "tcpdump", "-i", "eth1", "-s", "0", "-U", "-w", fifo, NULL);
}

#define ARG_PACKETLEN 				0x01
#define ARG_VERIFYCHECKSUM			0x02
#define ARG_COMPRESS				0x03
#define ARG_VERBOSE					0x04

#define ARG_EXTCAP_INTERFACE 		0xA0
#define ARG_EXTCAP_LISTINTERFACE 	0xA1
#define ARG_EXTCAP_LISTDLTS			0xA2
#define ARG_EXTCAP_CONFIG			0xA4
#define ARG_EXTCAP_DOCAPTURE		0xA8
#define ARG_EXTCAP_FIFO				0xB0

int main(int argc, char *argv[]) {
	int option_idx = 0;
	uint8_t do_tcpdump = 0, do_dlts = 0, do_verify = 0;
	uint16_t packetlen = 0;
	char *fifo = NULL;
	char *interface = NULL;

	static struct option longopts[] = {
		/* parameter for the extcap filter program, passed from wireshark */
		{ "packetlen", 			required_argument, 	0, ARG_PACKETLEN},
		{ "verifychecksum", 	no_argument,		0, ARG_VERIFYCHECKSUM },
		{ "compress", 			required_argument,	0, ARG_COMPRESS },
		{ "verbose", 			required_argument,	0, ARG_VERBOSE },

		/* Generic interface naming, may be used for normal tool usage */
		{ "list-interfaces", 	no_argument, 		0, ARG_EXTCAP_LISTINTERFACE },

		/* Extcap interface parameters */
		{ "extcap-interface", 	required_argument, 	0, ARG_EXTCAP_INTERFACE },
		{ "extcap-interfaces", 	no_argument, 		0, ARG_EXTCAP_LISTINTERFACE },
		{ "extcap-config",		no_argument, 		0, ARG_EXTCAP_CONFIG },
		{ "extcap-dlts",		no_argument,		0, ARG_EXTCAP_LISTDLTS },
		{ "capture", 			no_argument, 		0, ARG_EXTCAP_DOCAPTURE },
		{ "fifo", 				required_argument, 	0, ARG_EXTCAP_FIFO},

		{ 0, 0, 0, 0 }
	};

#if DEBUG
    {
        int j = 0;
        fprintf(stderr, "Call: ");
        while(j < argc) {
            fprintf(stderr, "%s ", argv[j]);
            j += 1;
        }
        fprintf(stderr, "\n");
    }
#endif

	while (1) {
		int r = getopt_long(argc, argv, "", longopts, &option_idx);

		if (r < 0)
			break;

		switch(r)
		{

		case ARG_PACKETLEN:
			packetlen = atoi(optarg, 10);
			break;

		case ARG_VERIFYCHECKSUM:
			do_verify = 1;
			break;

		case ARG_EXTCAP_INTERFACE:
			interface = strdup(optarg);
			break;
		case ARG_EXTCAP_LISTINTERFACE:
			list_interfaces();
			return(0);
			break;
		case ARG_EXTCAP_CONFIG:
			show_config();
			return(0);
			break;
		case ARG_EXTCAP_LISTDLTS:
			do_dlts = 1;
			break;
		case ARG_EXTCAP_DOCAPTURE:
			do_tcpdump = 1;
			break;
		case ARG_EXTCAP_FIFO:
			fifo = strdup(optarg);
			break;
		default:
			break;

		}
	}

	if (do_tcpdump) {
		if (fifo == NULL)
			return(1);

		spawn_tcpdump(fifo, packetlen, do_verify);
	}

	if (do_dlts) {
		if (interface == NULL)
			return(1);

		if (strcmp(interface, "tcptest") != 0 )
			return(1);

		list_dlts();

		return(0);
	}

	return(1);
}
