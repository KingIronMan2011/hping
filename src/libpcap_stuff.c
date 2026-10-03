/*
 * $smu-mark$
 * $name: libpcap_stuff.c$
 * $author: Salvatore Sanfilippo <antirez@invece.org>$
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$
 * $license: This software is under GPL version 2 of license$
 * $date: Fri Nov  5 11:55:48 MET 1999$
 * $rev: 8$
 */

/* $Id: libpcap_stuff.c,v 1.3 2004/04/09 23:38:56 antirez Exp $ */

#include "hping2.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#if defined(__linux__) || defined(__GLIBC__)
#include <pcap/bpf.h>
#else
#include <net/bpf.h>
#endif
#include <pcap.h>

#include "globals.h"

int dltype_to_lhs(int dltype)
{
	int lhs;

	switch(dltype) {
	case DLT_EN10MB:
#ifdef DLT_IEEE802
	case DLT_IEEE802:
#endif
		lhs = 14;
		break;
	case DLT_SLIP:
	case DLT_SLIP_BSDOS:
		lhs = 16;
		break;
	case DLT_PPP:
	case DLT_NULL:
#ifdef DLT_PPP_SERIAL
	case DLT_PPP_SERIAL:
#endif
#ifdef DLT_LOOP
	case DLT_LOOP:
#endif
		lhs = 4;
		break;
	case DLT_PPP_BSDOS:
		lhs = 24;
		break;
	case DLT_FDDI:
		lhs = 13;
		break;
	case DLT_RAW:
		lhs = 0;
		break;
#ifdef DLT_IEEE802_11
	case DLT_IEEE802_11:
		lhs = 14;
		break;
#endif
	case DLT_ATM_RFC1483:
#ifdef DLT_CIP
	case DLT_CIP:
#endif
#ifdef DLT_ATM_CLIP
	case DLT_ATM_CLIP:
#endif
		lhs = 8;
		break;
#ifdef DLT_C_HDLC
	case DLT_C_HDLC:
		lhs = 4;
		break;
#endif
#ifdef DLT_LINUX_SLL
	case DLT_LINUX_SLL:
#endif
#ifdef DLT_LANE8023
	case DLT_LANE8023:
#endif
		lhs = 16;
		break;
	default:
		return -1;
		break;
	}
	return lhs;
}

int get_linkhdr_size(char *ifname)
{
	int dltype = pcap_datalink(pcapfp);

	if (opt_debug)
		printf("DEBUG: dltype is %d\n", dltype);

	linkhdr_size = dltype_to_lhs(dltype);
	return linkhdr_size;
}

int open_pcap(void)
{
	int on;

	on = 1; /* no warning if BIOCIMMEDIATE will not be compiled */
	if (opt_debug)
		printf("DEBUG: pcap_open_live(%s, 99999, 0, 1, %p)\n",
			ifname, errbuf);

	pcapfp = pcap_open_live(ifname, 99999, 0, 1, errbuf);
	if (pcapfp == NULL) {
		printf("[open_pcap] pcap_open_live: %s\n", errbuf);
		return -1;
	}
#if (!defined OSTYPE_LINUX) && (!defined __sun__)
	/* Return the packets to userspace as fast as possible */
	if (ioctl(pcap_fileno(pcapfp), BIOCIMMEDIATE, &on) == -1)
		perror("[open_pcap] ioctl(... BIOCIMMEDIATE ...)");
#endif
	return 0;
}

int close_pcap(void)
{
	pcap_close(pcapfp);
	return 0;
}

int pcap_recv(char *packet, unsigned int size)
{
	char *p = NULL;
	int pcapsize;

	if (opt_debug)
		printf("DEBUG: under pcap_recv()\n");

	while(p == NULL) {
		p = (char*) pcap_next(pcapfp, &hdr);
		if (p == NULL && opt_debug)
			printf("DEBUG: [pcap_recv] p = NULL\n");
	}

	pcapsize = hdr.caplen;

	if (pcapsize < size)
		size = pcapsize;

	memcpy(packet, p, pcapsize);

	return pcapsize;
}
