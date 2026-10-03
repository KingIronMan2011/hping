/* 
 * $smu-mark$ 
 * $name: sendip.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:49 MET 1999$ 
 * $rev: 8$ 
 */ 

/* $Id: sendip.c,v 1.2 2004/04/09 23:38:56 antirez Exp $ */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "hping2.h"
#include "globals.h"

void send_ip(char *src, char *dst, char *data, unsigned int datalen,
		int more_fragments, unsigned short fragoff, char *options,
		char optlen)
{
	char		*packet;
	int		result,
			packetsize;
	struct myiphdr	*ip;

	packetsize = IPHDR_SIZE + optlen + datalen;
	if ((packet = malloc(packetsize)) == NULL) {
		perror("[send_ip] malloc()");
		return;
	}

	memset(packet, 0, packetsize);
	ip = (struct myiphdr*) packet;

	/* copy src and dst address */
	memcpy(&ip->saddr, src, sizeof(ip->saddr));
	memcpy(&ip->daddr, dst, sizeof(ip->daddr));

	/* build ip header */
	ip->version	= 4;
	ip->ihl		= (IPHDR_SIZE + optlen + 3) >> 2;
	ip->tos		= ip_tos;

#if defined OSTYPE_DARWIN || defined OSTYPE_FREEBSD || defined OSTYPE_NETBSD || defined OSTYPE_BSDI
/* FreeBSD */
/* NetBSD */
	ip->tot_len	= packetsize;
#else
/* Linux */
/* OpenBSD */
	ip->tot_len	= htons(packetsize);
#endif

	if (!opt_fragment)
	{
		ip->id		= (src_id == -1) ?
			htons((unsigned short) rand()) :
			htons((unsigned short) src_id);
	}
	else /* if you need fragmentation id must not be randomic */
	{
		/* FIXME: when frag. enabled sendip_handler shold inc. ip->id */
		/*        for every frame sent */
		ip->id		= (src_id == -1) ?
			htons(getpid() & 255) :
			htons((unsigned short) src_id);
	}

#if defined OSTYPE_DARWIN || defined OSTYPE_FREEBSD || defined OSTYPE_NETBSD || defined OSTYPE_BSDI
/* FreeBSD */
/* NetBSD */
	ip->frag_off	|= more_fragments;
	ip->frag_off	|= fragoff >> 3;
#else
/* Linux */
/* OpenBSD */
	ip->frag_off	|= htons(more_fragments);
	ip->frag_off	|= htons(fragoff >> 3); /* shift three flags bit */
#endif

	ip->ttl		= src_ttl;
	if (opt_rawipmode)	ip->protocol = raw_ip_protocol;
	else if	(opt_icmpmode)	ip->protocol = 1;	/* icmp */
	else if (opt_udpmode)	ip->protocol = 17;	/* udp  */
	else			ip->protocol = 6;	/* tcp  */
	ip->check	= 0; /* always computed by the kernel */

	/* copies options */
	if (options != NULL)
		memcpy(packet+IPHDR_SIZE, options, optlen);

	/* copies data */
	memcpy(packet + IPHDR_SIZE + optlen, data, datalen);
	
	if (opt_debug == TRUE)
	{
		unsigned int i;

		for (i=0; i<packetsize; i++)
			printf("%.2X ", packet[i]&255);
		printf("\n");
	}
	result = sendto(sockraw, packet, packetsize, 0,
		(struct sockaddr*)&remote, sizeof(remote));
	
	if (result == -1 && errno != EINTR && !opt_rand_dest && !opt_rand_source) {
		perror("[send_ip] sendto");
		if (close(sockraw) == -1)
			perror("[ipsender] close(sockraw)");
		if (close_pcap() == -1)
			printf("[ipsender] close_pcap failed\n");
		exit(1);
	}

	free(packet);

	/* inc packet id for safe protocol */
	if (opt_safe && !eof_reached)
		src_id++;
}

void send_ip_handler(char *packet, unsigned int size)
{
	ip_optlen = ip_opt_build(ip_opt);

	if (!opt_fragment && (size+ip_optlen+20 >= h_if_mtu))
	{
		/* auto-activate fragmentation */
		virtual_mtu = h_if_mtu-20;
		virtual_mtu = virtual_mtu - (virtual_mtu % 8);
		opt_fragment = TRUE;
		opt_mf = opt_df = FALSE; /* deactivate incompatible options */
		if (opt_verbose || opt_debug)
			printf("auto-activate fragmentation, fragments size: %d\n", virtual_mtu);
	}

	if (!opt_fragment)
	{
		unsigned short fragment_flag = 0;

		if (opt_mf) fragment_flag |= MF; /* more fragments */
		if (opt_df) fragment_flag |= DF; /* dont fragment */
		send_ip((char*)&local.sin_addr,
			(char*)&remote.sin_addr,
			packet, size, fragment_flag, ip_frag_offset,
			ip_opt, ip_optlen);
	}
	else
	{
		unsigned int remainder = size;
		int frag_offset = 0;

		while(1) {
			if (remainder <= virtual_mtu)
				break;

			send_ip((char*)&local.sin_addr,
				(char*)&remote.sin_addr,
				packet+frag_offset,
				virtual_mtu, MF, frag_offset,
				ip_opt, ip_optlen);

			remainder-=virtual_mtu;
			frag_offset+=virtual_mtu;
		}

		send_ip((char*)&local.sin_addr,
			(char*)&remote.sin_addr,
			packet+frag_offset,
			remainder, NF, frag_offset,
			ip_opt, ip_optlen);
	}
}

void send_rawip(void)
{
	char *packet;

	packet = malloc(data_size);
	if (packet == NULL) {
		perror("[send_rawip] malloc()");
		return;
	}
	memset(packet, 0, data_size);
	data_handler(packet, data_size);
	send_ip_handler(packet, data_size);
	free(packet);
}
