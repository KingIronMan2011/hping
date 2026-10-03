/* interface.c -- network interface handling
 * Copyright(C) 1999,2000,2001 Salvatore Sanfilippo <antirez@invece.org>
 * Copyright(C) 2001 by Nicolas Jombart <Nicolas.Jombart@hsc.fr>
 * Copyright(C) 2003 Salvatore Sanfilippo
 * This code is under the GPL license */

#include <stdio.h>		/* perror */
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>		/* struct sockaddr_in */
#include <arpa/inet.h>		/* inet_ntoa */
#include <net/if.h>
#include <unistd.h>		/* close */
#include <stdlib.h>

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || \
    defined(__bsdi__) || defined(__APPLE__)
#include <ifaddrs.h>
#include <net/route.h>
#include <net/if_media.h>
#endif /* defined(__*BSD__) */

#if !defined(__FreeBSD__) && !defined(__OpenBSD__) && !defined(__NetBSD__) && \
    !defined(__linux__) && !defined(__sun__) && !defined(__bsdi__) && \
    !defined(__APPLE__)
#error Sorry, interface code not implemented.
#endif

#ifdef __sun__
#include <sys/sockio.h>
#include <net/route.h>
#include <net/if_dl.h>
#endif

#include "hping2.h"
#include "globals.h"
#include "interface.h"

/* Try to obtain the IP address of the output interface according
 * to the OS routing table. Derived from R.Stevens */
int get_output_if(struct sockaddr_in *dest, struct sockaddr_in *ifip)
{
	socklen_t len;
	int sock_rt, on = 1;
	struct sockaddr_in iface_out;

	memset(&iface_out, 0, sizeof(iface_out));
	sock_rt = socket(AF_INET, SOCK_DGRAM, 0);

	dest->sin_port = htons(11111);
	if (setsockopt(sock_rt, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) == -1) {
		if (opt_debug)
			perror("DEBUG: [get_output_if] setsockopt(SOL_SOCKET, SO_BROADCAST)");
		close(sock_rt);
		return -1;
	}

	if (connect(sock_rt, (struct sockaddr*)dest, sizeof(struct sockaddr_in)) == -1) {
		if (opt_debug)
			perror("DEBUG: [get_output_if] connect");
		close(sock_rt);
		return -1;
	}

	len = sizeof(iface_out);
	if (getsockname(sock_rt, (struct sockaddr *)&iface_out, &len) == -1) {
		if (opt_debug)
			perror("DEBUG: [get_output_if] getsockname");
		close(sock_rt);
		return -1;
	}
	close(sock_rt);
	if (iface_out.sin_addr.s_addr == 0)
		return 1;
	memcpy(ifip, &iface_out, sizeof(struct sockaddr_in));
	return 0;
}

#if (defined OSTYPE_LINUX) || (defined __sun__)
int get_if_name(void)
{
	int fd;
	struct ifconf	ifc;
	struct ifreq	ibuf[16],
			ifr,
			*ifrp,
			*ifend;
	struct sockaddr_in sa;
	struct sockaddr_in output_if_addr;
	int known_output_if = 0;

	/* Try to get the output interface address according to
	 * the OS routing table */
	if (ifname[0] == '\0') {
		if (get_output_if(&remote, &output_if_addr) == 0) {
			known_output_if = 1;
			if (opt_debug)
				printf("DEBUG: Output interface address: %s\n",
					inet_ntoa(sa.sin_addr));
		} else {
			fprintf(stderr, "Warning: Unable to guess the output "
					"interface\n");
		}
	}

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("[get_if_name] socket(AF_INET, SOCK_DGRAM, 0)");
		return -1;
	}

	memset(ibuf, 0, sizeof(struct ifreq)*16);
	ifc.ifc_len = sizeof ibuf;
	ifc.ifc_buf = (caddr_t) ibuf;

	/* gets interfaces list */
	if (ioctl(fd, SIOCGIFCONF, (char*)&ifc) == -1 ||
	    ifc.ifc_len < sizeof(struct ifreq)) {
		perror("[get_if_name] ioctl(SIOCGIFCONF)");
		close(fd);
		return -1;
	}

	/* ifrp points to buffer and ifend points to buffer's end */
	ifrp = ibuf;
	ifend = (struct ifreq*) ((char*)ibuf + ifc.ifc_len);

	for (; ifrp < ifend; ifrp++) {
		strlcpy(ifr.ifr_name, ifrp->ifr_name, sizeof(ifr.ifr_name));

		if (ioctl(fd, SIOCGIFFLAGS, (char*)&ifr) == -1) {
			if (opt_debug)
				perror("DEBUG: [get_if_name] ioctl(SIOCGIFFLAGS)");
			continue;
		}

		if (opt_debug)
			printf("DEBUG: if %s: ", ifr.ifr_name);

		if (!(ifr.ifr_flags & IFF_UP)) {
			if (opt_debug)
				printf("DOWN\n");
			continue;
		}

		if (ifr.ifr_flags & IFF_LOOPBACK) {
			if (opt_debug)
				printf("LOOPBACK ");
		}

		if (ioctl(fd, SIOCGIFADDR, (char*)&ifr) == -1) {
			perror("DEBUG: [get_if_name] ioctl(SIOCGIFADDR)");
			continue;
		}

		memcpy(&sa, &ifr.ifr_addr, sizeof(struct sockaddr_in));
		if (opt_debug)
			printf("IP: %s ", inet_ntoa(sa.sin_addr));

		/* set the ifname if not provided by user */
		if (ifname[0] == '\0') {
			if (known_output_if) {
				if (sa.sin_addr.s_addr == output_if_addr.sin_addr.s_addr)
				{
					strlcpy(ifname, ifr.ifr_name, 1024);
					strlcpy(ifstraddr, inet_ntoa(sa.sin_addr), 1024);
					if (opt_debug)
						printf("MATCH\n");
					break;
				}
			} else if (!(ifr.ifr_flags & IFF_LOOPBACK)) {
				strlcpy(ifname, ifr.ifr_name, 1024);
				strlcpy(ifstraddr, inet_ntoa(sa.sin_addr), 1024);
				break;
			}
		} else if (!strcmp(ifname, ifr.ifr_name)) {
			strlcpy(ifstraddr, inet_ntoa(sa.sin_addr), 1024);
			break;
		}

		if (opt_debug)
			printf("\n");
	}

	if (ifrp < ifend) {
		strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
		if (ioctl(fd, SIOCGIFMTU, (char*)&ifr) == -1) {
			perror("Warning: [get_if_name] ioctl(SIOCGIFMTU)");
			fprintf(stderr, "Using a fixed MTU of 1500\n");
			h_if_mtu = 1500;
		}
		else
		{
#ifdef __sun__
			/* somehow solaris is braidamaged in wrt ifr_mtu */
			h_if_mtu = ifr.ifr_metric;
#else
			h_if_mtu = ifr.ifr_mtu;
#endif
		}
		close(fd);
		return 0;
	}
	/* interface not found, use 'lo' */
	strlcpy(ifname, "lo", 1024);
	strlcpy(ifstraddr, "127.0.0.1", 1024);
	h_if_mtu = 1500;

	close(fd);
	return 0;
}

#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || \
      defined(__bsdi__) || defined(__APPLE__)

int get_if_name(void)
{
	struct ifaddrs		*ifap, *ifa;
	char			current_if_name[24];
	char			saved_ifname[24];
	struct sockaddr_in	output_if_addr;
#ifdef __NetBSD__
	int s;
	struct ifreq ifr;
#endif  /* __NetBSD__ */

	if (getifaddrs(&ifap) < 0)
		perror("getifaddrs");

	saved_ifname[0] = 0;

	/* lookup desired interface */
	if (ifname[0] == 0) {
		/* find gateway interface from kernel */
		if (get_output_if(&remote, &output_if_addr) == 0) {
			if (opt_debug)
				printf("DEBUG: Output interface address: %s\n",
					inet_ntoa(output_if_addr.sin_addr));
			saved_ifname[0] = 'X'; saved_ifname[1] = 0;
		} else {
			fprintf(stderr, "Warning: Unable to guess the output "
					"interface\n");
		}
	}
	else {
		/* use the forced interface name */
		strlcpy(saved_ifname, ifname, 24);
	}

	/* get interface information */
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (opt_debug) printf("\n DEBUG: if %s: ", ifa->ifa_name);

		if (ifa->ifa_data) {
			if (opt_debug) printf("DEBUG: (struct DATA) ");
		} else {
			if (opt_debug) printf("DEBUG: (struct DATA is NULL) ");
		}

		if (!(ifa->ifa_flags & IFF_UP)) {       /* if down */
			if (opt_debug)
				printf("DEBUG: DOWN");
			continue; 
		}

		if ((ifa->ifa_flags & IFF_LOOPBACK)&&
		    (strncmp(saved_ifname, "lo0", 3))) {  /* if loopback */
			if (opt_debug)
				printf("DEBUG: LOOPBACK, SKIPPED");
			continue;
		}

		if (ifa->ifa_addr->sa_family == AF_LINK) {
			if (opt_debug)
				printf("DEBUG: AF_LINK ");
			strlcpy(ifname, ifa->ifa_name, 1024);
			strlcpy(current_if_name, ifa->ifa_name, 24);

			/* MTU */
			if (ifa->ifa_data != NULL)
				h_if_mtu = ((struct if_data *)ifa->ifa_data)->ifi_mtu;
			else {
#ifdef __NetBSD__
				s = socket(AF_INET, SOCK_DGRAM, 0);
				memset(&ifr, 0, sizeof(ifr));
				strlcpy(ifr.ifr_name, ifa->ifa_name, sizeof(ifr.ifr_name));
				if (ioctl(s, SIOCGIFMTU, (caddr_t)&ifr) < 0) {
					h_if_mtu = 1500;
				} else {
					h_if_mtu = ifr.ifr_mtu;
				}
				close(s);
#else
				h_if_mtu = 1500;
#endif
			}
			if (opt_debug)
				printf("DEBUG: MTU: %d\n", h_if_mtu);
		}

		if (ifa->ifa_addr->sa_family == AF_INET) {
			if (opt_debug)
				printf("DEBUG: AF_INET ");
			strlcpy(ifstraddr,
				inet_ntoa(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr),
				1024);
			if (opt_debug)
				printf("DEBUG: IP: %s\n", ifstraddr);

			if (saved_ifname[0] == 'X') {
				if (!memcmp(&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr,
					    &output_if_addr.sin_addr,
					    sizeof(struct in_addr)))
				{
					if (opt_debug)
						printf("DEBUG: Output interface address MATCH\n");
					break;
				}
			} else {
				if (!strncmp(current_if_name, saved_ifname, 24))
					break;
			}
		}
	}

	if (!ifa) {
		if (opt_debug) {
			printf("DEBUG: interface %s\n",
				saved_ifname[0] ? "not found" : "search failed");
		}

		/* interface not found, use hardcoded 'lo' */
		strlcpy(ifname, "lo0", 1024);
		strlcpy(ifstraddr, "127.0.0.1", 1024);
		h_if_mtu = 1500;
	}

	freeifaddrs(ifap);
	return 0;
}

#endif /* __*BSD__ */

#ifdef USE_TCL

#if (defined OSTYPE_LINUX) || (defined __sun__)
int hping_get_interfaces(struct hpingif *hif, int ilen)
{
	int fd, found = 0, i;
	struct ifconf	ifc;
	struct ifreq ibuf[HPING_IFACE_MAX], ifr;

	/* We need a socket to perform the ioctl()s */
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1)
		return -1;
	/* Setup the request structure */
	memset(ibuf, 0, sizeof(struct ifreq)*HPING_IFACE_MAX);
	ifc.ifc_len = sizeof ibuf;
	ifc.ifc_buf = (caddr_t) ibuf;
	/* Get a list of interfaces */
	if (ioctl(fd, SIOCGIFCONF, (char*)&ifc) == -1 ||
		ifc.ifc_len < sizeof(struct ifreq))
	{
		close(fd);
		return -1;
	}
	/* Walk the interfaces list, searching for UP interfaces */
	for (i = 0; i < (ifc.ifc_len/sizeof(struct ifreq)); i++) {
		struct ifreq *this = ibuf+i;
		in_addr_t ifaddr, ifbaddr = 0;
		struct sockaddr_in *sain;
		int ifloopback, ifmtu, ifptp, ifpromisc, ifbroadcast, ifindex, ifnolink = 0;

		memset(&ifr, 0, sizeof(ifr));
		if (!this->ifr_name[0])
			continue;
		strlcpy(ifr.ifr_name, this->ifr_name, HPING_IFNAME_LEN);
		if (ioctl(fd, SIOCGIFFLAGS, (char*)&ifr) == -1) {
			continue;
		}
		if (!(ifr.ifr_flags & IFF_UP))
			continue;

		ifloopback = (ifr.ifr_flags & IFF_LOOPBACK) != 0;
		ifptp = (ifr.ifr_flags & IFF_POINTOPOINT) != 0;
		ifpromisc = (ifr.ifr_flags & IFF_PROMISC) != 0;
		ifbroadcast = (ifr.ifr_flags & IFF_BROADCAST) != 0;

		/* Get the interface address */
		if (ioctl(fd, SIOCGIFADDR, (char*)&ifr) == -1)
			continue;
		sain = (struct sockaddr_in*) &ifr.ifr_addr;
		ifaddr = sain->sin_addr.s_addr;

		/* Get the broadcast address */
		if (ifbroadcast) {
			if (ioctl(fd, SIOCGIFBRDADDR, (char*)&ifr) == -1)
				continue;
			sain = (struct sockaddr_in*) &ifr.ifr_broadaddr;
			ifbaddr = sain->sin_addr.s_addr;
		}

		/* Get the MTU */
		if (ioctl(fd, SIOCGIFMTU, (char*)&ifr) == -1)
			continue;
#ifdef __sun__
		ifmtu = ifr.ifr_metric;
#else
		ifmtu = ifr.ifr_mtu;
#endif

		/* Get the interface index (only for Linux) */
#if defined(__linux__) && defined(SIOCGIFINDEX)
		if (ioctl(fd, SIOCGIFINDEX, (char*)&ifr) == -1)
			continue;
		ifindex = ifr.ifr_ifindex;
#else
		ifindex = -1;
#endif

		/* Read the MII status (only for Linux) */
#if defined(__linux__) && defined(SIOCGMIIPHY)
		{
			struct mii_data *mii;
			mii = (struct mii_data *)&ifr.ifr_data;
			mii->phy_id = 0;
			mii->reg_num = 1;
			if (ioctl(fd, SIOCGMIIPHY, &ifr) != -1 &&
			    ioctl(fd, SIOCGMIIREG, &ifr) != -1)
			{
				if (!(mii->val_out & MII_BMSR_LINK_VALID))
					ifnolink = 1;
			}
		}
#endif
		/* Check if the interface is already present in the output array */
		{
			int j;
			for (j = 0; j < found; j++) {
				if (!strcmp(hif[j].hif_name, this->ifr_name))
					break;
			}
			if (j != found) {
				if (hif[j].hif_naddr < HPING_IFADDR_MAX) {
					int na = hif[j].hif_naddr;
					hif[j].hif_addr[na] = ifaddr;
					hif[j].hif_baddr[na] = ifbaddr;
					hif[j].hif_naddr++;
				}
				continue;
			}
		}

		/* If there is no space left return the found interfaces anyway */
		if (found >= ilen) {
			found++;
			continue;
		}

		/* Fill the interface information */
		strlcpy(hif[found].hif_name, this->ifr_name, HPING_IFNAME_LEN);
		hif[found].hif_addr[0] = ifaddr;
		hif[found].hif_baddr[0] = ifbaddr;
		hif[found].hif_naddr = 1;
		hif[found].hif_loopback = ifloopback;
		hif[found].hif_ptp = ifptp;
		hif[found].hif_promisc = ifpromisc;
		hif[found].hif_broadcast = ifbroadcast;
		hif[found].hif_nolink = ifnolink;
		hif[found].hif_mtu = ifmtu;
		hif[found].hif_index = ifindex;
		found++;
	}
	close(fd);
	return found;
}
#endif /* OSTYPE_LINUX || __sun__ */

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || \
    defined(__bsdi__) || defined(__APPLE__)
int hping_get_interfaces(struct hpingif *hif, int ilen)
{
	struct ifaddrs *ifap, *ifa;
	struct if_data *ifdata;
	int found = 0;
	int ifloopback, ifptp, ifpromisc, ifbroadcast, ifnolink;

	if (getifaddrs(&ifap) == -1)
		return -1;
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		struct ifaddrs *ift;
		struct sockaddr_in *sa, *ba;
		int naddr = 0;
		if (!(ifa->ifa_flags & IFF_UP))
			continue;
		ifloopback = (ifa->ifa_flags & IFF_LOOPBACK) != 0;
		ifptp = (ifa->ifa_flags & IFF_POINTOPOINT) != 0;
		ifpromisc = (ifa->ifa_flags & IFF_PROMISC) != 0;
		ifbroadcast = (ifa->ifa_flags & IFF_BROADCAST) != 0;
		if (ifa->ifa_addr->sa_family != AF_LINK)
			continue;
		ift = ifa->ifa_next;
		for (; ift; ift = ift->ifa_next) {
			if (ift->ifa_addr->sa_family == AF_INET &&
			    ift->ifa_addr &&
			    !strcmp(ifa->ifa_name, ift->ifa_name))
			{
				sa = (struct sockaddr_in*) ift->ifa_addr;
				ba = (struct sockaddr_in*) ift->ifa_broadaddr;
				if (naddr < HPING_IFADDR_MAX) {
					hif[found].hif_addr[naddr] = sa->sin_addr.s_addr;
					hif[found].hif_baddr[naddr] = ba->sin_addr.s_addr;
					naddr++;
				}
			}
		}
		if (!naddr)
			continue;
		{
			struct ifmediareq ifmr;
			int s = -1;
			memset(&ifmr, 0, sizeof(ifmr));
			strncpy(ifmr.ifm_name, ifa->ifa_name, sizeof(ifmr.ifm_name));
			ifnolink = 0;
			s = socket(AF_INET, SOCK_DGRAM, 0);
			if (s != -1 &&
			    ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifmr) != -1)
			{
				if (ifmr.ifm_status & IFM_AVALID) {
					if (!(ifmr.ifm_status & IFM_ACTIVE))
						ifnolink = 1;
				}
			}
			if (s != -1)
				close(s);
		}
		ifdata = (struct if_data*) ifa->ifa_data;
		strlcpy(hif[found].hif_name, ifa->ifa_name, HPING_IFNAME_LEN);
		hif[found].hif_broadcast = ifbroadcast;
		hif[found].hif_mtu = ifdata->ifi_mtu;
		hif[found].hif_loopback = ifloopback;
		hif[found].hif_ptp = ifptp;
		hif[found].hif_promisc = ifpromisc;
		hif[found].hif_naddr = naddr;
		hif[found].hif_nolink = ifnolink;
		hif[found].hif_index = -1;
		found++;
		ilen--;
		if (!ilen)
			break;
	}
	freeifaddrs(ifap);
	return found;
}
#endif /* __*BSD__ */

#endif /* USE_TCL */
