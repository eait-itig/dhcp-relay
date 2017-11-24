/*	$OpenBSD: tftpd.c,v 1.39 2017/05/26 17:38:46 florian Exp $	*/

/*
 * Copyright (c) 2017 The University of Queensland
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Copyright (c) 2004 Henning Brauer <henning@cvs.openbsd.org>
 * Copyright (c) 1997, 1998, 1999 The Internet Software Consortium.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of The Internet Software Consortium nor the names
 *    of its contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INTERNET SOFTWARE CONSORTIUM AND
 * CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE INTERNET SOFTWARE CONSORTIUM OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This software has been written for the Internet Software Consortium
 * by Ted Lemon <mellon@fugue.com> in cooperation with Vixie
 * Enterprises.  To learn more about the Internet Software Consortium,
 * see ``http://www.vix.com/isc''.  To learn more about Vixie
 * Enterprises, see ``http://www.vix.com''.
 */


/*
 * This code was largely rewritten by David Gwynne <dlg@uq.edu.au>
 * as part of the Information Technology Infrastructure Group in the
 * Faculty of Engineering, Architecture and Information Technology.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/uio.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_types.h>

#include <net/bpf.h>

#include <arpa/inet.h> /* inet_ntoa */
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <err.h>
#include <ctype.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <paths.h>
#include <poll.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#include <signal.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <assert.h>

#include "dhcp.h"
#include "log.h"

#define SERVER_PORT	67
#define CLIENT_PORT	68
#define DHCP_USER	"_dhcp"
#define CHADDR_SIZE	16

#define ETHER_FMT	"%02x:%02x:%02x:%02x:%02x:%02x"
#define ETHER_ARGS(_e)	(_e)[0], (_e)[1], (_e)[2], (_e)[3], (_e)[4], (_e)[5] 

#define streq(_a, _b)	(strcmp(_a, _b) == 0)
#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

#define sin2sa(_sin)	(struct sockaddr *)(_sin)
#define sa2sin(_sa)	(struct sockaddr_in *)(_sa)

struct iface;

struct dhcp_giaddr {
	struct iface		*gi_if;
	struct sockaddr_in	 gi_sin;
	struct event		 gi_ev;
	const char		*gi_name;
};

struct iface {
	const char		*if_name;
	unsigned int		 if_index;

	struct sockaddr_in	*if_servers;
	unsigned int		 if_nservers;
	const char		**if_server_names;

	uint8_t			 if_hwaddr[16];
	unsigned int		 if_hwaddrlen;

	struct dhcp_giaddr	*if_giaddrs;
	unsigned int		 if_ngiaddrs;

	struct event		 if_bpf_ev;
	uint8_t			*if_bpf_buf;
	unsigned int		 if_bpf_len;
	unsigned int		 if_bpf_cur;

	struct event		 if_siginfo;

	uint64_t		 if_bpf_short;
	uint64_t		 if_ether_len;
	uint64_t		 if_ip_len;
	uint64_t		 if_ip_cksum;
	uint64_t		 if_udp_len;
	uint64_t		 if_udp_cksum;
	uint64_t		 if_dhcp_len;
	uint64_t		 if_dhcp_op;
	uint64_t		 if_srvr_op;
	uint64_t		 if_srvr_giaddr;
	uint64_t		 if_srvr_unknown;
};

struct packet_ctx {
	uint8_t			 pc_saddr[CHADDR_SIZE];
	uint8_t			 pc_daddr[CHADDR_SIZE];
	uint8_t			 pc_addrlen;
};

__dead void	 usage(void);
int		 rdaemon(int);

struct iface	*iface_get(const char *);
void		 iface_bpf_open(struct iface *);
int		 iface_cmp(const void *, const void *);
void		 iface_servers(struct iface *, int, char *[]);
void		 iface_siginfo(int, short, void *);

void		 dhcp_input(int, short, void *);
void		 dhcp_pkt_input(struct iface *, struct packet_ctx *,
		     const uint8_t *, size_t);
void		 dhcp_relay(struct iface *, struct packet_ctx *,
		     const void *, size_t);
void		 srvr_input(int, short, void *);
void		 srvr_relay(struct iface *, struct dhcp_giaddr *,
		     const char *, struct dhcp_packet *, size_t);

static uint32_t	 cksum_add(const void *, size_t, uint32_t);
static uint16_t	 cksum_fini(uint32_t);

static inline uint32_t
cksum_word(uint16_t word, uint32_t cksum)
{
	return (cksum + word);
}

#define cksum(_b, _l)	cksum_fini(cksum_add((_b), (_l), 0))

__dead void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-d] -i interface destination ...\n",
	    __progname);

	exit(1);
}

int
main(int argc, char *argv[])
{
	const char *ifname = NULL;
	int debug = 0;
	int ch;

	struct passwd *pw;
	int devnull = -1;

	struct iface *iface;
	unsigned int i;

	while ((ch = getopt(argc, argv, "di:")) != -1) {
		switch (ch) {
		case 'd':
			debug = 1;
			break;
		case 'i':
			if (ifname != NULL)
				usage();

			ifname = optarg;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	if (ifname == NULL)
		usage();

	argc -= optind;
	argv += optind;

	if (argc == 0)
		usage();

	if (geteuid() != 0)
		errx(1, "need root privileges");

	pw = getpwnam(DHCP_USER);
	if (pw == NULL)
		errx(1, "no %s user", DHCP_USER);

	iface = iface_get(ifname);
	if (iface->if_index == 0)
		errx(1, "Ethernet interface %s not found", ifname);
	if (iface->if_ngiaddrs == 0)
		errx(1, "interface %s no IPv4 addresses", ifname);

	iface_bpf_open(iface);

	iface->if_bpf_buf = malloc(iface->if_bpf_len * 2);
	if (iface->if_bpf_buf == NULL)
		err(1, "BPF buffer");

	for (i = 0; i < iface->if_ngiaddrs; i++) {
		struct dhcp_giaddr *gi = &iface->if_giaddrs[i];
		struct sockaddr_in *sin = &gi->gi_sin;
		int fd;
		int opt;

		gi->gi_name = strdup(inet_ntoa(sin->sin_addr));
		if (gi->gi_name == NULL)
			err(1, "gi name alloc");

		sin->sin_port = htons(SERVER_PORT);

		fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
		if (fd == -1)
			err(1, "socket");

		opt = 1;
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT,
		    &opt, sizeof(opt)) == -1)
			err(1, "setsockopt(SO_REUSEPORT)");

		if (bind(fd, sin2sa(sin), sizeof(*sin)) == -1)
			err(1, "bind to %s", inet_ntoa(sin->sin_addr));

		iface->if_giaddrs[i].gi_ev.ev_fd = fd;
	}

	iface_servers(iface, argc, argv);

	if (debug) {
		printf("interface address(es):");
		for (i = 0; i < iface->if_ngiaddrs; i++) {
			struct dhcp_giaddr *gi = &iface->if_giaddrs[i];
			printf(" %s", gi->gi_name);
		}
		printf("\n");

		printf("server address(es):");
		for (i = 0; i < iface->if_nservers; i++)
			printf(" %s", iface->if_server_names[i]);
		printf("\n");

		printf("BPF buffer length: %d\n", iface->if_bpf_len);
	} else {
		extern char *__progname;

		logger_syslog(__progname);

		devnull = open(_PATH_DEVNULL, O_RDWR, 0);
		if (devnull == -1)
			err(1, "%s", _PATH_DEVNULL);
	}

	if (chroot(pw->pw_dir) == -1)
		err(1, "chroot %s", pw->pw_dir);
	if (chdir("/") == -1)
		err(1, "chdir %s", pw->pw_dir);

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		errx(1, "can't drop privileges");

	if (!debug && rdaemon(devnull) == -1)
		err(1, "unable to daemonize");

	event_init();

	event_set(&iface->if_bpf_ev, iface->if_bpf_ev.ev_fd,
	    EV_READ | EV_PERSIST, dhcp_input, iface);
	event_add(&iface->if_bpf_ev, NULL);

	for (i = 0; i < iface->if_ngiaddrs; i++) {
		struct dhcp_giaddr *gi = &iface->if_giaddrs[i];

		event_set(&gi->gi_ev, gi->gi_ev.ev_fd, EV_READ | EV_PERSIST,
		    srvr_input, gi);
		event_add(&gi->gi_ev, NULL);
	}

	signal_set(&iface->if_siginfo, SIGINFO, iface_siginfo, iface);
	signal_add(&iface->if_siginfo, NULL);

	event_dispatch();

	return (0);
}

void
iface_siginfo(int sig, short events, void *arg)
{
	struct iface *iface = arg;

	linfo("bpf_short:%llu ether_len:%llu ip_len:%llu ip_cksum:%llu "
	    "udp_len:%llu udp_cksum:%llu dhcp_len:%llu dhcp_op:%llu "
	    "srvr_op:%llu srvr_giaddr:%llu srvr_unknown:%llu",
	    iface->if_bpf_short, iface->if_ether_len,
	    iface->if_ip_len, iface->if_ip_cksum,
	    iface->if_udp_len, iface->if_udp_cksum,
	    iface->if_dhcp_len, iface->if_dhcp_op,
	    iface->if_srvr_op, iface->if_srvr_giaddr, iface->if_srvr_unknown);
}

#if 0
static void
hexdump(const void *d, size_t datalen)
{
        const uint8_t *data = d;
        size_t i, j = 0;

        for (i = 0; i < datalen; i += j) {
                printf("%4zu: ", i);
                for (j = 0; j < 16 && i+j < datalen; j++)
                        printf("%02x ", data[i + j]);
                while (j++ < 16)
                        printf("   ");
                printf("|");
                for (j = 0; j < 16 && i+j < datalen; j++)
                        putchar(isprint(data[i + j]) ? data[i + j] : '.');
                printf("|\n");
        }
}
#endif

struct iface *
iface_get(const char *ifname)
{
	struct iface *iface;

	struct ifaddrs *ifas, *ifa;
	struct sockaddr_in *sin;
	struct dhcp_giaddr *giaddrs;
	struct sockaddr_dl *sdl;
	struct if_data *ifi;
	unsigned int o, n;

	iface = malloc(sizeof(*iface));
	if (iface == NULL)
		err(1, "iface alloc");

	memset(iface, 0, sizeof(*iface));

	if (getifaddrs(&ifas) == -1)
		err(1, "getifaddrs");

	for (ifa = ifas; ifa != NULL; ifa = ifa->ifa_next) {
		if ((ifa->ifa_flags & IFF_LOOPBACK) ||
		    (ifa->ifa_flags & IFF_POINTOPOINT))
			continue;

		if (!streq(ifa->ifa_name, ifname))
			continue;

		switch (ifa->ifa_addr->sa_family) {
		case AF_INET:
			sin = (struct sockaddr_in *)ifa->ifa_addr;
			if (sin->sin_addr.s_addr == htonl(INADDR_LOOPBACK))
				break;

			o = iface->if_ngiaddrs;
			n = o + 1;
			giaddrs = reallocarray(iface->if_giaddrs, n,
			    sizeof(*giaddrs));
			if (giaddrs == NULL)
				err(1, "giaddrs alloc");

			giaddrs[o].gi_if = iface;
			giaddrs[o].gi_sin = *sin;

			iface->if_giaddrs = giaddrs;
			iface->if_ngiaddrs = n;

			break;

		case AF_LINK:
			ifi = (struct if_data *)ifa->ifa_data;

			if (ifi->ifi_type != IFT_ETHER &&
			    ifi->ifi_type != IFT_CARP)
				break;

			sdl = (struct sockaddr_dl *)ifa->ifa_addr;

			if (sdl->sdl_alen > sizeof(iface->if_hwaddr))
				break; /* ? */

			iface->if_index = sdl->sdl_index;
			memcpy(iface->if_hwaddr, LLADDR(sdl), sdl->sdl_alen);
			iface->if_hwaddrlen = sdl->sdl_alen;
			break;

		default:
			break;
		}
	}

	freeifaddrs(ifas);
	iface->if_name = ifname;

	return (iface);
}

int
iface_cmp(const void *a, const void *b)
{
	const struct sockaddr_in *sina = a, *sinb = b;
	in_addr_t ina = ntohl(sina->sin_addr.s_addr);
	in_addr_t inb = ntohl(sinb->sin_addr.s_addr);

	if (ina > inb)
		return (1);
	if (ina < inb)
		return (-1);

	return (0);
}

void
iface_servers(struct iface *iface, int argc, char *argv[])
{
	const struct addrinfo hints = {
	    .ai_family = AF_INET,
	    .ai_socktype = SOCK_DGRAM,
	};
	struct addrinfo *res0, *res;
	const char *host;
	int error;
	int i;
	unsigned int s;

	for (i = 0; i < argc; i++) {
		host = argv[i];

		error = getaddrinfo(host, "bootps", &hints, &res0);
		if (error != 0)
			errx(1, "%s: %s", host, gai_strerror(error));

		for (res = res0; res != NULL; res = res->ai_next) {
			struct sockaddr_in *servers, *sin;
			unsigned int o, n;

			if (res->ai_addrlen > sizeof(*sin)) {
				/* XXX */
				continue;
			}

			sin = sa2sin(res->ai_addr);

			o = iface->if_nservers;
			n = o + 1;

			servers = reallocarray(iface->if_servers,
			    n, sizeof(*servers));
			if (servers == NULL)
				err(1, "server alloc");

			servers[o] = *sin;

			iface->if_servers = servers;
			iface->if_nservers = n;
		}

		freeaddrinfo(res0);
	}

	if (iface->if_nservers == 0)
		errx(1, "unable to resolve servers");

	qsort(iface->if_servers, iface->if_nservers,
	    sizeof(*iface->if_servers), iface_cmp);

	iface->if_server_names = reallocarray(NULL, iface->if_nservers,
	    sizeof(*iface->if_server_names));
	if (iface->if_server_names == NULL)
		err(1, "server name array alloc");

	for (s = 0; s < iface->if_nservers; s++) {
		struct sockaddr_in *sin = &iface->if_servers[s];

		iface->if_server_names[s] = strdup(inet_ntoa(sin->sin_addr));
		if (iface->if_server_names[s] == NULL)
			err(1, "server name alloc");
	}
}

/*
 * Packet filter program: 'ip and udp and dst port SERVER_PORT'
 */
/* const */ struct bpf_insn dhcp_bpf_rfilter[] = {
	/* Make sure this is "locally delivered" packet, ie, mcast/bcast */
	BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 0),
	BPF_JUMP(BPF_JMP + BPF_JSET + BPF_K, 1, 0, 10),

	/* Make sure this is an IP packet... */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IP, 0, 8),

	/* Make sure it's a UDP packet... */
	BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 23),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_UDP, 0, 6),

	/* Make sure this isn't a fragment... */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 20),
	BPF_JUMP(BPF_JMP + BPF_JSET + BPF_K, 0x1fff, 4, 0),

	/* Get the IP header length... */
	BPF_STMT(BPF_LDX + BPF_B + BPF_MSH, 14),

	/* Make sure it's to the right port... */
	BPF_STMT(BPF_LD + BPF_H + BPF_IND, 16),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, SERVER_PORT, 0, 1),

	/* If we passed all the tests, ask for the whole packet. */
	BPF_STMT(BPF_RET+BPF_K, (u_int)-1),

	/* Otherwise, drop it. */
	BPF_STMT(BPF_RET+BPF_K, 0),
};

void
iface_bpf_open(struct iface *iface)
{
	struct ifreq ifr;
	struct bpf_version v;
	struct bpf_program p;
	int opt;
	int fd;

	fd = open("/dev/bpf", O_RDWR|O_NONBLOCK);
	if (fd == -1)
		err(1, "/dev/bpf");

	if (ioctl(fd, BIOCVERSION, &v) == -1)
		err(1, "get BPF version");

	if (v.bv_major != BPF_MAJOR_VERSION || v.bv_minor < BPF_MINOR_VERSION)
		errx(1, "kerel BPF version is too high, recompile!");

	memset(&ifr, 0, sizeof(ifr));
	if (strlcpy(ifr.ifr_name, iface->if_name, sizeof(ifr.ifr_name)) >=
	    sizeof(ifr.ifr_name))
		errx(1, "interface name is too long");

	if (ioctl(fd, BIOCSETIF, &ifr) == -1)
		err(1, "unable to set BPF interface to %s", iface->if_name);

	opt = 1;
	if (ioctl(fd, BIOCIMMEDIATE, &opt) == -1)
		err(1, "unable to set BPF immediate mode");

	if (ioctl(fd, BIOCGBLEN, &opt) == -1)
		err(1, "unable to get BPF buffer length");

	if (opt < DHCP_FIXED_LEN) {
		errx(1, "BPF buffer length is too short: %d < %d",
		    opt, DHCP_FIXED_LEN);
	}

	p.bf_len = nitems(dhcp_bpf_rfilter);
	p.bf_insns = dhcp_bpf_rfilter;

	if (ioctl(fd, BIOCSETF, &p) == -1)
		err(1, "unable to set BPF read filter");

	if (ioctl(fd, BIOCLOCK) == -1)
		err(1, "unable to lock BPF descriptor");

	iface->if_bpf_ev.ev_fd = fd;
	iface->if_bpf_len = opt;
	iface->if_bpf_cur = 0;
}

void
dhcp_input(int fd, short events, void *arg)
{
	struct iface *iface = arg;
	struct packet_ctx pc;
	struct bpf_hdr hdr;
	size_t len, bpflen;
	ssize_t rv;
	uint8_t *buf = iface->if_bpf_buf;

	rv = read(fd, buf + iface->if_bpf_cur, iface->if_bpf_len);
	switch (rv) {
	case -1:
		switch (errno) {
		case EINTR:
		case EAGAIN:
			break;
		default:
			lerr(1, "BPF read");
			/* NOTREACHED */
		}
		return;
	case 0:
		lerrx(0, "BPF has closed");
		return;
	default:
		break;
	}

	len = iface->if_bpf_cur + rv;

	while (len >= sizeof(hdr)) {
		/* Copy out a bpf header... */
		memcpy(&hdr, buf, sizeof(hdr));
		bpflen = hdr.bh_hdrlen + hdr.bh_caplen;

		/*
		 * If the bpf header plus data doesn't fit in what's
		 * left of the buffer, stick head in sand yet again...
		 */
		if (bpflen > len)
			break;

		/*
		 * If the captured data wasn't the whole packet, or if
		 * the packet won't fit in the input buffer, all we can
		 * do is skip it.
		 */
		if (hdr.bh_caplen < hdr.bh_datalen)
			iface->if_bpf_short++;
		else {
			dhcp_pkt_input(iface, &pc,
			    buf + hdr.bh_hdrlen, hdr.bh_datalen);
		}

		bpflen = BPF_WORDALIGN(bpflen);
		if (len <= bpflen) {
			/* Short circuit if everything is consumed */
			iface->if_bpf_cur = 0;
			return;
		}

		/* Move the loop to the next packet */
		buf += bpflen;
		len -= bpflen;
	}

	if (len > iface->if_bpf_len) {
		lerrx(1, "len %zu > bpf len %u (iface=%p)", len,
		    iface->if_bpf_len, iface);
	}

	iface->if_bpf_cur = len;
	if (len && iface->if_bpf_buf != buf)
		memmove(iface->if_bpf_buf, buf, len);
}

void
dhcp_pkt_input(struct iface *iface, struct packet_ctx *pc,
    const uint8_t *pkt, size_t len)
{
	const struct ether_header *eh;
	struct ip iph;
	struct udphdr udph;
	unsigned int iplen, udplen;
	uint32_t cksum;
	uint16_t udpsum;

	if (len < sizeof(*eh)) {
		iface->if_ether_len++;
		return;
	}

	/* the bpf filter has already checked ether and ip proto types */

	eh = (const struct ether_header *)pkt;
	pkt += sizeof(*eh);
	len -= sizeof(*eh);

	if (len < sizeof(iph)) {
		iface->if_ip_len++;
		return;
	}

	memcpy(&iph, pkt, sizeof(iph));
	iplen = iph.ip_hl << 2;
	if (len < iplen) {
		iface->if_ip_len++;
		return;
	}

	if (cksum(pkt, iplen) != 0) {
		iface->if_ip_cksum++;
		return;
	}

	pkt += iplen;
	len -= iplen;

	if (len < sizeof(udph)) {
		iface->if_udp_len++;
		return;
	}

	memcpy(&udph, pkt, sizeof(udph));
	udplen = ntohs(udph.uh_ulen);
	if (len < udplen) {
		iface->if_udp_len++;
		return;
	}

	udpsum = udph.uh_sum;
	if (udpsum) {
		cksum = cksum_add(&iph.ip_src,
		    sizeof(iph.ip_src) + sizeof(iph.ip_dst), 0);
		cksum = cksum_word(IPPROTO_UDP, cksum);
		cksum = cksum_word(udplen, cksum);
		cksum = cksum_add(pkt, len, cksum);

		if (cksum_fini(cksum) != 0) {
			/* check for 0x0000? */
			iface->if_udp_cksum++;
			return;
		}
	}

	pkt += sizeof(udph);
	len = udplen - sizeof(udph); /* drop extra bytes */

	memcpy(pc->pc_saddr, eh->ether_shost, ETHER_ADDR_LEN);
	memcpy(pc->pc_daddr, eh->ether_dhost, ETHER_ADDR_LEN);
	pc->pc_addrlen = ETHER_ADDR_LEN;

	dhcp_relay(iface, pc, pkt, len);
}

void
dhcp_relay(struct iface *iface, struct packet_ctx *pc,
    const void *pkt, size_t len)
{
	static struct dhcp_packet *packet = NULL;
	static size_t pktlen = 0;

	unsigned int i, j;
	int giaddr = 0;

	if (len < BOOTP_MIN_LEN) {
		iface->if_dhcp_len++;
		return;
	}

	if (len > pktlen) {
		struct dhcp_packet *newpkt;

		newpkt = realloc(packet, len);
		if (newpkt == NULL) {
			lwarn("relay alloc");
			return;
		}

		packet = newpkt;
		pktlen = len;
	}

	memcpy(packet, pkt, len); /* align packet */
	if (packet->op != BOOTREQUEST) {
		iface->if_dhcp_op++;
		return;
	}

	if (packet->giaddr.s_addr == htonl(0))
		giaddr = 1;

	for (i = 0; i < iface->if_ngiaddrs; i++) {
		struct dhcp_giaddr *gi = &iface->if_giaddrs[i];

		if (giaddr)
			packet->giaddr = gi->gi_sin.sin_addr;

		for (j = 0; j < iface->if_nservers; j++) {
			struct sockaddr_in *sin = &iface->if_servers[j];

			if (sendto(EVENT_FD(&gi->gi_ev), packet, len, 0,
			    sin2sa(sin), sizeof(*sin)) == -1) {
				switch (errno) {
				case EAGAIN:
				case EINTR:
					break;
				default:
					err(1, "%s sendmsg",
					    inet_ntoa(sin->sin_addr));
				}
			}

			linfo("forwarded BOOTREQUEST for " ETHER_FMT
			    " from %s to %s", ETHER_ARGS(pc->pc_saddr),
			    gi->gi_name, iface->if_server_names[j]);
		}
	}
}

static uint32_t
cksum_add(const void *buf, size_t len, uint32_t sum)
{
	const uint16_t *words = buf;
	size_t nwords = len / sizeof(*words);
	size_t i;

	for (i = 0; i < nwords; i++)
		sum += ntohs(words[i]);

	if (len & 1) {
		const uint8_t *bytes = buf;
		sum += bytes[len - 1] << 8;
	}

	return (sum);
}

static uint16_t
cksum_fini(uint32_t sum)
{
	uint16_t cksum;

	cksum = sum;
	cksum += sum >> 16;

	return (~cksum);
}

void
srvr_input(int fd, short events, void *arg)
{
	struct dhcp_giaddr *gi = arg;
	struct iface *iface = gi->gi_if;
	uint8_t buf[4096];
	struct dhcp_packet *packet = (struct dhcp_packet *)buf;
	struct sockaddr_in sin;
	struct sockaddr_in *srvr;
	unsigned int s;
	socklen_t sinlen = sizeof(sin);
	ssize_t len;

	len = recvfrom(fd, buf, sizeof(buf), 0, sin2sa(&sin), &sinlen);
	switch (len) {
	case -1:
		switch (errno) {
		case EAGAIN:
		case EINTR:
			break;
		default:
			lerr(1, "udp recv");
		}
		return;
	case 0:
		lerrx(1, "udp has closed?");
	default:
		break;
	}

	if (sinlen < sizeof(sin))
		return;
	if (len < BOOTP_MIN_LEN)
		return;

	if (packet->op != BOOTREPLY) {
		iface->if_srvr_op++;
		return;
	}

	if (packet->giaddr.s_addr != gi->gi_sin.sin_addr.s_addr) {
		/* Filter packet that is not meant for us */
		iface->if_srvr_giaddr++;
		return;
	}

	if (packet->hlen > ETHER_ADDR_LEN) {
		/* nope */
		return;
	}

	srvr = bsearch(&sin, iface->if_servers, iface->if_nservers,
	    sizeof(*iface->if_servers), iface_cmp);
	if (srvr == NULL) {
		iface->if_srvr_unknown++;
		return;
	}
	s = srvr - iface->if_servers;

	srvr_relay(iface, gi, iface->if_server_names[s], packet, len);
}

void
srvr_relay(struct iface *iface, struct dhcp_giaddr *gi,
    const char *srvr_name, struct dhcp_packet *packet, size_t len)
{
	struct ether_header eh;
	struct {
		struct ip ip;
		struct udphdr udp;
	} l3h;
	struct ip *iph = &l3h.ip;
	struct udphdr *udph = &l3h.udp;
	struct iovec iov[3];
	uint32_t cksum;
	uint16_t udplen = sizeof(*udph) + len;
	ssize_t rv;

	/*
	 * VMware PXE "ROMs" confuse the DHCP gateway address
	 * with the IP gateway address. This is a problem if your
	 * DHCP relay is running on something that's not your
	 * network gateway.
	 *
	 * It is purely informational from the relay to the client
	 * so we can safely clear it.
	 */
	packet->giaddr.s_addr = htonl(0);

	if (packet->flags & htons(BOOTP_BROADCAST)) {
		memset(eh.ether_dhost, 0xff, sizeof(eh.ether_dhost));
		iph->ip_dst.s_addr = htonl(INADDR_BROADCAST);
	} else {
		/*
		 * We could unicast using sendto() with the giaddr socket,
		 * but the client may not have an ARP entry yet. Use BPF
		 * to send it because all the information is already here.
		 */
		memcpy(eh.ether_dhost, packet->chaddr, sizeof(eh.ether_dhost));
		iph->ip_dst = (packet->ciaddr.s_addr != htonl(0)) ?
		    packet->ciaddr : packet->yiaddr;
	}

	memcpy(eh.ether_shost, iface->if_hwaddr, sizeof(eh.ether_shost));
	eh.ether_type = htons(ETHERTYPE_IP);

	iph->ip_v = 4;
	iph->ip_hl = sizeof(*iph) >> 2;
	iph->ip_tos = IPTOS_LOWDELAY;
	iph->ip_len = htons(sizeof(l3h) + len);
	iph->ip_id = 0;
	iph->ip_off = 0;
	iph->ip_ttl = 16;
	iph->ip_p = IPPROTO_UDP;
	iph->ip_sum = htons(0);
	iph->ip_src = gi->gi_sin.sin_addr;

	iph->ip_sum = htons(cksum(iph, sizeof(*iph)));

	udph->uh_sport = gi->gi_sin.sin_port;
	udph->uh_dport = htons(CLIENT_PORT);
	udph->uh_ulen = htons(udplen);
	udph->uh_sum = htons(0);

	cksum = cksum_add(&iph->ip_src,
	    sizeof(iph->ip_src) + sizeof(iph->ip_dst), 0);
	cksum = cksum_word(IPPROTO_UDP, cksum);
	cksum = cksum_word(udplen, cksum);
	cksum = cksum_add(udph, sizeof(*udph), cksum);
	cksum = cksum_add(packet, len, cksum);

	udph->uh_sum = htons(cksum_fini(cksum));

	iov[0].iov_base = &eh;
	iov[0].iov_len = sizeof(eh);
	iov[1].iov_base = &l3h;
	iov[1].iov_len = sizeof(l3h);
	iov[2].iov_base = packet;
	iov[2].iov_len = len;

	rv = writev(EVENT_FD(&iface->if_bpf_ev), iov, nitems(iov));
	if (rv == -1) {
		switch (errno) {
		case EAGAIN:
		case EINTR:
			break;
		default:
			err(1, "bpf write");
		}

		/* oh well */
		return;
	}

	linfo("forwarded BOOTREPLY for " ETHER_FMT " from %s to %s",
	    ETHER_ARGS(packet->chaddr), srvr_name, gi->gi_name);
}

/* daemon(3) clone, intended to be used in a "r"estricted environment */
int
rdaemon(int devnull)
{
	if (devnull == -1) {
		errno = EBADF;
		return (-1);
	}
	if (fcntl(devnull, F_GETFL) == -1)
		return (-1);

	switch (fork()) {
	case -1:
		return (-1);
	case 0:
		break;
	default:
		_exit(0);
	}

	if (setsid() == -1)
		return (-1);

	(void)dup2(devnull, STDIN_FILENO);
	(void)dup2(devnull, STDOUT_FILENO);
	(void)dup2(devnull, STDERR_FILENO);
	if (devnull > 2)
		(void)close(devnull);

	return (0);
}

