/*	$OpenBSD: tftpd.c,v 1.39 2017/05/26 17:38:46 florian Exp $	*/

/*
 * Copyright (c) 2017, 2025, 2026 The University of Queensland
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

#include <net/route.h>

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
#include <stddef.h>

#include "dhcp.h"
#include "log.h"

#ifndef ISSET
#define ISSET(_v, _m)	((_v) & (_m))
#endif

#define SERVER_PORT	67
#define CLIENT_PORT	68
#define DHCP_USER	"_dhcp"
#define CHADDR_SIZE	16

#if 0
#define LLADDR_HELPER_PROCTITLE "lladdr helper"
#else
#define LLADDR_HELPER_PROCTITLE "arpendage"
#endif

struct dhcp_opt_header {
	uint8_t		code;
	uint8_t		len;
} __packed;

#define DHCP_MAX_MSG	(DHCP_MTU_MAX -					\
			    (sizeof(struct ip) + sizeof(struct udphdr)))

#define ETHER_FMT	"%02x:%02x:%02x:%02x:%02x:%02x"
#define ETHER_ARGS(_e)	(_e)[0], (_e)[1], (_e)[2], (_e)[3], (_e)[4], (_e)[5]

#define streq(_a, _b)	(strcmp(_a, _b) == 0)
#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

#ifndef roundup
#define roundup(x, y)	((((x)+((y)-1))/(y))*(y))
#endif

#define CMSG_FOREACH(_cmsg, _msgp) \
	for ((_cmsg) = CMSG_FIRSTHDR((_msgp)); \
	     (_cmsg) != NULL; \
	     (_cmsg) = CMSG_NXTHDR((_msgp), (_cmsg)))

static inline int
cmsg_match(const struct cmsghdr *cmsg, size_t len, int level, int type)
{
	return (cmsg->cmsg_len == CMSG_LEN(len) &&
	    cmsg->cmsg_level == level &&
	    cmsg->cmsg_type == type);
}

#define CMSG_MATCH(_cmsg, _len, _level, _type) \
	cmsg_match((_cmsg), (_len), (_level), (_type))

#define sin2sa(_sin)	(struct sockaddr *)(_sin)
#define sa2sin(_sa)	(struct sockaddr_in *)(_sa)

struct iface;

struct dhcp_helper {
	TAILQ_ENTRY(dhcp_helper)	 dh_entry;
	char				*dh_name;
};
TAILQ_HEAD(dhcp_helpers, dhcp_helper);

struct dhcp_giaddr {
	struct iface		*gi_if;
	struct sockaddr_in	 gi_addr;
	struct sockaddr_in	 gi_broadcast;
	struct event		 gi_ev;
	const char		*gi_name;
};

struct dhcp_server {
	struct sockaddr_in	 ds_addr; /* must be first */
	const char		*ds_name;
	unsigned int		 ds_helper;
};

struct dhcp_reply {
	uint8_t			 dr_buf[DHCP_MAX_MSG];
	size_t			 dr_len;
	struct dhcp_giaddr	*dr_gi;
	struct dhcp_server	*dr_ds;
};
#define IFACE_REPLY_RING_BITS	 4
#define IFACE_REPLY_RING_SIZE	 (1U << IFACE_REPLY_RING_BITS)
#define IFACE_REPLY_RING_MASK	 (IFACE_REPLY_RING_SIZE - 1)

struct iface {
	const char		*if_name;
	unsigned int		 if_index;
	u_char			 if_type;
	int			 if_nakfilt;

	struct dhcp_server	*if_servers;
	unsigned int		 if_nservers;

	uint8_t			 if_hwaddr[16];
	unsigned int		 if_hwaddrlen;
	uint32_t		 if_rdomain;

	struct dhcp_giaddr	*if_giaddrs;
	unsigned int		 if_ngiaddrs;
	struct dhcp_reply	 if_replies[IFACE_REPLY_RING_SIZE];
	unsigned int		 if_replies_head;
	unsigned int		 if_replies_tail;
	unsigned int		 if_rtseq;

	uint8_t			 if_hoplim;

	uint8_t			*if_rai;
	unsigned int		 if_railen;

	void			(*if_dhcp_relay)(struct iface *,
				      struct dhcp_packet *, size_t);
	void			(*if_srvr_relay)(struct iface *iface,
				      struct dhcp_giaddr *, const char *,
				      struct dhcp_packet *, size_t);

	struct event		 if_bcast_ev;
	struct event		 if_llh_ev;

	struct event		 if_siginfo;

	uint64_t		 if_bcast_short;
	uint64_t		 if_ether_len;
	uint64_t		 if_ip_len;
	uint64_t		 if_ip_cksum;
	uint64_t		 if_udp_len;
	uint64_t		 if_udp_cksum;
	uint64_t		 if_dhcp_len;
	uint64_t		 if_dhcp_opt_len;
	uint64_t		 if_dhcp_hlen;
	uint64_t		 if_dhcp_op;
	uint64_t		 if_dhcp_hops;
	uint64_t		 if_dhcp_nakfilt;
	uint64_t		 if_srvr_op;
	uint64_t		 if_srvr_giaddr;
	uint64_t		 if_srvr_unknown;
	uint64_t		 if_discards;
};

__dead void	 usage(void);
int		 rdaemon(int);

struct iface	*iface_get(const char *);
void		 iface_bcast_open(struct iface *);
ssize_t		 iface_bcast_recv(struct iface *, int, void *, size_t,
		     struct sockaddr_in *);
void		 iface_rai_set(struct iface *, const char *, const char *);
void		 iface_rai_add(struct iface *, uint8_t,  const char *,
		     const char *);
int		 iface_cmp(const void *, const void *);
void		 iface_servers(struct iface *, int, char *[]);
void		 iface_helpers(struct iface *, struct dhcp_helpers *);
void		 iface_siginfo(int, short, void *);

void		 dhcp_input(int, short, void *);
void		 dhcp_pkt_input(struct iface *, const uint8_t *, size_t);
void		 dhcp_relay(struct iface *,
		     uint8_t [static DHCP_MAX_MSG], size_t,
		     const struct sockaddr_in *);
void		 dhcp_if_relay(struct iface *, struct dhcp_packet *, size_t);
void		 dhcp_if_relay_rai(struct iface *, struct dhcp_packet *,
		     size_t);
void		 srvr_input(int, short, void *);
void		 srvr_relay_rai(struct iface *, struct dhcp_giaddr *,
		     const char *, struct dhcp_packet *, size_t);
void		 srvr_relay(struct iface *, struct dhcp_giaddr *,
		     const char *, struct dhcp_packet *, size_t);

static int	 lladdr_helper(struct iface *, int);
static void	 lladdr_reply(int, short, void *);
static int	 lladdr_add(struct iface *, struct dhcp_reply *);

__dead void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-dv] "
	    "[-C circuit] [-R remote] [-H hoplim] [-h helper]\n"
	    "    -i interface destination ...\n",
	    __progname);

	exit(1);
}

int verbose = 0;

int
main(int argc, char *argv[])
{
	const char *errstr;
	const char *ifname = NULL;
	const char *circuit = NULL;
	const char *remote = NULL;
	int nakfilt = 0;
	int debug = 0;
	int hoplim = -1;
	struct dhcp_helpers helpers = TAILQ_HEAD_INITIALIZER(helpers);
	int ch;

	struct passwd *pw;
	int devnull = -1;

	struct iface *iface;
	struct dhcp_helper *dh;
	unsigned int i;

	while ((ch = getopt(argc, argv, "C:dh:H:i:NR:v")) != -1) {
		switch (ch) {
		case 'C':
			if (circuit != NULL)
				usage();
			circuit = optarg;
			break;
		case 'd':
			debug = verbose = 1;
			break;
		case 'h':
			dh = malloc(sizeof(*dh));
			if (dh == NULL)
				err(1, NULL);

			dh->dh_name = optarg;

			TAILQ_INSERT_TAIL(&helpers, dh, dh_entry);
			break;

		case 'H':
			if (hoplim != -1)
				usage();
			hoplim = strtonum(optarg, 1, 16, &errstr);
			if (errstr != NULL)
				errx(1, "hop limit: %s", errstr);
			break;
		case 'i':
			if (ifname != NULL)
				usage();

			ifname = optarg;
			break;
		case 'N':
			nakfilt = 1;
			break;
		case 'R':
			if (remote != NULL)
				usage();
			remote = optarg;
			break;
		case 'v':
			verbose = 1;
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
	if (setrtable(iface->if_rdomain) == -1)
		err(1, "setrtable %s rdomain %u", ifname, iface->if_rdomain);

	if (hoplim != -1)
		iface->if_hoplim = hoplim;

	iface_bcast_open(iface);
	iface_rai_set(iface, circuit, remote);

	for (i = 0; i < iface->if_ngiaddrs; i++) {
		struct ip_mreqn mreqn = {
			.imr_ifindex = iface->if_index,
		};
		struct dhcp_giaddr *gi = &iface->if_giaddrs[i];
		struct sockaddr_in *sin = &gi->gi_addr;
		int fd;
		int opt;
		u_char loop;

		gi->gi_name = strdup(inet_ntoa(sin->sin_addr));
		if (gi->gi_name == NULL)
			err(1, "gi name alloc");

		sin->sin_port = htons(SERVER_PORT);

		fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
		if (fd == -1)
			err(1, "%s socket", gi->gi_name);

		if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF,
		    &mreqn, sizeof(mreqn)) == -1)
			err(1, "%s set IP_MULTICAST_IF", gi->gi_name);

		opt = 1;
		if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST,
		    &opt, sizeof(opt)) == -1)
			err(1, "%s enable SO_BROADCAST", gi->gi_name);

		loop = 0;
		if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP,
		    &loop, sizeof(loop)) == -1) {
			err(1, "%s disable IP_MULTICAST_LOOP", gi->gi_name);
		}

		if (bind(fd, sin2sa(sin), sizeof(*sin)) == -1)
			err(1, "bind to %s", gi->gi_name);

		event_set(&gi->gi_ev, fd, 0, NULL, NULL);
	}

	iface_servers(iface, argc, argv);
	iface_helpers(iface, &helpers);

	qsort(iface->if_servers, iface->if_nservers,
	    sizeof(*iface->if_servers), iface_cmp);

	if (debug) {
		printf("interface address(es):");
		for (i = 0; i < iface->if_ngiaddrs; i++) {
			struct dhcp_giaddr *gi = &iface->if_giaddrs[i];
			printf(" %s", gi->gi_name);
		}
		printf("\n");

		printf("server address(es):");
		for (i = 0; i < iface->if_nservers; i++) {
			struct dhcp_server *ds = &iface->if_servers[i];
			printf(" %s", ds->ds_name);
			if (ds->ds_helper)
				printf(" (helper)");
		}
		printf("\n");
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
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid))
		errx(1, "can't drop privileges");

	iface->if_llh_ev.ev_fd = lladdr_helper(iface, devnull);

	if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		errx(1, "can't drop privileges");

	if (!debug && rdaemon(devnull) == -1)
		err(1, "unable to daemonize");

	event_init();

	event_set(&iface->if_bcast_ev, iface->if_bcast_ev.ev_fd,
	    EV_READ | EV_PERSIST, dhcp_input, iface);
	event_add(&iface->if_bcast_ev, NULL);

	event_set(&iface->if_llh_ev, iface->if_llh_ev.ev_fd,
	    EV_READ | EV_PERSIST, lladdr_reply, iface);
	event_add(&iface->if_llh_ev, NULL);

	for (i = 0; i < iface->if_ngiaddrs; i++) {
		struct dhcp_giaddr *gi = &iface->if_giaddrs[i];

		event_set(&gi->gi_ev, gi->gi_ev.ev_fd, EV_READ | EV_PERSIST,
		    srvr_input, gi);
		event_add(&gi->gi_ev, NULL);
	}

	iface->if_nakfilt = nakfilt;

	signal_set(&iface->if_siginfo, SIGINFO, iface_siginfo, iface);
	signal_add(&iface->if_siginfo, NULL);

	event_dispatch();

	return (0);
}

void
iface_siginfo(int sig, short events, void *arg)
{
	struct iface *iface = arg;

	linfo("iface:%s bcast_short:%llu ether_len:%llu "
	    "ip_len:%llu ip_cksum:%llu "
	    "udp_len:%llu udp_cksum:%llu "
	    "dhcp_len:%llu dhcp_opt_len:%llu dhcp_op:%llu "
	    "dhcp_hops:%llu dhcp_nakfilt:%llu "
	    "srvr_op:%llu srvr_giaddr:%llu srvr_unknown:%llu discards:%llu",
	    iface->if_name, iface->if_bcast_short, iface->if_ether_len,
	    iface->if_ip_len, iface->if_ip_cksum,
	    iface->if_udp_len, iface->if_udp_cksum,
	    iface->if_dhcp_len, iface->if_dhcp_opt_len, iface->if_dhcp_op,
	    iface->if_dhcp_hops, iface->if_dhcp_nakfilt,
	    iface->if_srvr_op, iface->if_srvr_giaddr, iface->if_srvr_unknown,
	    iface->if_discards);
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
			giaddrs[o].gi_addr = *sin;

			sin = &giaddrs[o].gi_broadcast;
			*sin = *(struct sockaddr_in *)ifa->ifa_broadaddr;
			if (sin->sin_addr.s_addr == htonl(INADDR_ANY))
				sin->sin_addr.s_addr = htonl(INADDR_BROADCAST);

			iface->if_giaddrs = giaddrs;
			iface->if_ngiaddrs = n;

			break;

		case AF_LINK:
			ifi = (struct if_data *)ifa->ifa_data;

			if (ifi->ifi_type != IFT_ETHER)
				break;

			sdl = (struct sockaddr_dl *)ifa->ifa_addr;

			if (sdl->sdl_alen > sizeof(iface->if_hwaddr))
				break; /* ? */

			iface->if_index = sdl->sdl_index;
			memcpy(iface->if_hwaddr, LLADDR(sdl), sdl->sdl_alen);
			iface->if_hwaddrlen = sdl->sdl_alen;

			iface->if_type = ifi->ifi_type;
			iface->if_rdomain = ifi->ifi_rdomain;
			break;

		default:
			break;
		}
	}

	freeifaddrs(ifas);
	iface->if_name = ifname;
	iface->if_hoplim = 16;

	iface->if_dhcp_relay = dhcp_if_relay;
	iface->if_srvr_relay = srvr_relay;

	return (iface);
}

int
iface_cmp(const void *a, const void *b)
{
	const struct dhcp_server *dsa = a, *dsb = b;
	const struct sockaddr_in *sina = &dsa->ds_addr;
	const struct sockaddr_in *sinb = &dsb->ds_addr;
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

	for (i = 0; i < argc; i++) {
		host = argv[i];

		error = getaddrinfo(host, "bootps", &hints, &res0);
		if (error != 0)
			errx(1, "%s: %s", host, gai_strerror(error));

		for (res = res0; res != NULL; res = res->ai_next) {
			struct dhcp_server *servers, *server;
			unsigned int o, n;

			if (res->ai_addrlen > sizeof(servers->ds_addr)) {
				/* XXX */
				continue;
			}

			o = iface->if_nservers;
			n = o + 1;

			servers = reallocarray(iface->if_servers,
			    n, sizeof(*servers));
			if (servers == NULL)
				err(1, "server alloc");

			server = &servers[o];
			server->ds_addr = *sa2sin(res->ai_addr);
			server->ds_name = strdup(
			    inet_ntoa(server->ds_addr.sin_addr));
			if (server->ds_name == NULL)
				err(1, "server name alloc");

			server->ds_helper = 0;

			iface->if_servers = servers;
			iface->if_nservers = n;
		}

		freeaddrinfo(res0);
	}

	if (iface->if_nservers == 0)
		errx(1, "unable to resolve servers");
}

void
iface_helpers(struct iface *iface, struct dhcp_helpers *helpers)
{
	const struct addrinfo hints = {
	    .ai_family = AF_INET,
	    .ai_socktype = SOCK_DGRAM,
	};
	struct addrinfo *res0, *res;
	struct dhcp_helper *dh;
	char *host, *port;
	int error;

	while ((dh = TAILQ_FIRST(helpers)) != NULL) {
		TAILQ_REMOVE(helpers, dh, dh_entry);
		port = dh->dh_name;
		free(dh);

		host = strsep(&port, ":");

		error = getaddrinfo(host, port, &hints, &res0);
		if (error != 0) {
			errx(1, "%s port %s: %s", host, port ? port : "*",
			    gai_strerror(error));
		}

		for (res = res0; res != NULL; res = res->ai_next) {
			struct dhcp_server *servers, *server;
			unsigned int o, n;

			if (res->ai_addrlen > sizeof(servers->ds_addr)) {
				/* XXX */
				continue;
			}

			o = iface->if_nservers;
			n = o + 1;

			servers = reallocarray(iface->if_servers,
			    n, sizeof(*servers));
			if (servers == NULL)
				err(1, "server alloc");

			server = &servers[o];
			server->ds_addr = *sa2sin(res->ai_addr);
			server->ds_name = strdup(
			    inet_ntoa(server->ds_addr.sin_addr));
			if (server->ds_name == NULL)
				err(1, "server name alloc");

			server->ds_helper = 1;

			iface->if_servers = servers;
			iface->if_nservers = n;
		}

		freeaddrinfo(res0);
	}
}

void
iface_bcast_open(struct iface *iface)
{
	static const struct sockaddr_in sin = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_BROADCAST),
		.sin_port = htons(SERVER_PORT),
	};
	int opt;
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
	if (fd == -1)
		err(1, "%s broadcast socket", iface->if_name);

	opt = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) == -1)
		err(1, "%s broadcast enable SO_REUSEADDR", iface->if_name);

	opt = 1;
	if (setsockopt(fd, IPPROTO_IP, IP_RECVIF, &opt, sizeof(opt)) == -1)
		err(1, "%s broadcast enable IP_RECVIF", iface->if_name);

	if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) == -1)
		err(1, "%s broadcast bind", iface->if_name);

	if (shutdown(fd, SHUT_WR) == -1)
		err(1, "%s broadcast send shutdown", iface->if_name);

	event_set(&iface->if_bcast_ev, fd, 0, NULL, NULL);
}

void
iface_rai_add(struct iface *iface, uint8_t code, const char *value,
    const char *name)
{
	struct dhcp_opt_header *hdr;
	size_t vlen, olen, rlen, nlen;

	vlen = strlen(value);
	olen = sizeof(*hdr) + vlen;
	if (olen > DHCP_OPTION_MAXLEN)
		errx(1, "%s: too long", name);

	rlen = iface->if_railen;
	nlen = rlen + olen;
	iface->if_rai = realloc(iface->if_rai, nlen);
	if (iface->if_rai == NULL)
		err(1, "%s", name);

	hdr = (struct dhcp_opt_header *)(iface->if_rai + rlen);
	hdr->code = code;
	hdr->len = vlen;
	memcpy(hdr + 1, value, vlen);

	iface->if_railen = nlen;
}

void
iface_rai_set(struct iface *iface, const char *circuit, const char *remote)
{
	struct dhcp_opt_header *hdr;
	size_t len;

	if (circuit == NULL && remote == NULL)
		return;

	iface->if_rai = NULL;
	iface->if_railen = sizeof(*hdr);

	if (circuit != NULL)
		iface_rai_add(iface, RAI_CIRCUIT_ID, circuit, "Circuit ID");

	if (remote != NULL)
		iface_rai_add(iface, RAI_REMOTE_ID, remote, "Remote ID");

	len = iface->if_railen - sizeof(*hdr);
	if (len > DHCP_OPTION_MAXLEN)
		errx(1, "Relay Agent Information: too long");

	hdr = (struct dhcp_opt_header *)iface->if_rai;
	hdr->code = DHO_RELAY_AGENT_INFORMATION;
	hdr->len = len;

	iface->if_dhcp_relay = dhcp_if_relay_rai;
	iface->if_srvr_relay = srvr_relay_rai;
}

ssize_t
iface_bcast_recv(struct iface *iface, int fd, void *buf, size_t len,
    struct sockaddr_in *src)
{
	const struct sockaddr_dl *sdl;
	struct iovec iov[1] = {
		{ .iov_base = buf, .iov_len = len },
	};
	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(*sdl))];
	} cmsgbuf;
	struct msghdr msg = {
		.msg_name = src,
		.msg_namelen = sizeof(*src),
		.msg_iov = iov,
		.msg_iovlen = nitems(iov),
		.msg_control = &cmsgbuf.buf,
		.msg_controllen = sizeof(cmsgbuf.buf),
	};
	struct cmsghdr *cmsg;
	ssize_t rv;

	rv = recvmsg(fd, &msg, 0);
	if (rv == -1) {
		switch (errno) {
		case EINTR:
		case EAGAIN:
			return (0);
		default:
			break;
		}
		return (rv);
	}

	CMSG_FOREACH(cmsg, &msg) {
		if (CMSG_MATCH(cmsg, sizeof(*sdl), IPPROTO_IP, IP_RECVIF))
			sdl = (struct sockaddr_dl *)CMSG_DATA(cmsg);
	}

	if (iface->if_index != sdl->sdl_index)
		return (0);

	return (rv);
}

void
dhcp_input(int fd, short events, void *arg)
{
	struct iface *iface = arg;
	size_t len;
	ssize_t rv;
	uint8_t buf[DHCP_MAX_MSG];
	struct sockaddr_in src;

	rv = iface_bcast_recv(iface, fd, buf, sizeof(buf), &src);
	switch (rv) {
	case -1:
		lerr(1, "%s bcast read", iface->if_name);
		/* NOTREACHED */
	case 0:
		/* the message wasn't for us */
		return;
	default:
		break;
	}

	len = rv;

	dhcp_relay(iface, buf, len, &src);
}

void
dhcp_relay(struct iface *iface,
    uint8_t buf[static DHCP_MAX_MSG], size_t len,
    const struct sockaddr_in *src)
{
	struct dhcp_packet *packet = (struct dhcp_packet *)buf;
	ssize_t olen;
	uint8_t hops;

	/*
	 * Apple firmware sometimes generates packets without padding the
	 * options field. Technically not correct, but as long as the
	 * non-optional fields are there it can work.
	 */
	if (len < offsetof(struct dhcp_packet, cookie)) {
		iface->if_dhcp_len++;
		return;
	}

	if (packet->op != BOOTREQUEST) {
		iface->if_dhcp_op++;
		return;
	}

	hops = packet->hops;
	if (hops > iface->if_hoplim) {
		iface->if_dhcp_hops++;
		return;
	}
	packet->hops = ++hops;

	if (packet->hlen != ETHER_ADDR_LEN) {
		iface->if_dhcp_hlen++;
		return;
	}

	if (packet->giaddr.s_addr != htonl(0)) {
		/* don't support relay chaining yet */
		return;
	}

	olen = BOOTP_MIN_LEN - len;
	if (olen > 0) {
		iface->if_dhcp_opt_len++;
		memset(buf + len, 0, olen);
		len = BOOTP_MIN_LEN;
	}

	(*iface->if_dhcp_relay)(iface, packet, len);
}

static ssize_t
dhcp_opt_end(const uint8_t *opts, size_t olen, uint8_t match)
{
	size_t i = 0;
	uint8_t len;

	while (i < olen) {
		uint8_t code = opts[i];
		if (code == match)
			return (i);

		switch (opts[i]) {
		case DHO_PAD:
			i++;
			break;
		case DHO_END:
			return (-1);
		case DHO_RELAY_AGENT_INFORMATION:
			/* relay chaining unsupported */
			return (-1);
		default:
			i++;
			if (i >= olen) {
				/* too short */
				return (-1);
			}
			len = opts[i];
			i += len + 1;
			break;
		}
	}

	return (0);
}

void
dhcp_if_relay_rai(struct iface *iface, struct dhcp_packet *packet, size_t len)
{
	ssize_t olen;
	size_t nlen;
	uint8_t *opts;

	if (memcmp(packet->cookie, DHCP_OPTIONS_COOKIE,
	    sizeof(packet->cookie)) != 0) {
		/* invalid signature */
		return;
	}

	opts = (uint8_t *)(packet + 1);
	olen = dhcp_opt_end(opts, len - sizeof(*packet), DHO_END);
	if (olen == -1) {
		/* too short or unsupported opts */
		return;
	}
	len = sizeof(*packet) + olen;

	nlen = len + iface->if_railen;
	if (nlen >= DHCP_MAX_MSG) {
		/* not enough space */
		return;
	}

	opts += olen;
	memcpy(opts, iface->if_rai, iface->if_railen);
	opts += iface->if_railen;
	*opts = DHO_END;

	if (nlen < BOOTP_MIN_LEN)
		nlen = BOOTP_MIN_LEN;

	dhcp_if_relay(iface, packet, nlen);
}

void
dhcp_if_relay(struct iface *iface, struct dhcp_packet *packet, size_t len)
{
	unsigned int i, j;
	int giaddr;

	giaddr = packet->giaddr.s_addr == htonl(0);

	for (i = 0; i < iface->if_ngiaddrs; i++) {
		struct dhcp_giaddr *gi = &iface->if_giaddrs[i];

		if (giaddr)
			packet->giaddr = gi->gi_addr.sin_addr;

		for (j = 0; j < iface->if_nservers; j++) {
			struct dhcp_server *ds = &iface->if_servers[j];
			struct sockaddr_in *sin;

			if (ds->ds_helper)
				continue;

			sin = &ds->ds_addr;

			if (sendto(EVENT_FD(&gi->gi_ev), packet, len, 0,
			    sin2sa(sin), sizeof(*sin)) == -1) {
				switch (errno) {
				case EACCES:
				case EHOSTUNREACH:
				case ENETUNREACH:
				case EHOSTDOWN:
				case ENETDOWN:
					lwarn("%s sendmsg",
					    inet_ntoa(sin->sin_addr));
					/* FALLTHROUGH */
				case ENOBUFS:
				case EAGAIN:
				case EINTR:
					/* skip to the next one */
					continue;
				default:
					lerr(1, "%s fatal sendmsg",
					    inet_ntoa(sin->sin_addr));
				}
			}

			if (verbose) {
				linfo("forwarded BOOTREQUEST for "
				    ETHER_FMT " xid %08x on %s from %s to %s",
				    ETHER_ARGS(packet->chaddr),
				    ntohl(packet->xid), iface->if_name,
				    gi->gi_name, ds->ds_name);
			}
		}
	}
}

static struct dhcp_server *
dhcp_validate(struct iface *iface, struct dhcp_giaddr *gi,
    const void *buf, size_t len,
    const struct sockaddr_in *sin, socklen_t sinlen)
{
	const struct dhcp_packet *packet = buf;
	struct dhcp_server *ds;

	if (len < BOOTP_MIN_LEN)
		return (NULL);
	if (sinlen < sizeof(sin))
		return (NULL);

	if (packet->op != BOOTREPLY) {
		iface->if_srvr_op++;
		return (NULL);
	}

	if (packet->giaddr.s_addr != gi->gi_addr.sin_addr.s_addr) {
		/* Filter packet that is not meant for us */
		iface->if_srvr_giaddr++;
		return (NULL);
	}

	if (packet->hlen != ETHER_ADDR_LEN) {
		/* nope */
		iface->if_dhcp_hlen++;
		return (NULL);
	}

	if (iface->if_nakfilt) {
		uint8_t mlen;
		const uint8_t *opts = (const uint8_t *)(packet + 1);
		ssize_t orv = dhcp_opt_end(opts, len - sizeof(*packet),
		    DHO_DHCP_MESSAGE_TYPE);
		size_t olen;
		if (orv == -1) {
			/* too short or missing opts */
			iface->if_dhcp_len++;
			return (NULL);
		}
		olen = orv;

		olen++; /* move to the len */
		if (olen >= len) {
			/* too short */
			iface->if_dhcp_len++;
			return (NULL);
		}

		mlen = opts[olen];
		if (mlen != 1) {
			/* unknown message length */
			iface->if_dhcp_len++;
			return (NULL);
		}

		olen++; /* move to the value */
		if (olen >= len) {
			/* too short */
			iface->if_dhcp_len++;
			return (NULL);
		}

		if (opts[olen] == DHCPNAK) {
			/* filter */
			iface->if_dhcp_nakfilt++;
			return (NULL);
		}
	}

	if (memcmp(packet->cookie, DHCP_OPTIONS_COOKIE,
	    sizeof(packet->cookie)) != 0) {
		/* invalid signature */
		return (NULL);
	}

	ds = bsearch(sin, iface->if_servers, iface->if_nservers,
	    sizeof(*iface->if_servers), iface_cmp);
	if (ds == NULL) {
		iface->if_srvr_unknown++;
		return (NULL);
	}

	return (ds);
}

static void
srvr_discard(int fd, struct iface *iface, struct dhcp_giaddr *gi)
{
	uint8_t buf[DHCP_MAX_MSG];
	struct sockaddr_in sin;
	socklen_t sinlen = sizeof(sin);
	struct dhcp_server *ds;
	ssize_t rv;

	rv = recvfrom(fd, buf, sizeof(buf), 0, sin2sa(&sin), &sinlen);
	if (rv == -1) {
		switch (errno) {
		case EINTR:
		case EAGAIN:
			break;
		default:
			lwarn("%s discard recv", gi->gi_name);
			break;
		}
		return;
	}

	iface->if_discards++;

	ds = dhcp_validate(iface, gi, buf, rv, &sin, sinlen);
	if (ds == NULL)
		return;

	if (verbose) {
		const struct dhcp_packet *packet =
		    (const struct dhcp_packet *)buf;

		linfo("discarding BOOTREPLY for " ETHER_FMT " xid %08x on %s"
		    " from %s to %s", ETHER_ARGS(packet->chaddr),
		    ntohl(packet->xid), iface->if_name,
		    ds->ds_name, gi->gi_name);
	}
}

void
srvr_input(int fd, short events, void *arg)
{
	struct dhcp_giaddr *gi = arg;
	struct iface *iface = gi->gi_if;
	struct dhcp_reply *dr;
	struct dhcp_packet *packet;
	struct sockaddr_in sin;
	socklen_t sinlen = sizeof(sin);
	struct dhcp_server *ds;
	ssize_t rv;
	unsigned int diff, head;

	head = iface->if_replies_head;
	diff = head - iface->if_replies_tail;
	if (diff >= nitems(iface->if_replies)) {
		srvr_discard(fd, iface, gi);
		return;
	}

	dr = &iface->if_replies[head++ & IFACE_REPLY_RING_MASK];

	rv = recvfrom(fd, dr->dr_buf, sizeof(dr->dr_buf), 0,
	    sin2sa(&sin), &sinlen);
	if (rv == -1) {
		switch (errno) {
		case EAGAIN:
		case EINTR:
			break;
		default:
			lerr(1, "%s udp recv", gi->gi_name);
			/* NOTREACHED */
		}
		return;
	}
	dr->dr_len = rv;

	ds = dhcp_validate(iface, gi, dr->dr_buf, dr->dr_len, &sin, sinlen);
	if (ds == NULL)
		return;

	dr->dr_gi = gi;
	dr->dr_ds = ds;

	packet = (struct dhcp_packet *)dr->dr_buf;
	if (packet->ciaddr.s_addr == htonl(0) &&
	    packet->yiaddr.s_addr == htonl(0)) {
		/* we can't inject arp for this */
		(*iface->if_srvr_relay)(iface, dr->dr_gi, dr->dr_ds->ds_name,
		    packet, dr->dr_len);
		return;
	}

	if (lladdr_add(iface, dr) == -1)
		return;
	iface->if_replies_head = head;
}

void
srvr_relay_rai(struct iface *iface, struct dhcp_giaddr *gi,
    const char *srvr_name, struct dhcp_packet *packet, size_t len)
{
	ssize_t olen;
	ssize_t diff;
	uint8_t *opts;

	if (memcmp(packet->cookie, DHCP_OPTIONS_COOKIE,
	    sizeof(packet->cookie)) != 0) {
		/* invalid signature */
		return;
	}

	opts = (uint8_t *)(packet + 1);
	olen = dhcp_opt_end(opts, len - sizeof(*packet),
	    DHO_RELAY_AGENT_INFORMATION);
	if (olen == -1) {
		/* too short or missing opts */
		return;
	}

	if ((len - olen) < iface->if_railen) {
		/* not enough space */
		return;
	}

	opts += olen;
	if (memcmp(opts, iface->if_rai, iface->if_railen) != 0) {
		/* option is wrong */
		return;
	}
	*opts = DHO_END;

	len -= iface->if_railen;

	diff = BOOTP_MIN_LEN - len;
	if (diff > 0) {
		memset((uint8_t *)packet + len, 0, diff);
		len = BOOTP_MIN_LEN;
	}

	srvr_relay(iface, gi, srvr_name, packet, len);
}

void
srvr_relay(struct iface *iface, struct dhcp_giaddr *gi,
    const char *srvr_name, struct dhcp_packet *packet, size_t len)
{
	struct sockaddr_in sin = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_BROADCAST),
		.sin_port = htons(CLIENT_PORT),
	};
	ssize_t rv;

	if (!ISSET(packet->flags, htons(BOOTP_BROADCAST))) {
		if (packet->ciaddr.s_addr != htonl(0))
			sin.sin_addr = packet->ciaddr;
		else if (packet->yiaddr.s_addr != htonl(0))
			sin.sin_addr = packet->yiaddr;
		else
			sin.sin_addr = gi->gi_broadcast.sin_addr;
	}

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

	rv = sendto(EVENT_FD(&gi->gi_ev), packet, len, 0,
	    sin2sa(&sin), sizeof(sin));
	if (rv == -1) {
		switch (errno) {
		case EAGAIN:
		case EINTR:
			return;

		case ENOMEM:
		case ENOBUFS:
		case EHOSTDOWN:
		case EHOSTUNREACH:
		case ENETDOWN:
		case ENETUNREACH:
		case EMSGSIZE:
			break;

		default:
			lwarn("%s %s sendto %s", iface->if_name, gi->gi_name,
			    inet_ntoa(sin.sin_addr));
			break;
		}

		/* oh well */
		return;
	}

	if (verbose) {
		linfo("forwarded BOOTREPLY for " ETHER_FMT " xid %08x on %s"
		    " from %s to %s to %s", ETHER_ARGS(packet->chaddr),
		    ntohl(packet->xid), iface->if_name, srvr_name,
		    gi->gi_name, inet_ntoa(sin.sin_addr));
	}
}

static void
lladdr_reply(int fd, short events, void *arg)
{
	struct rt_msghdr rtm;
	struct iface *iface = arg;
	struct dhcp_reply *dr;
	unsigned int tail;
	ssize_t rv;
	size_t len;
	//unsigned int seq;

	rv = recv(fd, &rtm, sizeof(rtm), 0);
	if (rv == -1) {
		switch (errno) {
		case EAGAIN:
		case EINTR:
			break;
		default:
			lwarn("lladdr helper reply");
			break;
		}

		return;
	}
	len = rv;
	if (len == 0)
		lerrx(1, "lladdr helper has gone");
	if (len < sizeof(rtm))
		lerrx(1, "lladdr helper: short reply");

	tail = iface->if_replies_tail;
	if (iface->if_replies_head == tail)
		lerrx(1, "unexpected lladdr reply");

	//seq = rtm.rtm_seq;

	dr = &iface->if_replies[tail++ & IFACE_REPLY_RING_MASK];

	if (rtm.rtm_errno != 0) {
		lwarnc(rtm.rtm_errno, "%s", __func__);
	} else {
		(*iface->if_srvr_relay)(iface, dr->dr_gi, dr->dr_ds->ds_name,
		    (struct dhcp_packet *)dr->dr_buf, dr->dr_len);
	}

	iface->if_replies_tail = tail;
}

#define RTMSG_SPACE(_s) roundup(_s, sizeof(long))
#define RTMSG_NEXT(_s) (void *)((uint8_t *)(_s) + RTMSG_SPACE(sizeof(*_s)))

static int
lladdr_add(struct iface *iface, struct dhcp_reply *dr)
{
	const struct dhcp_packet *packet =
	    (const struct dhcp_packet *)dr->dr_buf;
	ssize_t rv;

	struct rt_msghdr *rtm;
	struct sockaddr_in *sin;
	struct sockaddr_dl *sdl;

	uint8_t rtmsg[RTMSG_SPACE(sizeof(*rtm)) +
	    RTMSG_SPACE(sizeof(*sin)) + /* RTA_DST */
	    RTMSG_SPACE(sizeof(*sdl)) + /* RTA_GATEWAY */
	    RTMSG_SPACE(sizeof(*sin)) + /* RTA_NETMASK */
	    RTMSG_SPACE(sizeof(*sdl)) + /* RTA_IFP */
	    RTMSG_SPACE(sizeof(*sin))]; /* RTA_IFA */

	memset(rtmsg, 0, sizeof(rtmsg));

	rtm = (struct rt_msghdr *)rtmsg;
	rtm->rtm_msglen = sizeof(rtmsg);
	rtm->rtm_version = RTM_VERSION;
	rtm->rtm_type = RTM_ADD;
	rtm->rtm_hdrlen = sizeof(*rtm);
	rtm->rtm_index = iface->if_index;
	rtm->rtm_tableid = iface->if_rdomain;
	rtm->rtm_priority = RTP_CONNECTED - 1; /* XXX */
	rtm->rtm_flags = RTF_UP | RTF_HOST | RTF_LLINFO;
	rtm->rtm_addrs =
	    RTA_DST | RTA_GATEWAY | RTA_NETMASK | RTA_IFP | RTA_IFA;
	rtm->rtm_seq = ++iface->if_rtseq;

	rtm->rtm_inits = RTV_EXPIRE;
	rtm->rtm_rmx.rmx_expire = time(NULL) + 1200;

	/* DST */
	sin = RTMSG_NEXT(rtm);
	sin->sin_len = sizeof(*sin);
	sin->sin_family = AF_INET;
	sin->sin_addr = (packet->ciaddr.s_addr != htonl(0)) ?
	    packet->ciaddr : packet->yiaddr;

	/* GATEWAY */
	sdl = RTMSG_NEXT(sin);
	sdl->sdl_len = sizeof(*sdl);
	sdl->sdl_family = AF_LINK;
	sdl->sdl_alen = packet->hlen;
	memcpy(LLADDR(sdl), packet->chaddr, sdl->sdl_alen);

	/* NETMASK */
	sin = RTMSG_NEXT(sdl);
	sin->sin_len = sizeof(*sin);
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(0xffffffff);

	/* IFP */
	sdl = RTMSG_NEXT(sin);
	sdl->sdl_len = sizeof(*sdl);
	sdl->sdl_family = AF_LINK;
	sdl->sdl_index = iface->if_index;
	sdl->sdl_type = IFT_ETHER;
	sdl->sdl_nlen = strlen(iface->if_name);
	memcpy(sdl->sdl_data, iface->if_name, sdl->sdl_nlen);
	sdl->sdl_alen = iface->if_hwaddrlen;
	memcpy(LLADDR(sdl), iface->if_hwaddr, sdl->sdl_alen);

	/* IFA */
	sin = RTMSG_NEXT(sdl);
	*sin = dr->dr_gi->gi_addr;
	sin->sin_len = sizeof(*sin);

	rv = send(EVENT_FD(&iface->if_llh_ev), rtmsg, sizeof(rtmsg), 0);
	if (rv == -1) {
		lwarn("lladdr helper send");
		return (-1);
	}

	return (0);
}

static void
lladdr_rtmsg(int fd, int rtsock)
{
	char rtmsg[1024]; /* XXX magic */
	struct rt_msghdr *rtm = (struct rt_msghdr *)rtmsg;
	ssize_t rv;
	size_t len;
	//unsigned int seq;

	rv = recv(fd, rtmsg, sizeof(rtmsg), 0);
	if (rv == -1) {
		switch (errno) {
		case EINTR:
		case EAGAIN:
			break;
		default:
			lwarn("lladdr helper request");
		}
		return;
	}
	len = rv;

	if (rtm->rtm_version != RTM_VERSION)
		lerrx(1, "lladdr helper: request rtm_version invalid");
	if (rtm->rtm_type != RTM_ADD)
		lerrx(1, "lladdr helper: request rtm_type invalid");
	if (rtm->rtm_hdrlen != sizeof(*rtm))
		lerrx(1, "lladdr helper: request rtm_hdrlen invalid");
	if (rtm->rtm_msglen >= sizeof(rtmsg))
		lerrx(1, "lladdr helper: request rtm_msglen is too long");
	if (rtm->rtm_msglen != len)
               lerrx(1, "lladdr helper: request rtm_msglen is wrong");
	if (rtm->rtm_flags &
	    ~(RTF_UP | RTF_HOST | RTF_LLINFO | RTF_STATIC | RTF_MPATH)) {
		lerrx(1,
		    "lladdr helper: request rtm_flags has unexpected bits");
	}
	if (rtm->rtm_addrs &
	    ~(RTA_DST | RTA_GATEWAY | RTA_NETMASK | RTA_IFP | RTA_IFA)) {
		lerrx(1,
		    "lladdr helper: request rtm_addrs has unexpected bits");
	}
	if (rtm->rtm_inits & ~(RTV_EXPIRE)) {
		lerrx(1,
		    "lladdr helper: request rtm_inits has unexpected bits");
	}

	/* XXX check more? */

	//seq = rtm->rtm_seq;

	rtm->rtm_errno = 0;
	rv = send(rtsock, rtmsg, len, 0);
	if (rv == -1) {
		/* handle if there's an existing LLFINO entry */
		if (errno == EEXIST) {
			rtm->rtm_type = RTM_CHANGE;
			/* We want this flag clear if the kernel has it set. */
			rtm->rtm_fmask = RTF_REJECT;

			rv = send(rtsock, rtmsg, len, 0);
			if (rv == -1)
				rtm->rtm_errno = errno;
		} else
			rtm->rtm_errno = errno;
	}

	/* Report back to the main process what happened */
	rv = send(fd, rtm, sizeof(*rtm), 0);
	if (rv == -1)
		lerr(1, "lladdr helper: unable to reply");
}

static void
lladdr_closefrom(struct iface *iface)
{
	size_t i;

	close(iface->if_bcast_ev.ev_fd);

	for (i = 0; i < iface->if_ngiaddrs; i++) {
		struct dhcp_giaddr *gi = &iface->if_giaddrs[i];
		close(gi->gi_ev.ev_fd);
	}
}

static int
lladdr_helper(struct iface *iface, int devnull)
{
	int llhpair[2];
	int rtsock;

	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0,
	    llhpair) == -1)
		err(1, "lladdr handler socketpair");

	switch (fork()) {
	case -1:
		err(1, "lladdr handler fork");
		/* NOTREACHED */

	case 0: /* child */
		break;

	default: /* parent */
		close(llhpair[0]);
		return (llhpair[1]);
	}

	setproctitle("%s %s", iface->if_name, LLADDR_HELPER_PROCTITLE);
	close(llhpair[1]);
	lladdr_closefrom(iface);

	rtsock = socket(AF_ROUTE, SOCK_RAW, 0); /* we can block on rtsock */
	if (rtsock == -1)
		err(1, "route socket");

	/* no filesystem visibility */
	if (unveil("/", "") == -1)
		err(1, "lladdr helper unveil");
	if (unveil(NULL, NULL) == -1)
		err(1, "router helper unveil fini");

	if (devnull != -1 && rdaemon(devnull) == -1)
		err(1, "lladdr helper unable to daemonize");

	for (;;) {
		struct pollfd pfd[] = {
			{ .fd = llhpair[0], .events = POLLIN },
		};
		int nfds = poll(pfd, nitems(pfd), -1);
		if (nfds == -1) {
			if (errno != EINTR)
				lwarn("poll");
			continue;
		}
		if (nfds == 0)
			continue;

		if (pfd[0].revents & POLLHUP)
			lerrx(1, "lladdr helper: ipc socket closed");

		if (pfd[0].revents & POLLIN)
			lladdr_rtmsg(llhpair[0], rtsock);
	}

	exit(1);
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

