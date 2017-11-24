# $OpenBSD: Makefile,v 1.4 2017/04/05 14:43:14 reyk Exp $

.include <bsd.own.mk>

PROG=	dhcp-relay
SRCS=	dhcp-relay.c
SRCS+=	log.c
MAN=	

LDADD=  -levent
DPADD=  ${LIBEVENT}

CFLAGS+=-Wall
CFLAGS+=-Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=-Wmissing-declarations
CFLAGS+=-Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=-Wsign-compare
DEBUG=-g

.include <bsd.prog.mk>
