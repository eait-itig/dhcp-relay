/*	$OpenBSD$ */

/*
 * Copyright (c) 2008 David Gwynne <loki@animata.net>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <syslog.h>
#include <errno.h>
#include <err.h>

#include "log.h"

static const struct loggers conslogger = {
	errc,
	errx,
	warnc,
	warnx,
	warnx
};

const struct loggers *logger = &conslogger;

static __dead void	syslog_errc(int, int, const char *, ...)
			    __attribute__((__format__ (printf, 3, 4)));
static __dead void	syslog_errx(int, const char *, ...)
			    __attribute__((__format__ (printf, 2, 3)));
static void		syslog_warnc(int, const char *, ...);
static void		syslog_warnx(const char *, ...);
static void		syslog_info(const char *, ...);
static void		syslog_vstrerror(int, int, const char *, va_list);

static const struct loggers syslogger = {
	syslog_errc,
	syslog_errx,
	syslog_warnc,
	syslog_warnx,
	syslog_info,
};

static void
syslog_vstrerror(int code, int priority, const char *fmt, va_list ap)
{
	char *s;

	if (vasprintf(&s, fmt, ap) == -1) {
		syslog(LOG_EMERG, "unable to alloc in syslog_vstrerror");
		exit(1);
	}

	syslog(priority, "%s: %s", s, strerror(code));

	free(s);
}

static void
syslog_errc(int eval, int code, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	syslog_vstrerror(code, LOG_EMERG, fmt, ap);
	va_end(ap);

	exit(eval);
}

static void
syslog_errx(int eval, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(LOG_WARNING, fmt, ap);
	va_end(ap);

	exit(eval);
}

static void
syslog_warnc(int code, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	syslog_vstrerror(code, LOG_WARNING, fmt, ap);
	va_end(ap);
}

static void
syslog_warnx(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(LOG_WARNING, fmt, ap);
	va_end(ap);
}

static void
syslog_info(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(LOG_INFO, fmt, ap);
	va_end(ap);
}

void
logger_syslog(const char *ident)
{
	openlog(ident, LOG_PID|LOG_NDELAY, LOG_DAEMON);
	tzset();

	logger = &syslogger;
}
