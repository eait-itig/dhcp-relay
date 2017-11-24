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

#ifndef _LOG_H_
#define _LOG_H_

struct loggers {
	__dead void	(*errc)(int, int, const char *, ...)
			    __attribute__((__format__ (printf, 3, 4)));
	__dead void	(*errx)(int, const char *, ...)
			    __attribute__((__format__ (printf, 2, 3)));
	void		(*warnc)(int, const char *, ...)
			    __attribute__((__format__ (printf, 2, 3)));
	void		(*warnx)(const char *, ...)
			    __attribute__((__format__ (printf, 1, 2)));
	void		(*info)(const char *, ...)
			    __attribute__((__format__ (printf, 1, 2)));
};

extern const struct loggers *logger;

void	logger_syslog(const char *);

#define lerrc(_e, _c,  _f...)	logger->errc((_e), (_c), _f)
#define lerrx(_e, _f...)	logger->errx((_e), _f)
#define lwarnc(_c, _f...)	logger->warnc((_c), _f)
#define lwarnx(_f...)		logger->warnx(_f)
#define linfo(_f...)		logger->info(_f)

#define lerr(_e, _f...)		lerrc((_e), errno, _f)
#define lwarn(_f...)		lwarnc(errno, _f)

#endif /* _LOG_H_ */
