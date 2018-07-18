/*	$OpenBSD: arc4random.c,v 1.23 2012/06/24 18:25:12 matthew Exp $	*/

/*
 * Copyright (c) 1996, David Mazieres <dm@uun.org>
 * Copyright (c) 2008, Damien Miller <djm@openbsd.org>
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
 * Arc4 random number generator for OpenBSD.
 *
 * This code is derived from section 17.1 of Applied Cryptography,
 * second edition, which describes a stream cipher allegedly
 * compatible with RSA Labs "RC4" cipher (the actual description of
 * which is a trade secret).  The same algorithm is used as a stream
 * cipher called "arcfour" in Tatu Ylonen's ssh package.
 *
 * RC4 is a registered trademark of RSA Laboratories.
 */

#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/sysctl.h>

/********** LINUX ***********/
#ifdef __LINUX__

/* Linux compatibility code, by 
 * Vincent Strubel <clipos@ssi.gouv.fr>
 */

#ifdef LINUX_THREADS
#include <pthread.h>

static pthread_mutex_t arc4_mutex = PTHREAD_MUTEX_INITIALIZER;

#define _ARC4_LOCK() \
	pthread_mutex_lock(&arc4_mutex);

#define _ARC4_UNLOCK() \
	pthread_mutex_unlock(&arc4_mutex);

#else 

#define _ARC4_LOCK()
#define _ARC4_UNLOCK()

#endif

#ifndef RANDOM_DEVICE
#define RANDOM_DEVICE		"/dev/urandom"
#endif

#include <errno.h>

static int random_fd;

#else /* __LINUX__ */

#include "thread_private.h"

#endif /* __LINUX__ */
#ifdef __GNUC__
#define inline __inline
#else				/* !__GNUC__ */
#define inline
#endif				/* !__GNUC__ */

struct arc4_stream {
	u_int8_t i;
	u_int8_t j;
	u_int8_t s[256];
};

static int rs_initialized;
static struct arc4_stream rs;
static pid_t arc4_stir_pid;
static int arc4_count;

static inline u_int8_t arc4_getbyte(void);

static inline void
arc4_init(void)
{
	int     n;

	for (n = 0; n < 256; n++)
		rs.s[n] = n;
	rs.i = 0;
	rs.j = 0;
}

static inline void
arc4_addrandom(u_char *dat, int datlen)
{
	int     n;
	u_int8_t si;

	rs.i--;
	for (n = 0; n < 256; n++) {
		rs.i = (rs.i + 1);
		si = rs.s[rs.i];
		rs.j = (rs.j + si + dat[n % datlen]);
		rs.s[rs.i] = rs.s[rs.j];
		rs.s[rs.j] = si;
	}
	rs.j = rs.i;
}

#ifdef __LINUX__

static void
arc4_stir(void)
{
	u_char rnd[128];
	size_t	len = sizeof(rnd);
	ssize_t rlen;
	u_char *ptr = rnd;
	unsigned int i;

	if (!rs_initialized) {
		arc4_init();
		rs_initialized = 1;
	}

	if (!random_fd) {
		/* Called under lock anyway, no race */
		random_fd = open(RANDOM_DEVICE, O_RDONLY);
		if (random_fd < 0)
			abort();
		fcntl(random_fd, FD_CLOEXEC);
	}

	while (len) {
		rlen = read(random_fd, ptr, len);
		if (rlen < 0) {
			if (errno == EINTR)
				continue;
			/* Pull the other one, it's got bells on */
			abort();
		}
		len -= rlen;
		ptr += rlen;
	}

	arc4_addrandom(rnd, sizeof(rnd));

	/*
	 * Discard early keystream, as per recommendations in:
	 * http://www.wisdom.weizmann.ac.il/~itsik/RC4/Papers/Rc4_ksa.ps
	 */
	for (i = 0; i < 256; i++)
		(void)arc4_getbyte();
	arc4_count = 1600000;
}

#else /* __LINUX__ */

static void
arc4_stir(void)
{
	int     i, mib[2];
	size_t	len;
	u_char rnd[128];

	if (!rs_initialized) {
		arc4_init();
		rs_initialized = 1;
	}

	mib[0] = CTL_KERN;
	mib[1] = KERN_ARND;

	len = sizeof(rnd);
	sysctl(mib, 2, rnd, &len, NULL, 0);

	arc4_addrandom(rnd, sizeof(rnd));

	/*
	 * Discard early keystream, as per recommendations in:
	 * http://www.wisdom.weizmann.ac.il/~itsik/RC4/Papers/Rc4_ksa.ps
	 */
	for (i = 0; i < 256; i++)
		(void)arc4_getbyte();
	arc4_count = 1600000;
}

#endif /* __LINUX__ */

static void
arc4_stir_if_needed(void)
{
	pid_t pid = getpid();

	if (arc4_count <= 0 || !rs_initialized || arc4_stir_pid != pid)
	{
		arc4_stir_pid = pid;
		arc4_stir();
	}
}

static inline u_int8_t
arc4_getbyte(void)
{
	u_int8_t si, sj;

	rs.i = (rs.i + 1);
	si = rs.s[rs.i];
	rs.j = (rs.j + si);
	sj = rs.s[rs.j];
	rs.s[rs.i] = sj;
	rs.s[rs.j] = si;
	return (rs.s[(si + sj) & 0xff]);
}

static inline 
arc4_getword(void)
{
	u_int32_t val;
	val = arc4_getbyte() << 24;
	val |= arc4_getbyte() << 16;
	val |= arc4_getbyte() << 8;
	val |= arc4_getbyte();
	return val;
}

void __attribute__((visibility("hidden")))
arc4random_stir(void)
{
	_ARC4_LOCK();
	arc4_stir();
	_ARC4_UNLOCK();
}

void __attribute__((visibility("hidden")))
arc4random_addrandom(u_char *dat, int datlen)
{
	_ARC4_LOCK();
	if (!rs_initialized)
		arc4_stir();
	arc4_addrandom(dat, datlen);
	_ARC4_UNLOCK();
}

u_int32_t __attribute__((visibility("hidden")))
arc4random(void)
{
	u_int32_t val;
	_ARC4_LOCK();
	arc4_count -= 4;
	arc4_stir_if_needed();
	val = arc4_getword();
	_ARC4_UNLOCK();
	return val;
}

void __attribute__((visibility("hidden")))
arc4random_buf(void *_buf, size_t n)
{
	u_char *buf = (u_char *)_buf;
	_ARC4_LOCK();
	arc4_stir_if_needed();
	while (n--) {
		if (--arc4_count <= 0)
			arc4_stir();
		buf[n] = arc4_getbyte();
	}
	_ARC4_UNLOCK();
}

/*
 * Calculate a uniformly distributed random number less than upper_bound
 * avoiding "modulo bias".
 *
 * Uniformity is achieved by generating new random numbers until the one
 * returned is outside the range [0, 2**32 % upper_bound).  This
 * guarantees the selected random number will be inside
 * [2**32 % upper_bound, 2**32) which maps back to [0, upper_bound)
 * after reduction modulo upper_bound.
 */
u_int32_t  __attribute__((visibility("hidden")))
arc4random_uniform(u_int32_t upper_bound)
{
	u_int32_t r, min;

	if (upper_bound < 2)
		return 0;

	/* 2**32 % x == (2**32 - x) % x */
	min = -upper_bound % upper_bound;

	/*
	 * This could theoretically loop forever but each retry has
	 * p > 0.5 (worst case, usually far better) of selecting a
	 * number inside the range we need, so it should rarely need
	 * to re-roll.
	 */
	for (;;) {
		r = arc4random();
		if (r >= min)
			break;
	}

	return r % upper_bound;
}

#if 0
/*-------- Test code for i386 --------*/
#include <stdio.h>
#include <machine/pctr.h>
int
main(int argc, char **argv)
{
	const int iter = 1000000;
	int     i;
	pctrval v;

	v = rdtsc();
	for (i = 0; i < iter; i++)
		arc4random();
	v = rdtsc() - v;
	v /= iter;

	printf("%qd cycles\n", v);
}
#endif
