#pragma once

#include <osmocom/core/timer.h>
#include <osmocom/core/timer_compat.h>

#define clock_debug(fmt, args...) \
	do { \
		struct timespec ts; \
		struct timeval tv; \
		osmo_clock_gettime(CLOCK_MONOTONIC, &ts); \
		osmo_gettimeofday(&tv, NULL); \
		fprintf(stdout, "sys={%lu.%06lu}, mono={%lu.%06lu}: " fmt "\n", \
			tv.tv_sec, tv.tv_usec, ts.tv_sec, ts.tv_nsec/1000, ##args); \
	} while (0)

static void clock_override_enable(bool enable)
{
	osmo_gettimeofday_override = enable;
	osmo_clock_override_enable(CLOCK_MONOTONIC, enable);
}

static void clock_override_set(long sec, long usec)
{
	struct timespec *mono;
	osmo_gettimeofday_override_time.tv_sec = sec;
	osmo_gettimeofday_override_time.tv_usec = usec;
	mono = osmo_clock_override_gettimespec(CLOCK_MONOTONIC);
	mono->tv_sec = sec;
	mono->tv_nsec = usec*1000;

	clock_debug("clock_override_set");
}

static inline void clock_override_add_debug(long sec, long usec, bool dbg)
{
	osmo_gettimeofday_override_add(sec, usec);
	osmo_clock_override_add(CLOCK_MONOTONIC, sec, usec*1000);
	if (dbg)
		clock_debug("clock_override_add");
}
#define clock_override_add(sec, usec) clock_override_add_debug(sec, usec, true)
