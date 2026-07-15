/*
 * slab_mon - SheavesSiphon buddy return detector
 * Run as root in a separate terminal while exploit runs.
 *
 * Usage: sudo ./slab_mon [interval_ms]
 *   default interval: 50ms
 *
 * Monitors ALL kmalloc-*-512 caches.
 * Silent until num_slabs drops -> prints only the cache that dropped.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

#define MAX_CACHES 32

struct cache_snap {
	char name[64];
	unsigned long active_objs;
	unsigned long num_objs;
	unsigned long num_slabs;
	unsigned long active_slabs;
};

static volatile int g_run = 1;

static void sig_handler(int s) { (void)s; g_run = 0; }

static int snap_512(struct cache_snap *out, int max) {
	FILE *fp;
	char line[1024], name[64], *sd;
	unsigned long ao, no, os, ops2, pps, as2, ns;
	int n = 0;

	fp = fopen("/proc/slabinfo", "r");
	if (!fp) 
		return 0;
	while (fgets(line, sizeof(line), fp) && n < max) {
		if (!strstr(line, "-512"))
			continue;
		if (!strstr(line, "kmalloc"))
			continue;
		/* skip sub-caches like kmalloc-rnd-06-8 that match "-512" in name but aren't 512 */
		if (sscanf(line, "%63s %lu %lu %lu %lu %lu", name, &ao, &no, &os, &ops2, &pps) < 6)
			continue;
		if (os != 512)
			continue;
		as2 = 0; ns = 0;
		sd = strstr(line, "slabdata");
		if (sd)
			sscanf(sd, "slabdata %lu %lu", &as2, &ns);
		strcpy(out[n].name, name);
		out[n].active_objs = ao;
		out[n].num_objs = no;
		out[n].num_slabs = ns;
		out[n].active_slabs = as2;
		n++;
	}
	fclose(fp);

	return n;
}

static inline double ts_sec(void) {
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);

	return t.tv_sec + t.tv_nsec / 1e9;
}

int main(int argc, char *argv[]) {
	int interval_ms = 50;
	struct cache_snap prev[MAX_CACHES], cur[MAX_CACHES];
	int nprev, ncur, i, j, detected = 0;
	double t0, now;
	char *filter = NULL;

	if (argc > 1)
		filter = argv[1];
	if (argc > 2)
		interval_ms = atoi(argv[2]);
	if (interval_ms < 5)
		interval_ms = 5;
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	if (filter)
		printf("\033[1;36m[slab_mon] watching %s (interval %dms)\033[0m\n", filter, interval_ms);
	else
		printf("\033[1;36m[slab_mon] watching ALL kmalloc-*-512 (interval %dms)\033[0m\n", interval_ms);
	printf("\033[1;36m[slab_mon] silent until buddy return detected...\033[0m\n\n");
	nprev = snap_512(prev, MAX_CACHES);
	t0 = ts_sec();
	while (g_run) {
		usleep(interval_ms * 1000);
		ncur = snap_512(cur, MAX_CACHES);
		now = ts_sec() - t0;
		for (i = 0; i < ncur; i++) {
			if (filter && strcmp(cur[i].name, filter) != 0)
				continue;
			/* find matching cache in prev */
			for (j = 0; j < nprev; j++) {
				if (strcmp(cur[i].name, prev[j].name) == 0)
					break;
			}
			if (j >= nprev)
				continue;
			/* check: num_slabs dropped? */
			if (cur[i].num_slabs < prev[j].num_slabs) {
				long delta = (long)prev[j].num_slabs - (long)cur[i].num_slabs;
				printf("\033[1;32m[R2B +%.1fs] %s: %lu→%lu slabs (-%ld) | "
				       "active: %lu→%lu | objs: %lu→%lu -> BUDDY RETURN \033[0m\n",
				       now, cur[i].name,
				       prev[j].num_slabs, cur[i].num_slabs, delta,
				       prev[j].active_objs, cur[i].active_objs,
				       prev[j].num_objs, cur[i].num_objs);
				detected++;
			}
		}
		/* update prev */
		memcpy(prev, cur, sizeof(cur));
		nprev = ncur;
	}
	printf("\n\033[1;36m[slab_mon] stopped. detected %d buddy return events.\033[0m\n", detected);

	return 0;
}
