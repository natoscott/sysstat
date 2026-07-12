/*
 * pcp_mpstat.c: Read CPU statistics from a PCP archive for mpstat.
 * (C) 2026 Red Hat, Inc.
 * (C) 2025-2026 by Sebastien Godard (sysstat <at> orange.fr)
 *
 * Implements "mpstat -a <archive>".  Populates the same globals that
 * mpstat's live read path fills (st_cpu, uptime_cs, mp_tstamp, cpu_nr)
 * then calls the existing write_stats() display function unchanged.
 *
 * PCP delivers CPU times in milliseconds; the globals expect jiffies.
 * Conversion: jiffies = ms * hz / 1000.
 */

#ifdef HAVE_PCP

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <pcp/pmapi.h>

#include "common.h"
#include "rd_stats.h"
#include "mpstat.h"
#include "pcp_def_metrics.h"
#include "pcp_mpstat.h"

#include <locale.h>
#ifdef USE_NLS
# include <libintl.h>
# define _(s) gettext(s)
#else
# define _(s) (s)
#endif

/* Functions defined in mpstat.c */
void write_stats(int curr, int dis);

/* Globals owned by mpstat.c that we populate */
extern struct stats_cpu    *st_cpu[3];
extern unsigned long long   uptime_cs[3];
extern struct tm            mp_tstamp[3];
extern int                  cpu_nr;
extern uint64_t             actflags;
extern uint64_t             xflags;
extern unsigned int         flags;

/* PMIDs — use values from pcp_def_metrics.h, already the correct PMIDs */
enum {
	PCP_MPSTAT_PERCPU_USER,
	PCP_MPSTAT_PERCPU_NICE,
	PCP_MPSTAT_PERCPU_SYS,
	PCP_MPSTAT_PERCPU_IDLE,
	PCP_MPSTAT_PERCPU_IOWAIT,
	PCP_MPSTAT_PERCPU_HARDIRQ,
	PCP_MPSTAT_PERCPU_SOFTIRQ,
	PCP_MPSTAT_PERCPU_STEAL,
	PCP_MPSTAT_PERCPU_GUEST,
	PCP_MPSTAT_PERCPU_GUESTNICE,
	PCP_MPSTAT_ALLCPU_USER,
	PCP_MPSTAT_ALLCPU_NICE,
	PCP_MPSTAT_ALLCPU_SYS,
	PCP_MPSTAT_ALLCPU_IDLE,
	PCP_MPSTAT_ALLCPU_IOWAIT,
	PCP_MPSTAT_ALLCPU_HARDIRQ,
	PCP_MPSTAT_ALLCPU_SOFTIRQ,
	PCP_MPSTAT_ALLCPU_STEAL,
	PCP_MPSTAT_ALLCPU_GUEST,
	PCP_MPSTAT_ALLCPU_GUESTNICE,
	PCP_MPSTAT_NR
};

static pmID pcp_mpstat_pmids[PCP_MPSTAT_NR] = {
	[PCP_MPSTAT_PERCPU_USER]      = PMID_CPU_PERCPU_USER,
	[PCP_MPSTAT_PERCPU_NICE]      = PMID_CPU_PERCPU_NICE,
	[PCP_MPSTAT_PERCPU_SYS]       = PMID_CPU_PERCPU_SYS,
	[PCP_MPSTAT_PERCPU_IDLE]      = PMID_CPU_PERCPU_IDLE,
	[PCP_MPSTAT_PERCPU_IOWAIT]    = PMID_CPU_PERCPU_WAITTOTAL,
	[PCP_MPSTAT_PERCPU_HARDIRQ]   = PMID_CPU_PERCPU_IRQHARD,
	[PCP_MPSTAT_PERCPU_SOFTIRQ]   = PMID_CPU_PERCPU_IRQSOFT,
	[PCP_MPSTAT_PERCPU_STEAL]     = PMID_CPU_PERCPU_STEAL,
	[PCP_MPSTAT_PERCPU_GUEST]     = PMID_CPU_PERCPU_GUEST,
	[PCP_MPSTAT_PERCPU_GUESTNICE] = PMID_CPU_PERCPU_GUESTNICE,
	[PCP_MPSTAT_ALLCPU_USER]      = PMID_CPU_ALLCPU_USER,
	[PCP_MPSTAT_ALLCPU_NICE]      = PMID_CPU_ALLCPU_NICE,
	[PCP_MPSTAT_ALLCPU_SYS]       = PMID_CPU_ALLCPU_SYS,
	[PCP_MPSTAT_ALLCPU_IDLE]      = PMID_CPU_ALLCPU_IDLE,
	[PCP_MPSTAT_ALLCPU_IOWAIT]    = PMID_CPU_ALLCPU_WAITTOTAL,
	[PCP_MPSTAT_ALLCPU_HARDIRQ]   = PMID_CPU_ALLCPU_IRQHARD,
	[PCP_MPSTAT_ALLCPU_SOFTIRQ]   = PMID_CPU_ALLCPU_IRQSOFT,
	[PCP_MPSTAT_ALLCPU_STEAL]     = PMID_CPU_ALLCPU_STEAL,
	[PCP_MPSTAT_ALLCPU_GUEST]     = PMID_CPU_ALLCPU_GUEST,
	[PCP_MPSTAT_ALLCPU_GUESTNICE] = PMID_CPU_ALLCPU_GUESTNICE,
};

static unsigned long long
scalar_u64(pmValueSet *vset)
{
	pmAtomValue atom;

	if (!vset || vset->numval <= 0)
		return 0;
	if (pmExtractValue(vset->valfmt, &vset->vlist[0],
			   PM_TYPE_U64, &atom, PM_TYPE_U64) < 0)
		return 0;
	return atom.ull;
}

static unsigned long long
inst_u64(pmValueSet *vset, int inst_id)
{
	int i;

	if (!vset) return 0;
	for (i = 0; i < vset->numval; i++) {
		if (vset->vlist[i].inst == inst_id) {
			pmAtomValue atom;

			if (pmExtractValue(vset->valfmt, &vset->vlist[i],
					   PM_TYPE_U64, &atom, PM_TYPE_U64) < 0)
				return 0;
			return atom.ull;
		}
	}
	return 0;
}

#define MS_TO_J(ms) ((ms) * hz / 1000)

static void
build_cpu_snap(int s, pmResult *result)
{
	pmValueSet *vs[PCP_MPSTAT_NR];
	struct stats_cpu *scc;
	int m, i;

	memset(vs, 0, sizeof(vs));
	for (m = 0; m < result->numpmid; m++) {
		int idx;

		for (idx = 0; idx < PCP_MPSTAT_NR; idx++) {
			if (result->vset[m]->pmid == pcp_mpstat_pmids[idx]) {
				vs[idx] = result->vset[m];
				break;
			}
		}
	}

	/* Slot 0: all-CPU aggregate */
	scc = &st_cpu[s][0];
	scc->cpu_user       = MS_TO_J(scalar_u64(vs[PCP_MPSTAT_ALLCPU_USER]));
	scc->cpu_nice       = MS_TO_J(scalar_u64(vs[PCP_MPSTAT_ALLCPU_NICE]));
	scc->cpu_sys        = MS_TO_J(scalar_u64(vs[PCP_MPSTAT_ALLCPU_SYS]));
	scc->cpu_idle       = MS_TO_J(scalar_u64(vs[PCP_MPSTAT_ALLCPU_IDLE]));
	scc->cpu_iowait     = MS_TO_J(scalar_u64(vs[PCP_MPSTAT_ALLCPU_IOWAIT]));
	scc->cpu_hardirq    = MS_TO_J(scalar_u64(vs[PCP_MPSTAT_ALLCPU_HARDIRQ]));
	scc->cpu_softirq    = MS_TO_J(scalar_u64(vs[PCP_MPSTAT_ALLCPU_SOFTIRQ]));
	scc->cpu_steal      = MS_TO_J(scalar_u64(vs[PCP_MPSTAT_ALLCPU_STEAL]));
	scc->cpu_guest      = MS_TO_J(scalar_u64(vs[PCP_MPSTAT_ALLCPU_GUEST]));
	scc->cpu_guest_nice = MS_TO_J(scalar_u64(vs[PCP_MPSTAT_ALLCPU_GUESTNICE]));

	/* Slots 1..cpu_nr: per-CPU (instance ID = CPU number) */
	if (!vs[PCP_MPSTAT_PERCPU_USER]) return;

	for (i = 0; i < vs[PCP_MPSTAT_PERCPU_USER]->numval; i++) {
		int cpu_id = vs[PCP_MPSTAT_PERCPU_USER]->vlist[i].inst;

		if (cpu_id < 0 || cpu_id >= cpu_nr) continue;

		scc = &st_cpu[s][cpu_id + 1];
		scc->cpu_user       = MS_TO_J(inst_u64(vs[PCP_MPSTAT_PERCPU_USER],      cpu_id));
		scc->cpu_nice       = MS_TO_J(inst_u64(vs[PCP_MPSTAT_PERCPU_NICE],      cpu_id));
		scc->cpu_sys        = MS_TO_J(inst_u64(vs[PCP_MPSTAT_PERCPU_SYS],       cpu_id));
		scc->cpu_idle       = MS_TO_J(inst_u64(vs[PCP_MPSTAT_PERCPU_IDLE],      cpu_id));
		scc->cpu_iowait     = MS_TO_J(inst_u64(vs[PCP_MPSTAT_PERCPU_IOWAIT],    cpu_id));
		scc->cpu_hardirq    = MS_TO_J(inst_u64(vs[PCP_MPSTAT_PERCPU_HARDIRQ],   cpu_id));
		scc->cpu_softirq    = MS_TO_J(inst_u64(vs[PCP_MPSTAT_PERCPU_SOFTIRQ],   cpu_id));
		scc->cpu_steal      = MS_TO_J(inst_u64(vs[PCP_MPSTAT_PERCPU_STEAL],     cpu_id));
		scc->cpu_guest      = MS_TO_J(inst_u64(vs[PCP_MPSTAT_PERCPU_GUEST],     cpu_id));
		scc->cpu_guest_nice = MS_TO_J(inst_u64(vs[PCP_MPSTAT_PERCPU_GUESTNICE], cpu_id));
	}
}

int
pcp_mpstat_run(const char *archive)
{
	int ctx, sts, i;
	pmResult *result = NULL, *prev_result = NULL;
	int first = 1, curr = 1;

	ctx = pmNewContext(PM_CONTEXT_ARCHIVE, archive);
	if (ctx < 0) {
		fprintf(stderr, _("Cannot open PCP archive %s: %s\n"),
			archive, pmErrStr(ctx));
		return 1;
	}

	pmSetMode(PM_MODE_FORW, NULL, 0);

	while ((sts = pmFetch(PCP_MPSTAT_NR, pcp_mpstat_pmids, &result)) >= 0) {
		struct timespec curr_tv;
		time_t t;
		unsigned long long curr_ts_cs;

		curr_tv = result->timestamp;
		t = (time_t)curr_tv.tv_sec;
		curr_ts_cs = (unsigned long long)curr_tv.tv_sec * 100
			     + curr_tv.tv_nsec / 10000000;

		if (first) {
			/*
			 * First fetch: discover CPU count, allocate st_cpu arrays,
			 * then use this result as the initial snapshot — no separate
			 * probe needed (a second pmSetMode(NULL) does NOT rewind).
			 */
			pmValueSet *percpu_vset = NULL;
			int m;

			for (m = 0; m < result->numpmid; m++) {
				if (result->vset[m]->pmid ==
				    pcp_mpstat_pmids[PCP_MPSTAT_PERCPU_USER]) {
					percpu_vset = result->vset[m];
					break;
				}
			}
			if (!percpu_vset || percpu_vset->numval <= 0) {
				fprintf(stderr,
					_("No per-CPU metrics in archive %s\n"), archive);
				pmFreeResult(result);
				break;
			}
			cpu_nr = percpu_vset->numval;

			for (i = 0; i < 3; i++) {
				st_cpu[i] = calloc(cpu_nr + 1, sizeof(struct stats_cpu));
				if (!st_cpu[i]) {
					perror("calloc");
					pmFreeResult(result);
					goto out;
				}
			}
		}

		/* Set mpstat's timestamp and uptime_cs globals */
		localtime_r(&t, &mp_tstamp[curr]);
		uptime_cs[curr] = curr_ts_cs;

		build_cpu_snap(curr, result);

		if (!first) {
			/* actflags drives what write_stats displays; ensure -u is set */
			if (!actflags)
				actflags |= M_D_CPU;
			write_stats(curr, TRUE);
		}

		if (prev_result) pmFreeResult(prev_result);
		prev_result = result;
		result = NULL;

		curr = (curr == 1) ? 2 : 1;
		first = 0;
	}
out:

	if (result) pmFreeResult(result);
	if (prev_result) pmFreeResult(prev_result);
	for (i = 0; i < 3; i++) { free(st_cpu[i]); st_cpu[i] = NULL; }

	pmDestroyContext(ctx);
	return 0;
}

#endif /* HAVE_PCP */
