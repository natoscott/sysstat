/*
 * pcp_iostat.c: Read disk I/O statistics from a PCP archive for iostat.
 * (C) 2026 Red Hat, Inc.
 * (C) 2025-2026 by Sebastien Godard (sysstat <at> orange.fr)
 *
 * Implements "iostat -a <archive>".  Builds dev_list from disk.dev.*
 * instances in the archive and calls iostat's existing write_stats()
 * display function unchanged.
 *
 * Unit conversions (PCP → io_stats):
 *   disk.dev.read_bytes  / .write_bytes  kB → sectors (× 2)
 *   disk.dev.read_rawactive / avactive   ms → ms (direct, same units)
 *   disk.dev.read / .write / .read_merge counts direct
 */

#ifdef HAVE_PCP

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <pcp/pmapi.h>

#include "common.h"
#include "iostat.h"
#include "pcp_def_metrics.h"
#include "pcp_iostat.h"

#include <locale.h>
#ifdef USE_NLS
# include <libintl.h>
# define _(s) gettext(s)
#else
# define _(s) (s)
#endif

/* Functions defined in iostat.c */
struct io_device *add_list_device(struct io_device **dlist, char *name,
				  int dtype, int major, int minor);
void write_stats(int curr, struct tm *rectime, int skip);

/* Globals owned by iostat.c that we populate */
extern struct io_device *dev_list;
extern uint64_t          xflags;
extern unsigned int      flags;

/* Metric index for disk.dev.* — PMIDs already defined in pcp_def_metrics.h */
enum {
	PCP_IOSTAT_READ,	/* disk.dev.read       (count, counter) */
	PCP_IOSTAT_WRITE,	/* disk.dev.write      (count, counter) */
	PCP_IOSTAT_RD_BYTES,	/* disk.dev.read_bytes (kB,    counter) */
	PCP_IOSTAT_WR_BYTES,	/* disk.dev.write_bytes(kB,    counter) */
	PCP_IOSTAT_RD_MERGE,	/* disk.dev.read_merge (count, counter) */
	PCP_IOSTAT_WR_MERGE,	/* disk.dev.write_merge(count, counter) */
	PCP_IOSTAT_RD_ACTIVE,	/* disk.dev.read_rawactive  (ms, counter) */
	PCP_IOSTAT_WR_ACTIVE,	/* disk.dev.write_rawactive (ms, counter) */
	PCP_IOSTAT_AVACTIVE,	/* disk.dev.avactive   (ms, counter) */
	PCP_IOSTAT_AVEQ,	/* disk.dev.aveq       (ms, counter) */
	PCP_IOSTAT_NR
};

static pmID pcp_iostat_pmids[PCP_IOSTAT_NR] = {
	[PCP_IOSTAT_READ]      = PMID_DISK_PERDEV_READ,
	[PCP_IOSTAT_WRITE]     = PMID_DISK_PERDEV_WRITE,
	[PCP_IOSTAT_RD_BYTES]  = PMID_DISK_PERDEV_READBYTES,
	[PCP_IOSTAT_WR_BYTES]  = PMID_DISK_PERDEV_WRITEBYTES,
	[PCP_IOSTAT_RD_MERGE]  = PMI_ID(60, 0, 49), /* disk.dev.read_merge  */
	[PCP_IOSTAT_WR_MERGE]  = PMI_ID(60, 0, 50), /* disk.dev.write_merge */
	[PCP_IOSTAT_RD_ACTIVE] = PMID_DISK_PERDEV_READACTIVE,
	[PCP_IOSTAT_WR_ACTIVE] = PMID_DISK_PERDEV_WRITEACTIVE,
	[PCP_IOSTAT_AVACTIVE]  = PMID_DISK_PERDEV_AVACTIVE,
	[PCP_IOSTAT_AVEQ]      = PMID_DISK_PERDEV_AVQUEUE,
};

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

/*
 * Build dev_list from the pmResult: create/update io_device entries
 * and fill dev_stats[curr] with the raw counter values.
 */
static void
build_disk_snap(int curr, pmResult *result, pmDesc *rd_desc)
{
	pmValueSet *vs[PCP_IOSTAT_NR];
	pmValueSet *read_vset;
	int m, i;
	int *indom_ids = NULL;
	char **indom_names = NULL;
	int n_indom;

	memset(vs, 0, sizeof(vs));
	for (m = 0; m < result->numpmid; m++) {
		int idx;

		for (idx = 0; idx < PCP_IOSTAT_NR; idx++) {
			if (result->vset[m]->pmid == pcp_iostat_pmids[idx]) {
				vs[idx] = result->vset[m];
				break;
			}
		}
	}

	read_vset = vs[PCP_IOSTAT_READ];
	if (!read_vset || read_vset->numval <= 0)
		return;

	/*
	 * Fetch all (inst_id, name) pairs for the disk indom in one call.
	 * libpcp caches this internally so it is fast after the first fetch.
	 */
	n_indom = pmGetInDom(rd_desc->indom, &indom_ids, &indom_names);

	for (i = 0; i < read_vset->numval; i++) {
		int inst_id = read_vset->vlist[i].inst;
		char inst_buf[MAX_NAME_LEN];
		char *inst_name = inst_buf;
		struct io_device *d;
		struct io_stats *ios;
		int j;

		/* Look up device name from the per-sample indom snapshot */
		pmsprintf(inst_buf, sizeof(inst_buf), "dev%d", inst_id);
		for (j = 0; j < n_indom; j++) {
			if (indom_ids[j] == inst_id) {
				inst_name = indom_names[j];
				break;
			}
		}

		d = add_list_device(&dev_list, inst_name, T_DEV,
				    UKWN_MAJ_NR, 0);
		if (!d)
			continue;

		if (!d->dev_stats[curr]) {
			d->dev_stats[curr] = calloc(1, sizeof(struct io_stats));
			if (!d->dev_stats[curr])
				continue;
		}
		ios = d->dev_stats[curr];

		ios->rd_ios    = (unsigned long)inst_u64(vs[PCP_IOSTAT_READ],      inst_id);
		ios->wr_ios    = (unsigned long)inst_u64(vs[PCP_IOSTAT_WRITE],     inst_id);
		ios->rd_merges = (unsigned long)inst_u64(vs[PCP_IOSTAT_RD_MERGE],  inst_id);
		ios->wr_merges = (unsigned long)inst_u64(vs[PCP_IOSTAT_WR_MERGE],  inst_id);
		/* PCP read_bytes is kB; io_stats rd_sectors is 512-byte sectors */
		ios->rd_sectors = inst_u64(vs[PCP_IOSTAT_RD_BYTES], inst_id) * 2;
		ios->wr_sectors = inst_u64(vs[PCP_IOSTAT_WR_BYTES], inst_id) * 2;
		ios->rd_ticks  = (unsigned int)inst_u64(vs[PCP_IOSTAT_RD_ACTIVE], inst_id);
		ios->wr_ticks  = (unsigned int)inst_u64(vs[PCP_IOSTAT_WR_ACTIVE], inst_id);
		ios->tot_ticks = (unsigned int)inst_u64(vs[PCP_IOSTAT_AVACTIVE],  inst_id);
		ios->rq_ticks  = (unsigned int)inst_u64(vs[PCP_IOSTAT_AVEQ],      inst_id);
	}

	if (n_indom > 0) {
		free(indom_ids);
		free(indom_names);
	}
}

int
pcp_iostat_run(const char *archive)
{
	int ctx, sts, i;
	pmResult *result = NULL, *prev_result = NULL;
	int first = 1, curr = 1;
	pmDesc rd_desc;
	struct tm rectime;

	ctx = pmNewContext(PM_CONTEXT_ARCHIVE, archive);
	if (ctx < 0) {
		fprintf(stderr, _("Cannot open PCP archive %s: %s\n"),
			archive, pmErrStr(ctx));
		return 1;
	}

	/* Descriptor needed for the correct indom in pmGetInDom calls */
	if (pmLookupDesc(pcp_iostat_pmids[PCP_IOSTAT_READ], &rd_desc) < 0)
		rd_desc.indom = PM_INDOM_NULL;

	/* Filter available metrics */
	pmID fetch_pmids[PCP_IOSTAT_NR];
	int  fetch_nr = 0;

	for (i = 0; i < PCP_IOSTAT_NR; i++) {
		pmDesc d;

		if (pmLookupDesc(pcp_iostat_pmids[i], &d) >= 0)
			fetch_pmids[fetch_nr++] = pcp_iostat_pmids[i];
	}

	if (!fetch_nr) {
		fprintf(stderr, _("No disk metrics in archive %s\n"), archive);
		pmDestroyContext(ctx);
		return 1;
	}

	/* Enable -x (extended) by default for richer output */
	if (!DISPLAY_EXTENDED(flags))
		flags |= I_D_EXTENDED;

	pmSetMode(PM_MODE_FORW, NULL, 0);

	while ((sts = pmFetch(fetch_nr, fetch_pmids, &result)) >= 0) {
		struct timespec curr_tv;
		time_t t;

		curr_tv = result->timestamp;
		t = (time_t)curr_tv.tv_sec;
		localtime_r(&t, &rectime);

		build_disk_snap(curr, result, &rd_desc);

		if (!first)
			write_stats(curr, &rectime, FALSE);

		/* Roll curr: swap io_stats[0] and io_stats[1] via prev/curr */
		if (prev_result) pmFreeResult(prev_result);
		prev_result = result;
		result = NULL;

		curr = !curr;
		first = 0;
	}

	if (result) pmFreeResult(result);
	if (prev_result) pmFreeResult(prev_result);

	pmDestroyContext(ctx);
	return 0;
}

#endif /* HAVE_PCP */
