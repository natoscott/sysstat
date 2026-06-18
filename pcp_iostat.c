/*
 * pcp_iostat.c: Read disk I/O statistics from a PCP archive for iostat.
 * (C) 2026 Red Hat, Inc.
 * (C) 2025-2026 by Sebastien Godard (sysstat <at> orange.fr)
 *
 * Implements "iostat -a <archive>".  Builds dev_list from all disk device
 * classes in the archive (disk.dev.*, disk.dm.*, disk.md.*,
 * disk.partitions.*, zram.*) and calls iostat's existing write_stats()
 * display function unchanged.
 *
 * Unit conversions (PCP → io_stats):
 *   *.read_bytes / .write_bytes  kB → sectors (× 2)
 *   *.read_rawactive / avactive   ms → ms (direct, same units)
 *   *.read / .write / .read_merge counts direct
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

/*
 * Secondary disk device class PMID sets.  All four classes share the same
 * metric item numbering within their cluster; only the cluster differs.
 * Populated at runtime by build_class_pmids() using DCLASS_CLUSTER_* and
 * DCLASS_ITEM_* macros from pcp_def_metrics.h.
 */
#define DCLASS_PMIDS(cluster) {					\
	[PCP_IOSTAT_READ]      = PMI_ID(60, cluster, DCLASS_ITEM_READ),		\
	[PCP_IOSTAT_WRITE]     = PMI_ID(60, cluster, DCLASS_ITEM_WRITE),	\
	[PCP_IOSTAT_RD_BYTES]  = PMI_ID(60, cluster, DCLASS_ITEM_READBYTES),	\
	[PCP_IOSTAT_WR_BYTES]  = PMI_ID(60, cluster, DCLASS_ITEM_WRITEBYTES),	\
	[PCP_IOSTAT_RD_MERGE]  = PMI_ID(60, cluster, DCLASS_ITEM_READ_MERGE),	\
	[PCP_IOSTAT_WR_MERGE]  = PMI_ID(60, cluster, DCLASS_ITEM_WRITE_MERGE),	\
	[PCP_IOSTAT_RD_ACTIVE] = PMI_ID(60, cluster, DCLASS_ITEM_RD_ACTIVE),	\
	[PCP_IOSTAT_WR_ACTIVE] = PMI_ID(60, cluster, DCLASS_ITEM_WR_ACTIVE),	\
	[PCP_IOSTAT_AVACTIVE]  = PMI_ID(60, cluster, DCLASS_ITEM_AVACTIVE),	\
	[PCP_IOSTAT_AVEQ]      = PMI_ID(60, cluster, DCLASS_ITEM_AVEQ),		\
}

static pmID dm_iostat_pmids[PCP_IOSTAT_NR]   = DCLASS_PMIDS(DCLASS_CLUSTER_DM);
static pmID md_iostat_pmids[PCP_IOSTAT_NR]   = DCLASS_PMIDS(DCLASS_CLUSTER_MD);
static pmID part_iostat_pmids[PCP_IOSTAT_NR] = DCLASS_PMIDS(DCLASS_CLUSTER_PART);
static pmID zram_iostat_pmids[PCP_IOSTAT_NR] = DCLASS_PMIDS(DCLASS_CLUSTER_ZRAM);

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
 * Build dev_list from one disk device class in the pmResult.
 *
 * IN:
 * @curr	Sample slot (0 or 1).
 * @result	pmResult from pmFetch.
 * @pmids	PMID array (PCP_IOSTAT_NR entries) for this class.
 * @indom	PCP instance domain for this class (used to look up names).
 */
static void
build_disk_snap(int curr, pmResult *result,
		const pmID *pmids, pmInDom indom)
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
			if (result->vset[m]->pmid == pmids[idx]) {
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
	n_indom = pmGetInDom(indom, &indom_ids, &indom_names);

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

/*
 * Describe the five disk device classes.
 */
struct disk_class {
	const pmID *pmids;	/* PCP_IOSTAT_NR PMIDs for this class */
	pmInDom     indom;	/* instance domain for name lookup */
};

static const struct disk_class disk_classes[] = {
	{ pcp_iostat_pmids,  PMI_INDOM(60,  1) },	/* disk.dev.*        */
	{ dm_iostat_pmids,   PMI_INDOM(60, 24) },	/* disk.dm.*         */
	{ md_iostat_pmids,   PMI_INDOM(60, 25) },	/* disk.md.*         */
	{ part_iostat_pmids, PMI_INDOM(60, 10) },	/* disk.partitions.* */
	{ zram_iostat_pmids, PMI_INDOM(60, 38) },	/* zram.*            */
};
#define NDISK_CLASSES ((int)(sizeof(disk_classes)/sizeof(disk_classes[0])))
#define MAX_FETCH_PMIDS (NDISK_CLASSES * PCP_IOSTAT_NR)

int
pcp_iostat_run(const char *archive)
{
	int ctx, sts, c, i, m;
	pmResult *result = NULL, *prev_result = NULL;
	int first = 1, curr = 1;
	struct tm rectime;

	/*
	 * Flat arrays covering all classes × metrics.
	 * pmid_class[i]: which disk_classes[] entry owns fetch_pmids[i].
	 */
	pmID fetch_pmids[MAX_FETCH_PMIDS];
	int  pmid_class[MAX_FETCH_PMIDS];
	int  fetch_nr = 0;
	pmDesc descs[MAX_FETCH_PMIDS];

	ctx = pmNewContext(PM_CONTEXT_ARCHIVE, archive);
	if (ctx < 0) {
		fprintf(stderr, _("Cannot open PCP archive %s: %s\n"),
			archive, pmErrStr(ctx));
		return 1;
	}

	/*
	 * Collect all candidate PMIDs, then resolve them all in one
	 * pmLookupDescs call.  Only those that resolve successfully
	 * (sts >= 0 per descriptor) are included in the fetch set.
	 */
	{
		pmID  all_pmids[MAX_FETCH_PMIDS];
		int   all_cls[MAX_FETCH_PMIDS];
		int   all_nr = 0;
		pmDesc all_descs[MAX_FETCH_PMIDS];

		for (c = 0; c < NDISK_CLASSES; c++) {
			for (m = 0; m < PCP_IOSTAT_NR; m++) {
				all_pmids[all_nr] = disk_classes[c].pmids[m];
				all_cls[all_nr]   = c;
				all_nr++;
			}
		}

		/* Batch descriptor lookup — one round-trip for all PMIDs */
		pmLookupDescs(all_nr, all_pmids, all_descs);

		for (i = 0; i < all_nr; i++) {
			if (all_descs[i].pmid == PM_ID_NULL)
				continue;	/* not in this archive */
			fetch_pmids[fetch_nr] = all_pmids[i];
			pmid_class[fetch_nr]  = all_cls[i];
			descs[fetch_nr]       = all_descs[i];
			fetch_nr++;
		}
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

		/*
		 * Dispatch each vset to the correct class using pmid_class[].
		 * build_disk_snap matches vsets by PMID against the class's
		 * pmids[] array, so passing the full result is correct.
		 */
		for (c = 0; c < NDISK_CLASSES; c++)
			build_disk_snap(curr, result,
					disk_classes[c].pmids,
					disk_classes[c].indom);

		if (!first)
			write_stats(curr, &rectime, FALSE);

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
