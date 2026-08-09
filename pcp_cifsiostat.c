/*
 * pcp_cifsiostat.c: Read CIFS statistics from a PCP archive for cifsiostat.
 * (C) 2026 Red Hat, Inc.
 * (C) 2025-2026 by Sebastien Godard (sysstat <at> orange.fr)
 *
 * Implements "cifsiostat -a <archive>".  Builds cifs_list from cifs.fs.*
 * and cifs.ops.* metrics in a PCP archive (written by pmlogger with the
 * CIFS PMDA, domain 121) and calls cifsiostat's existing write_stats()
 * display function unchanged.
 *
 * Metric mapping:
 *   cifs.fs.read        → cifs_st.rd_ops
 *   cifs.fs.read_bytes  → cifs_st.rd_bytes
 *   cifs.fs.write       → cifs_st.wr_ops
 *   cifs.fs.write_bytes → cifs_st.wr_bytes
 *   cifs.ops.open       → cifs_st.fopens
 *   cifs.ops.close      → cifs_st.fcloses
 *   cifs.ops.delete     → cifs_st.fdeletes
 */

#ifdef HAVE_PCP

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <pcp/pmapi.h>

#include "common.h"
#include "cifsiostat.h"
#include "pcp_cifsiostat.h"
#include "pcp_def_metrics.h"

#include <locale.h>
#ifdef USE_NLS
# include <libintl.h>
# define _(s) gettext(s)
#else
# define _(s) (s)
#endif

/* Globals owned by cifsiostat.c */
extern struct io_cifs *cifs_list;
extern uint64_t        xflags;
extern unsigned int    flags;

struct io_cifs *add_list_cifs(struct io_cifs **clist, char *name);
void write_stats(int curr, struct tm *rectime);

/* CIFS PMDA is domain 121; all share the per-filesystem indom (121:1) */

enum {
	PCP_CIFS_READ,		/* cifs.fs.read        121:1:3  */
	PCP_CIFS_READ_BYTES,	/* cifs.fs.read_bytes  121:1:4  */
	PCP_CIFS_WRITE,		/* cifs.fs.write       121:1:5  */
	PCP_CIFS_WRITE_BYTES,	/* cifs.fs.write_bytes 121:1:6  */
	PCP_CIFS_OPEN,		/* cifs.ops.open       121:1:11 */
	PCP_CIFS_CLOSE,		/* cifs.ops.close      121:1:12 */
	PCP_CIFS_DELETE,	/* cifs.ops.delete     121:1:13 */
	PCP_CIFS_NR
};

/* Use metric names for lookup so this works regardless of PMDA installation */
static const char *pcp_cifs_names[PCP_CIFS_NR] = {
	[PCP_CIFS_READ]       = "cifs.fs.read",
	[PCP_CIFS_READ_BYTES] = "cifs.fs.read_bytes",
	[PCP_CIFS_WRITE]      = "cifs.fs.write",
	[PCP_CIFS_WRITE_BYTES]= "cifs.fs.write_bytes",
	[PCP_CIFS_OPEN]       = "cifs.ops.open",
	[PCP_CIFS_CLOSE]      = "cifs.ops.close",
	[PCP_CIFS_DELETE]     = "cifs.ops.delete",
};

static pmID pcp_cifs_pmids[PCP_CIFS_NR];
static pmDesc pcp_cifs_descs[PCP_CIFS_NR];

static void
build_cifs_snap(int curr, pmResult *result)
{
	pmValueSet *vs[PCP_CIFS_NR];
	int m, i;

	memset(vs, 0, sizeof(vs));
	for (m = 0; m < result->numpmid; m++) {
		int idx;

		for (idx = 0; idx < PCP_CIFS_NR; idx++) {
			if (result->vset[m]->pmid == pcp_cifs_pmids[idx]) {
				vs[idx] = result->vset[m];
				break;
			}
		}
	}

	if (!vs[PCP_CIFS_READ] || vs[PCP_CIFS_READ]->numval <= 0)
		return;

	for (i = 0; i < vs[PCP_CIFS_READ]->numval; i++) {
		int inst_id = vs[PCP_CIFS_READ]->vlist[i].inst;
		char *inst_name = NULL;
		struct io_cifs *ci;
		struct cifs_st *cs;

		if (pmNameInDom(pcp_cifs_descs[PCP_CIFS_READ].indom,
				inst_id, &inst_name) < 0)
			continue;

		ci = add_list_cifs(&cifs_list, inst_name);
		free(inst_name);
		if (!ci) continue;

		if (!ci->cifs_stats[curr]) {
			ci->cifs_stats[curr] = calloc(1, sizeof(struct cifs_st));
			if (!ci->cifs_stats[curr]) continue;
		}
		cs = ci->cifs_stats[curr];

		cs->rd_ops   = pcp_inst_u64(vs[PCP_CIFS_READ],        inst_id);
		cs->rd_bytes = pcp_inst_u64(vs[PCP_CIFS_READ_BYTES],   inst_id);
		cs->wr_ops   = pcp_inst_u64(vs[PCP_CIFS_WRITE],        inst_id);
		cs->wr_bytes = pcp_inst_u64(vs[PCP_CIFS_WRITE_BYTES],  inst_id);
		cs->fopens   = pcp_inst_u64(vs[PCP_CIFS_OPEN],         inst_id);
		cs->fcloses  = pcp_inst_u64(vs[PCP_CIFS_CLOSE],        inst_id);
		cs->fdeletes = pcp_inst_u64(vs[PCP_CIFS_DELETE],        inst_id);
	}
}

int
pcp_cifsiostat_run(const char *archive)
{
	int ctx, sts, m, first = 1, curr = 0;
	pmResult *result = NULL, *prev_result = NULL;
	pmID fetch_pmids[PCP_CIFS_NR];
	int fetch_nr = 0;
	struct tm rectime;

	ctx = pmNewContext(PM_CONTEXT_ARCHIVE, archive);
	if (ctx < 0) {
		fprintf(stderr, _("Cannot open PCP archive %s: %s\n"),
			archive, pmErrStr(ctx));
		return 1;
	}

	/* Batch name→PMID and descriptor lookups */
	for (m = 0; m < PCP_CIFS_NR; m++)
		pcp_cifs_pmids[m] = PM_ID_NULL;
	pmLookupName(PCP_CIFS_NR, pcp_cifs_names, pcp_cifs_pmids);
	pmLookupDescs(PCP_CIFS_NR, pcp_cifs_pmids, pcp_cifs_descs);

	for (m = 0; m < PCP_CIFS_NR; m++) {
		if (pcp_cifs_pmids[m] != PM_ID_NULL)
			fetch_pmids[fetch_nr++] = pcp_cifs_pmids[m];
	}

	if (!fetch_nr) {
		fprintf(stderr,
			_("No CIFS metrics in archive %s\n"
			  "Ensure the CIFS PMDA is installed and pmlogger\n"
			  "records cifs.fs.* metrics.\n"), archive);
		pmDestroyContext(ctx);
		return 1;
	}

	pmSetMode(PM_MODE_FORW, NULL, 0);

	while ((sts = pmFetch(fetch_nr, fetch_pmids, &result)) >= 0) {
		time_t t = (time_t)result->timestamp.tv_sec;

		localtime_r(&t, &rectime);
		build_cifs_snap(curr, result);

		if (!first)
			write_stats(curr, &rectime);

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
