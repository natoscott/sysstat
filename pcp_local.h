/*
 * pcp_local.h: Local PMDA metric collection for PCP archive output.
 * (C) 2026 Red Hat, Inc.
 * (C) 2025-2026 by Sebastien Godard (sysstat <at> orange.fr)
 */

#ifndef _PCP_LOCAL_H
#define _PCP_LOCAL_H

#ifdef HAVE_PMI_APPEND
#include <pcp/pmapi.h>
#include <pcp/import.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Per-instance domain state for local-context metrics.
 * inst_ids[] is kept sorted ascending so binary search gives O(log n) lookup.
 * inst_names[] runs parallel to inst_ids[].
 * Metric handle arrays (pcp_local_metric.handles[]) are indexed by slot,
 * where slot = sorted position in inst_ids[].
 */
struct pcp_local_indom {
	pmInDom  indom;
	size_t   hwm;		/* active instance count */
	size_t   capacity;	/* allocated size */
	int	*inst_ids;	/* sorted ascending by instance ID */
	char   **inst_names;	/* parallel PMDA-provided name strings */
};

/*
 * Per-metric descriptor with associated handle storage.
 */
struct pcp_local_metric {
	char			*name;
	pmID			 pmid;
	pmDesc			 desc;
	int			 indom_idx;	/* index into cfg->indoms, -1 for singleton */
	int			 handle;	/* singleton handle */
	int			*handles;	/* instanced: handles[slot] */
	size_t			 handle_cap;	/* mirrors indom->capacity */
};

/*
 * Parsed sysstat.pcpconf configuration.
 */
struct pcp_local_config {
	size_t			 volume_size;	/* data volume rotation size (bytes) */
	size_t			 num_metrics;
	struct pcp_local_metric	*metrics;
	size_t			 num_indoms;
	struct pcp_local_indom	*indoms;
	pmID			*pmids;		/* flat array for pmFetch */
};

/* Parse config, load PMDAs, open PM_CONTEXT_LOCAL, discover metrics */
int  pcp_local_init(struct pcp_local_config *cfg, const char *conffile);

/* Register discovered metrics into the active PMI write context */
void pcp_local_register(struct pcp_local_config *cfg);

/* Fetch and write local-context metrics at this timestamp */
void pcp_local_write(struct pcp_local_config *cfg,
		     unsigned long long ust_time, long nsec);

/* Release all resources */
void pcp_local_free(struct pcp_local_config *cfg);

#else /* !HAVE_PMI_APPEND */

struct pcp_local_config { int dummy; };

static inline int
pcp_local_init(struct pcp_local_config *c __attribute__((unused)),
	       const char *f __attribute__((unused)))
	{ return 0; }
static inline void
pcp_local_register(struct pcp_local_config *c __attribute__((unused))) {}
static inline void
pcp_local_write(struct pcp_local_config *c __attribute__((unused)),
		unsigned long long t __attribute__((unused)),
		long n __attribute__((unused))) {}
static inline void
pcp_local_free(struct pcp_local_config *c __attribute__((unused))) {}

#endif /* HAVE_PMI_APPEND */
#endif /* _PCP_LOCAL_H */
