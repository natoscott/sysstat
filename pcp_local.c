/*
 * pcp_local.c: Local PMDA metric collection for PCP archive output.
 * (C) 2026 Red Hat, Inc.
 * (C) 2025-2026 by Sebastien Godard (sysstat <at> orange.fr)
 *
 * Reads /etc/sysconfig/sysstat.pcpconf to discover which metrics to collect
 * from a PM_CONTEXT_LOCAL context (pmda_proc.so and optionally others),
 * then writes them into the sadc PCP archive at a configurable interval.
 */

#ifdef HAVE_PMI_APPEND

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <pcp/pmapi.h>
#include <pcp/import.h>

#include "common.h"
#include "sysconfig.h"
#include "pcp_local.h"

#ifndef HAVE_NLS
# define _(x) (x)
#endif

/* PM_CONTEXT_LOCAL handle — saved at init, restored after each fetch */
static int local_ctx = -1;

/*
 ***************************************************************************
 * Config file parsing
 ***************************************************************************
 */

#define SECTION_NONE     0
#define SECTION_SETTINGS 1
#define SECTION_PMDAS    2
#define SECTION_METRICS  3

/* Growing string list used during config parsing and PMNS traversal */
struct strlist {
	char   **items;
	size_t	 count;
	size_t	 capacity;
};

static void strlist_add(struct strlist *sl, const char *s)
{
	if (sl->count >= sl->capacity) {
		sl->capacity = sl->capacity ? sl->capacity * 2 : 16;
		sl->items = realloc(sl->items, sl->capacity * sizeof(char *));
	}
	sl->items[sl->count++] = strdup(s);
}

static void strlist_free(struct strlist *sl)
{
	size_t i;

	for (i = 0; i < sl->count; i++)
		free(sl->items[i]);
	free(sl->items);
	sl->items = NULL;
	sl->count = sl->capacity = 0;
}

/* Static state for pmTraversePMNS callback (single-threaded init only) */
static struct strlist g_traverse;

static void traverse_cb(const char *name)
{
	strlist_add(&g_traverse, name);
}

/*
 * Strip leading and trailing whitespace in-place, return pointer to first
 * non-space character (may point inside the original buffer).
 */
static char *strip(char *s)
{
	char *end;

	while (isspace((unsigned char)*s))
		s++;
	if (!*s)
		return s;
	end = s + strlen(s) - 1;
	while (end > s && isspace((unsigned char)*end))
		*end-- = '\0';
	return s;
}

/*
 ***************************************************************************
 * Parse sysstat.pcpconf.
 *
 * IN:
 * @conffile	Path to configuration file.
 * @pmdas	Output: list of PMDA names from [pmdas] section.
 * @raw_metrics	Output: list of raw metric names from [metrics] section.
 * @interval	Output: local sampling interval (seconds).
 * @volume_size	Output: data volume rotation size (bytes, 0 = disabled).
 *
 * RETURNS:
 * 0 on success, -1 on error (file not found is treated as empty config).
 ***************************************************************************
 */
static int
parse_config(const char *conffile, struct strlist *pmdas,
	     struct strlist *raw_metrics, size_t *volume_size)
{
	FILE *fp;
	char line[1024];
	int section = SECTION_NONE;

	*volume_size = 0;

	if ((fp = fopen(conffile, "r")) == NULL)
		return -1;

	while (fgets(line, sizeof(line), fp)) {
		char *p = strip(line);

		if (!*p || *p == '#')
			continue;

		if (*p == '[') {
			char *end = strchr(p, ']');
			if (!end)
				continue;
			*end = '\0';
			p++;
			if (!strcmp(p, "settings"))
				section = SECTION_SETTINGS;
			else if (!strcmp(p, "pmdas"))
				section = SECTION_PMDAS;
			else if (!strcmp(p, "metrics"))
				section = SECTION_METRICS;
			else
				section = SECTION_NONE;
			continue;
		}

		switch (section) {
		case SECTION_SETTINGS: {
			char *eq = strchr(p, '=');
			if (!eq)
				break;
			*eq = '\0';
			char *key = strip(p);
			char *val = strip(eq + 1);
			if (!strcmp(key, "volume_size"))
				*volume_size = (size_t)strtoull(val, NULL, 10);
			break;
		}
		case SECTION_PMDAS:
			strlist_add(pmdas, p);
			break;
		case SECTION_METRICS:
			strlist_add(raw_metrics, p);
			break;
		default:
			break;
		}
	}

	fclose(fp);
	return 0;
}

/*
 ***************************************************************************
 * Instance domain management
 ***************************************************************************
 */

/*
 * Find the slot for inst_id in the sorted indom, or (size_t)-1 if absent.
 */
static size_t
local_indom_find(const struct pcp_local_indom *id, int inst_id)
{
	size_t lo = 0, hi = id->hwm;

	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;

		if (id->inst_ids[mid] == inst_id)
			return mid;
		if (id->inst_ids[mid] < inst_id)
			lo = mid + 1;
		else
			hi = mid;
	}
	return (size_t)-1;
}

/*
 * Insert inst_id at sorted position, growing all metric handle arrays that
 * reference this indom.  Returns the new slot index.
 *
 * IN:
 * @cfg		Full local config (needed to grow metric handle arrays).
 * @id		Indom to insert into.
 * @inst_id	Instance ID to insert.
 * @inst_name	PMDA-provided instance name string.
 *
 * RETURNS:
 * Slot index of the inserted instance.
 ***************************************************************************
 */
static size_t
local_indom_insert(struct pcp_local_config *cfg, struct pcp_local_indom *id,
		   int inst_id, const char *inst_name)
{
	size_t pos, i;
	/* Find insertion point */
	for (pos = 0; pos < id->hwm; pos++) {
		if (id->inst_ids[pos] > inst_id)
			break;
	}

	/* Grow if needed */
	if (id->hwm >= id->capacity) {
		size_t new_cap = id->capacity ? id->capacity * 2 : 16;

		id->inst_ids   = realloc(id->inst_ids,   new_cap * sizeof(int));
		id->inst_names = realloc(id->inst_names, new_cap * sizeof(char *));

		/* Grow handle arrays for every metric using this indom */
		for (i = 0; i < cfg->num_metrics; i++) {
			struct pcp_local_metric *m = &cfg->metrics[i];

			if (m->indom_idx < 0 || &cfg->indoms[m->indom_idx] != id)
				continue;
			m->handles = realloc(m->handles, new_cap * sizeof(int));
			/* Initialise newly allocated slots to -1 */
			if (new_cap > m->handle_cap) {
				memset(m->handles + m->handle_cap, -1,
				       (new_cap - m->handle_cap) * sizeof(int));
			}
			m->handle_cap = new_cap;
		}
		id->capacity = new_cap;
	}

	/* Shift inst_ids and inst_names right to make room */
	if (pos < id->hwm) {
		memmove(&id->inst_ids[pos + 1],   &id->inst_ids[pos],
			(id->hwm - pos) * sizeof(int));
		memmove(&id->inst_names[pos + 1], &id->inst_names[pos],
			(id->hwm - pos) * sizeof(char *));

		/* Shift handle arrays right for every metric using this indom */
		for (i = 0; i < cfg->num_metrics; i++) {
			struct pcp_local_metric *m = &cfg->metrics[i];

			if (m->indom_idx < 0 || &cfg->indoms[m->indom_idx] != id)
				continue;
			memmove(&m->handles[pos + 1], &m->handles[pos],
				(id->hwm - pos) * sizeof(int));
		}
	}

	id->inst_ids[pos]   = inst_id;
	id->inst_names[pos] = strdup(inst_name);

	/* Initialise handles at this slot for all referencing metrics */
	for (i = 0; i < cfg->num_metrics; i++) {
		if (cfg->metrics[i].indom_idx >= 0
		    && &cfg->indoms[cfg->metrics[i].indom_idx] == id)
			cfg->metrics[i].handles[pos] = -1;
	}

	id->hwm++;
	return pos;
}

/*
 * Find or create the indom entry for a given pmInDom value.
 * Returns the index into cfg->indoms (stable across future reallocs).
 */
static int
local_indom_get(struct pcp_local_config *cfg, pmInDom indom)
{
	size_t i;

	for (i = 0; i < cfg->num_indoms; i++) {
		if (cfg->indoms[i].indom == indom)
			return (int)i;
	}

	cfg->indoms = realloc(cfg->indoms,
			      (cfg->num_indoms + 1) * sizeof(*cfg->indoms));
	memset(&cfg->indoms[cfg->num_indoms], 0, sizeof(*cfg->indoms));
	cfg->indoms[cfg->num_indoms].indom = indom;
	return (int)cfg->num_indoms++;
}

/*
 ***************************************************************************
 * Add a single leaf metric to the config.
 *
 * IN:
 * @cfg		Config to extend.
 * @name	Metric name (will be duped).
 *
 * RETURNS:
 * 0 on success, -1 on error (metric not found, or duplicate PMID).
 ***************************************************************************
 */
static int
local_metric_add(struct pcp_local_config *cfg, const char *name)
{
	pmID   pmid;
	pmDesc desc;
	int    sts;
	const char *np = name;

	sts = pmLookupName(1, &np, &pmid);
	if (sts < 0) {
		fprintf(stderr, _("PCP local: skipping metric '%s': %s\n"),
			name, pmErrStr(sts));
		return -1;
	}

	sts = pmLookupDesc(pmid, &desc);
	if (sts < 0) {
		fprintf(stderr, _("PCP local: skipping metric '%s': %s\n"),
			name, pmErrStr(sts));
		return -1;
	}

	cfg->metrics = realloc(cfg->metrics,
			       (cfg->num_metrics + 1) * sizeof(*cfg->metrics));
	memset(&cfg->metrics[cfg->num_metrics], 0, sizeof(*cfg->metrics));

	struct pcp_local_metric *m = &cfg->metrics[cfg->num_metrics];
	m->name      = strdup(name);
	m->pmid      = pmid;
	m->desc      = desc;
	m->handle    = -1;
	m->indom_idx = -1;

	if (desc.indom != PM_INDOM_NULL) {
		m->indom_idx  = local_indom_get(cfg, desc.indom);
		m->handles    = NULL;
		m->handle_cap = 0;
	}

	cfg->num_metrics++;
	return 0;
}

/*
 ***************************************************************************
 * Initialise local-context metric collection.
 *
 * Parses conffile, loads PMDAs via pmSpecLocalPMDA, opens a
 * PM_CONTEXT_LOCAL context, looks up metric names and descs.
 * Must be called BEFORE pmiStart() so pmSpecLocalPMDA takes effect.
 *
 * IN:
 * @cfg		Config structure to populate.
 * @conffile	Path to sysstat.pcpconf.
 *
 * RETURNS:
 * 0 on success, -1 if config absent or no usable metrics found.
 ***************************************************************************
 */
int
pcp_local_init(struct pcp_local_config *cfg, const char *conffile)
{
	struct strlist pmdas = {0}, raw_metrics = {0};
	size_t volume_size;
	size_t i;
	int sts;

	memset(cfg, 0, sizeof(*cfg));

	if (parse_config(conffile, &pmdas, &raw_metrics, &volume_size) < 0) {
		strlist_free(&pmdas);
		strlist_free(&raw_metrics);
		return -1;
	}

	cfg->volume_size = volume_size;

	/* Load additional PMDAs before opening the local context */
	for (i = 0; i < pmdas.count; i++) {
		if (pmSpecLocalPMDA(pmdas.items[i]) == NULL)
			fprintf(stderr,
				_("PCP local: cannot load PMDA '%s'\n"),
				pmdas.items[i]);
	}
	strlist_free(&pmdas);

	/*
	 * Point libpcp at the local DSO PMDA configuration and namespace so
	 * that PM_CONTEXT_LOCAL loads the correct set of DSO PMDAs and resolves
	 * metric names against the matching local PMNS.
	 * Use pmGetConfig() for platform-portable paths rather than hardcoding.
	 */
	char path[MAXPATHLEN];
	pmsprintf(path, sizeof(path), "%s/local.conf", pmGetConfig("PCP_SYSCONF_DIR"));
	setenv("PCP_PMCDCONF_FILE", path, 0);
	pmsprintf(path, sizeof(path), "%s/pmns/local.root", pmGetConfig("PCP_VAR_DIR"));
	setenv("PMNS_DEFAULT",      path, 0);

	/* Open PM_CONTEXT_LOCAL — loads proc PMDA (and any extras above) */
	sts = pmNewContext(PM_CONTEXT_LOCAL, NULL);
	if (sts < 0) {
		fprintf(stderr, _("PCP local: pmNewContext failed: %s\n"),
			pmErrStr(sts));
		strlist_free(&raw_metrics);
		return -1;
	}
	local_ctx = sts;

	/*
	 * Expand raw metric names: non-leaf names are expanded to all leaves
	 * beneath them via pmTraversePMNS.
	 */
	struct strlist leaf_metrics = {0};

	for (i = 0; i < raw_metrics.count; i++) {
		pmID pmid;
		const char *np = raw_metrics.items[i];

		sts = pmLookupName(1, &np, &pmid);
		if (sts >= 0) {
			/* Leaf metric */
			strlist_add(&leaf_metrics, raw_metrics.items[i]);
		} else if (sts == PM_ERR_NONLEAF) {
			/* Namespace node — traverse to find all leaves */
			memset(&g_traverse, 0, sizeof(g_traverse));
			pmTraversePMNS(raw_metrics.items[i], traverse_cb);
			size_t j;

			for (j = 0; j < g_traverse.count; j++)
				strlist_add(&leaf_metrics, g_traverse.items[j]);
			strlist_free(&g_traverse);
		} else {
			fprintf(stderr,
				_("PCP local: skipping '%s': %s\n"),
				raw_metrics.items[i], pmErrStr(sts));
		}
	}
	strlist_free(&raw_metrics);

	/* Add each leaf metric to the config */
	for (i = 0; i < leaf_metrics.count; i++)
		local_metric_add(cfg, leaf_metrics.items[i]);
	strlist_free(&leaf_metrics);

	if (!cfg->num_metrics) {
		fprintf(stderr, _("PCP local: no usable metrics found in %s\n"),
			conffile);
		return -1;
	}

	/* Build flat PMID array for pmFetch */
	cfg->pmids = malloc(cfg->num_metrics * sizeof(pmID));
	for (i = 0; i < cfg->num_metrics; i++)
		cfg->pmids[i] = cfg->metrics[i].pmid;

	return 0;
}

/*
 ***************************************************************************
 * Register local metrics into the active PMI write context.
 * Must be called AFTER pmiStart().  Silently skips metrics whose PMID is
 * already registered (avoiding double-writes with built-in sadc metrics).
 ***************************************************************************
 */
void
pcp_local_register(struct pcp_local_config *cfg)
{
	size_t i;

	for (i = 0; i < cfg->num_metrics; i++) {
		struct pcp_local_metric *m = &cfg->metrics[i];
		int sts;

		/* Use PMID/desc exactly as provided by the PMDA */
		sts = pmiAddMetric(m->name, m->pmid,
				   m->desc.type, m->desc.indom,
				   m->desc.sem,  m->desc.units);
		if (sts < 0) {
			/*
			 * PM_ERR_DUPPMID means the metric is already registered
			 * by sadc's built-in write path — skip silently.
			 */
			if (sts != PMI_ERR_DUPMETRICID) {
				fprintf(stderr,
					_("PCP local: pmiAddMetric '%s': %s\n"),
					m->name, pmiErrStr(sts));
			}
			/* Mark metric inactive by zeroing its pmid */
			m->pmid = PM_ID_NULL;
		}
	}
}

/*
 ***************************************************************************
 * Fetch and write local-context metrics into the PMI pending buffer.
 * Called from the sadc main loop when the local interval has elapsed.
 * Does NOT call pmiHighResWrite — that is done by the main loop.
 *
 * IN:
 * @cfg		Local metric configuration.
 * @ust_time	Current sample timestamp (seconds since epoch).
 * @nsec	Nanosecond part of the timestamp.
 ***************************************************************************
 */
void
pcp_local_write(struct pcp_local_config *cfg,
		unsigned long long ust_time, long nsec)
{
	pmResult *result = NULL;
	int saved_ctx, sts;
	size_t i;

	(void)ust_time; (void)nsec;	/* timestamp used by caller's pmiHighResWrite */

	if (!cfg->num_metrics || local_ctx < 0)
		return;

	/* Switch to the local fetch context */
	saved_ctx = pmWhichContext();
	pmUseContext(local_ctx);

	sts = pmFetch((int)cfg->num_metrics, cfg->pmids, &result);
	if (sts < 0) {
		fprintf(stderr, _("PCP local: pmFetch failed: %s\n"),
			pmErrStr(sts));
		pmUseContext(saved_ctx);
		return;
	}

	/* Restore write context before calling PMI functions */
	pmUseContext(saved_ctx);

	for (i = 0; i < (size_t)result->numpmid; i++) {
		pmValueSet *vset = result->vset[i];
		struct pcp_local_metric *m = NULL;
		size_t j;

		if (vset->numval <= 0)
			continue;

		/* Find matching metric by PMID */
		for (j = 0; j < cfg->num_metrics; j++) {
			if (cfg->metrics[j].pmid == vset->pmid) {
				m = &cfg->metrics[j];
				break;
			}
		}
		if (!m || m->pmid == PM_ID_NULL)
			continue;

		if (m->indom_idx < 0) {
			/* Singleton metric */
			pmAtomValue atom;

			if (pmExtractValue(vset->valfmt, &vset->vlist[0],
					   m->desc.type, &atom,
					   m->desc.type) < 0)
				continue;

			if (m->handle < 0)
				m->handle = pmiGetHandle(m->name, NULL);
			if (m->handle >= 0)
				pmiPutAtomValueHandle(m->handle, &atom);
		} else {
			/* Instanced metric — look up indom by stable index */
			struct pcp_local_indom *id = &cfg->indoms[m->indom_idx];
			int vi;

			for (vi = 0; vi < vset->numval; vi++) {
				int inst_id = vset->vlist[vi].inst;
				size_t slot;
				pmAtomValue atom;
				char *inst_name;

				slot = local_indom_find(id, inst_id);
				if (slot == (size_t)-1) {
					/*
					 * New instance: look up name from PMDA,
					 * register with PMI, insert into indom.
					 */
					pmUseContext(local_ctx);
					sts = pmNameInDom(m->desc.indom,
							  inst_id, &inst_name);
					pmUseContext(saved_ctx);
					if (sts < 0)
						continue;

					pmiAddInstance(m->desc.indom,
						       inst_name, inst_id);
					slot = local_indom_insert(cfg, id,
								  inst_id,
								  inst_name);
					free(inst_name);
					/* Reacquire pointer: insert may have realloc'd cfg->indoms */
					id = &cfg->indoms[m->indom_idx];
				}

				if (pmExtractValue(vset->valfmt,
						   &vset->vlist[vi],
						   m->desc.type, &atom,
						   m->desc.type) < 0)
					continue;

				if (m->handles[slot] < 0) {
					m->handles[slot] =
						pmiGetHandle(m->name,
							     id->inst_names[slot]);
				}
				if (m->handles[slot] >= 0)
					pmiPutAtomValueHandle(m->handles[slot],
							      &atom);
			}
		}
	}

	pmFreeResult(result);
}

/*
 ***************************************************************************
 * Free all resources associated with a local metric configuration.
 ***************************************************************************
 */
void
pcp_local_free(struct pcp_local_config *cfg)
{
	size_t i;

	for (i = 0; i < cfg->num_metrics; i++) {
		free(cfg->metrics[i].name);
		free(cfg->metrics[i].handles);
	}
	free(cfg->metrics);

	for (i = 0; i < cfg->num_indoms; i++) {
		size_t j;

		for (j = 0; j < cfg->indoms[i].hwm; j++)
			free(cfg->indoms[i].inst_names[j]);
		free(cfg->indoms[i].inst_ids);
		free(cfg->indoms[i].inst_names);
	}
	free(cfg->indoms);
	free(cfg->pmids);

	memset(cfg, 0, sizeof(*cfg));
}

#endif /* HAVE_PMI_APPEND */
