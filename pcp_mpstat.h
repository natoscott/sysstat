/*
 * pcp_mpstat.h: Read CPU statistics from a PCP archive for mpstat.
 * (C) 2026 Red Hat, Inc.
 * (C) 2025-2026 by Sebastien Godard (sysstat <at> orange.fr)
 */

#ifndef _PCP_MPSTAT_H
#define _PCP_MPSTAT_H

#ifdef HAVE_PCP

int pcp_mpstat_run(const char *archive);

#else

static inline int
pcp_mpstat_run(const char *a __attribute__((unused))) { return 0; }

#endif
#endif /* _PCP_MPSTAT_H */
