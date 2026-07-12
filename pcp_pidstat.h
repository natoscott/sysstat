/*
 * pcp_pidstat.h: Read per-process statistics from a PCP archive for pidstat.
 * (C) 2026 Red Hat, Inc.
 * (C) 2025-2026 by Sebastien Godard (sysstat <at> orange.fr)
 */

#ifndef _PCP_PIDSTAT_H
#define _PCP_PIDSTAT_H

#ifdef HAVE_PCP

/*
 * Read from a PCP archive and display pidstat-format output.
 *
 * IN:
 * @archive	PCP archive base path.
 *
 * RETURNS:
 * 0 on success, non-zero on fatal error.
 */
int pcp_pidstat_run(const char *archive);

#else /* !HAVE_PCP */

static inline int
pcp_pidstat_run(const char *a __attribute__((unused))) { return 0; }

#endif /* HAVE_PCP */
#endif /* _PCP_PIDSTAT_H */
