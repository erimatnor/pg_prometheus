#ifndef PG_PROMETHEUS_AM_H
#define PG_PROMETHEUS_AM_H

#include <postgres.h>
#include <fmgr.h>

Datum prom_handler(PG_FUNCTION_ARGS);

#endif /* PG_PROMETHEUS_AM_H */
