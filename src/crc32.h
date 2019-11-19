#ifndef PG_PROMETHEUS_CRC32_H
#define PG_PROMETHEUS_CRC32_H

#include "types.h"

extern void crc32(const void *data, size_t n_bytes, uint32 *crc);

#endif /* PG_PROMETHEUS_CRC32_H */
