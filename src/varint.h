#ifndef PG_PROMETHEUS_VARINT_H
#define PG_PROMETHEUS_VARINT_H

#include "types.h"

extern uint16 scan_varint(unsigned len, const uint8 *data);
extern uint64 uint64_unpack(const uint8 *data, size_t len, uint16 *varintlen);
extern int64 int64_unpack(const uint8 *data, size_t len, uint16 *varintlen);

#endif /* PG_PROMETHEUS_VARINT_H */
