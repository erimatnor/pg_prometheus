#ifndef PG_PROMETHEUS_BITSTREAM_H
#define PG_PROMETHEUS_BITSTREAM_H

#include "types.h"

#define ZERO false
#define BS_EOF -100

typedef struct Bitstream {
	const uint8 *data;
	size_t len;
	off_t off;
	uint8 count;
} Bitstream;

extern void bitstream_init(Bitstream *bs, const uint8 *data, size_t len);
extern int bitstream_read_bit(Bitstream *bs, Bit *bit);
extern int bitstream_read_byte(Bitstream *bs, Byte *byte);
extern int bitstream_read_bytes(Bitstream *bs, Byte *byte, uint16 len);
extern int bitstream_read_bits(Bitstream *bs, uint8 nbits, uint64 *bits);
extern int bitstream_read_uvarint(Bitstream *bs, uint64 *value);
extern int bitstream_read_varint(Bitstream *bs, int64 *value);

#endif /* PG_PROMETHEUS_BITSTREAM_H */
