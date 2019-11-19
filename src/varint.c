#include "varint.h"

uint16
scan_varint(unsigned len, const uint8 *data)
{
	uint16 i;
	if (len > 10)
		len = 10;
	for (i = 0; i < len; i++)
		if ((data[i] & 0x80) == 0)
			break;
	if (i == len)
		return 0;
	return i + 1;
}

static inline uint32
parse_uint32(unsigned len, const uint8 *data)
{
	uint32_t rv = data[0] & 0x7f;
	if (len > 1) {
		rv |= ((uint32_t) (data[1] & 0x7f) << 7);
		if (len > 2) {
			rv |= ((uint32_t) (data[2] & 0x7f) << 14);
			if (len > 3) {
				rv |= ((uint32_t) (data[3] & 0x7f) << 21);
				if (len > 4)
					rv |= ((uint32_t) (data[4]) << 28);
			}
		}
	}
	return rv;
}

static inline uint64
parse_uint64(unsigned len, const uint8 *data)
{
	unsigned shift, i;
	uint64_t rv;

	if (len < 5)
		return parse_uint32(len, data);
	rv = ((uint64_t) (data[0] & 0x7f)) |
		((uint64_t) (data[1] & 0x7f) << 7) |
		((uint64_t) (data[2] & 0x7f) << 14) |
		((uint64_t) (data[3] & 0x7f) << 21);
	shift = 28;
	for (i = 4; i < len; i++) {
		rv |= (((uint64_t) (data[i] & 0x7f)) << shift);
		shift += 7;
	}
	return rv;
}

uint64
uint64_unpack(const uint8 *data, size_t len, uint16 *varintlen)
{
	uint16 l = scan_varint(len, data);

	if (varintlen)
		*varintlen = l;

	return parse_uint64(l, data);
}

int64
int64_unpack(const uint8 *data, size_t len, uint16 *varintlen)
{
	uint64 ux = uint64_unpack(data, len, varintlen);
	int64 x = (int64) (ux >> 1);

	if ((ux & 1) != 0)
		x = ~x;

	return x;
}
