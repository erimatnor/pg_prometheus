#include "bitstream.h"
#include "varint.h"

void
bitstream_init(Bitstream *bs, const uint8 *data, size_t len)
{
	memset(bs, 0, sizeof(*bs));
	bs->data = data;
	bs->len = len;
	bs->count = 8;
}

static inline const uint8
bsbyte(Bitstream *bs)
{
	return bs->data[bs->off];
}

static inline bool
bseof(Bitstream *bs)
{
	return (size_t)bs->off == bs->len;
}

static inline bool
bsinc(Bitstream *bs)
{
	bs->off++;
	return bseof(bs);
}

int
bitstream_read_bit(Bitstream *bs, Bit *bit)
{
	uint8 d;

	if (bseof(bs))
		return BS_EOF;

	if (bs->count == 0)
	{
		if (bsinc(bs))
			return BS_EOF + 1;

		bs->count = 8;
	}

	d = ((uint8) (bsbyte(bs) << (8 - bs->count))) & 0x80;
	bs->count--;

	if (bit)
		*bit = d != 0;

	elog(DEBUG, "BIT: @ 0x%02x count=%u  [%d]", bs->data[bs->off], bs->count, *bit);

	return 0;
}

int
bitstream_read_byte(Bitstream *bs, Byte *byte)
{
	uint8 b;

	if (bseof(bs))
		return BS_EOF;

	if (bs->count == 0)
	{
		if (bsinc(bs))
			return BS_EOF + 3;

		if (byte)
			*byte = bsbyte(bs);

		return 0;
	}

	if (bs->count == 8) {
		bs->count = 0;

		if (byte)
			*byte = bsbyte(bs);

		return 0;
	}

	if (byte)
		b = ((uint8 ) bsbyte(bs) << (8 - bs->count));

	if (bsinc(bs))
	{
		if (byte)
			*byte = 0;
		return BS_EOF + 4;
	}

	/* We just advanced the stream and can assume the shift to be 0. */
	if (byte)
		*byte = b | ((uint8) (bsbyte(bs) >> bs->count));

	return 0;
}

int
bitstream_read_bytes(Bitstream *bs, Byte *byte, uint16 len)
{
	uint16 i;
	int nread = 0;

	if (!byte)
		return 0;

	for (i = 0; i < len; i++)
	{
		int err = bitstream_read_byte(bs, &byte[i]);

		if (err != 0)
			return err;

		nread++;
	}

	return nread;
}

int
bitstream_read_bits(Bitstream *bs, uint8 nbits, uint64 *bits)
{
	uint64 u = 0;

	while (nbits >= 8)
	{
		Byte byte;
		int err;

		err = bitstream_read_byte(bs, &byte);

		if (err != 0)
			return err;

		u = (u << 8) | byte;
		nbits -= 8;
	}

	if (nbits == 0)
	{
		if (bits)
			*bits = u;

		return 0;
	}

	if (nbits > bs->count)
	{
		u = (u << bs->count) | ((uint8) ((bsbyte(bs) << (8 - bs->count))) >> (8 - bs->count));
		nbits -= bs->count;

		if (bsinc(bs))
			return BS_EOF + 5;

		bs->count = 8;
	}

	//printf("u=%" PRIu64 " leftshift=%d rightshift=%d\n", u, (8 - bs->count), (8 - nbits));
	u = (u << nbits) | ((uint8) ((bsbyte(bs) << (8 - bs->count)))) >> (8 - nbits);
	bs->count -= nbits;

	// 11111111
	// << 2
	// 11111100
	// >> 3
	// 00011111

	if (bits)
		*bits = u;

	return 0;
}

#define MAX_VARINT_LEN 10

int
bitstream_read_uvarint(Bitstream *bs, uint64 *value)
{
	uint16 varintlen;
	Byte bytes[MAX_VARINT_LEN];
	uint64 v;
	int nread;
	off_t off = bs->off;
	uint8 count = bs->count;

	nread = bitstream_read_bytes(bs, bytes, sizeof(bytes));

	if (nread < 0)
		return nread;

	elog(DEBUG, "** Uvarint @ 0x%02x 0x%02x count=%d", bytes[0],
				 bytes[1], bs->count);

	v = uint64_unpack(bytes, nread, &varintlen);

	if (value)
		*value = v;

	/* First back up the bytes we read from the stream and then add up the
	 * actual varint len */
	bs->off = off;
	bs->count = count;
	nread = bitstream_read_bytes(bs, bytes, varintlen);

	return varintlen;
}

int
bitstream_read_varint(Bitstream *bs, int64 *value)
{
	uint16 varintlen;
	Byte bytes[MAX_VARINT_LEN];
	int64 v;
	int nread;
	off_t off = bs->off;
	uint8 count = bs->count;

	nread = bitstream_read_bytes(bs, bytes, sizeof(bytes));

	if (nread < 0)
		return nread;

	elog(DEBUG, "** Varint @ 0x%02x 0x%02x count=%d", bytes[0],
				 bytes[1], bs->count);

	v = int64_unpack(bytes, nread, &varintlen);

	if (value)
		*value = v;

	/* First back up the bytes we read from the stream and then add up the
	 * actual varint len */
	bs->off = off;
	bs->count = count;
	nread = bitstream_read_bytes(bs, bytes, varintlen);

	return varintlen;
}
