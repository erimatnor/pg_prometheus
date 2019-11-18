#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <assert.h>

enum {
	ERROR,
	WARNING,
	NOTICE,
	DEBUG,
};

#define elog(x, fmt, ...)								\
	{													\
		if (x == ERROR) {								\
			fprintf(stderr, fmt "\n", ##__VA_ARGS__);	\
			exit(-1);									\
		} else {										\
			fprintf(stdout, fmt "\n", ##__VA_ARGS__);	\
		}												\
	}


typedef float float32;
typedef double float64;
typedef uint8_t uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;
typedef int8_t int8;
typedef int16_t int16;
typedef int32_t int32;
typedef int64_t int64;
typedef unsigned char uchar;

typedef struct ChunkFile
{
	uchar magic[4];
	uint32 version:8;
	uint32 padding:24;
	uchar chunks[0];
} ChunkFile;


typedef struct Chunk
{
	uint64 len;
	uint8 encoding;
	const uchar *data;
	uint32 crc32;
} Chunk;

static uint32
crc32_for_byte(uint32 r)
{
	int j;

	for (j = 0; j < 8; ++j)
		r = (r & 1? 0: (uint32)0xEDB88320L) ^ r >> 1;

	return r ^ (uint32)0xFF000000L;
}

static void
crc32(const void *data, size_t n_bytes, uint32* crc)
{
  static uint32 table[0x100];
  size_t i;

  if (!*table)
  {
	  for (i = 0; i < 0x100; ++i)
		  table[i] = crc32_for_byte(i);
  }

  for (i = 0; i < n_bytes; ++i)
	  *crc = table[(uint8)*crc ^ ((uint8*)data)[i]] ^ *crc >> 8;
}

/*
static uint64
decode_unsigned_varint(const void *const data, size_t *decoded_bytes)
{
	const uchar *const bytes = (const uchar *const) data;
	size_t i = 0;
	uint64_t decoded_value = 0;
	int shift_amount = 0;

	do
	{
		decoded_value |= (uint64)(bytes[i] & 0x7F) << shift_amount;
		shift_amount += 7;
	} while ( (bytes[i++] & 0x80) != 0 );

	if (decoded_bytes)
		*decoded_bytes = i;

	return decoded_value;
}
*/

#if 0

static const char MSB = 0x80;

static uint64
uvarint_decode(const unsigned char* buf, size_t* bytes) {
	uint64 result = 0;
	int bits = 0;
	const unsigned char* ptr = buf;
	uint64 ll;

	if (bytes != NULL)
		*bytes = 0;

	while (*ptr & MSB) {
		ll = *ptr;
		result += ((ll & 0x7F) << bits);
		ptr++;
		bits += 7;
//	assert((ptr - buf) < len);
	}

	ll = *ptr;
	result += ((ll & 0x7F) << bits);

	if (bytes != NULL)
		*bytes = ptr - buf + 1;

	return result;
}
#endif

static uint16
scan_varint(unsigned len, const uint8_t *data)
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

static inline uint32_t
parse_uint32(unsigned len, const uint8_t *data)
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

static uint64_t
parse_uint64(unsigned len, const uint8_t *data)
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

static uint64
uint64_unpack(const uchar *data, size_t len, uint16 *varintlen)
{
	uint16 l = scan_varint(len, data);

	if (varintlen)
		*varintlen = l;

	return parse_uint64(l, data);
}

static int64
int64_unpack(const uchar *data, size_t len, uint16 *varintlen)
{
	uint64 ux = uint64_unpack(data, len, varintlen);
	int64 x = (int64) (ux >> 1);

	if ((ux & 1) != 0)
		x = ~x;

	return x;
}

typedef bool Bit;
typedef uchar Byte;

#define ZERO false
#define BS_EOF 1

typedef struct Bitstream {
	const uchar *data;
	size_t len;
	off_t off;
	uint8 num_valid_bits;
} Bitstream;

static void
bitstream_init(Bitstream *bs, const uchar *data, size_t len)
{
	memset(bs, 0, sizeof(*bs));
	bs->data = data;
	bs->len = len;
	bs->num_valid_bits = 8;
}

static int
bitstream_read_bit(Bitstream *bs, Bit *bit)
{
	if ((size_t) bs->off == bs->len)
		return BS_EOF;

	if (bs->num_valid_bits == 0)
	{
		bs->off++;

		if ((size_t) bs->off == bs->len)
			return BS_EOF;

		bs->num_valid_bits = 8;
	}

	if (NULL != bit)
		*bit = (bs->data[0] << (8 - bs->num_valid_bits)) & 0x80;

	bs->num_valid_bits--;

	return 0;
}

static int
bitstream_read_byte(Bitstream *bs, Byte *byte)
{
	if ((size_t) bs->off == bs->len)
		return BS_EOF;


	if (bs->num_valid_bits == 0)
	{
		bs->off++;

		if ((size_t) bs->off == bs->len)
			return BS_EOF;

		if (byte)
			*byte = bs->data[bs->off - 1];

		return 0;
	}

	if (bs->num_valid_bits == 8) {
		bs->num_valid_bits = 0;

		if (byte)
			*byte = bs->data[0];

		return 0;
	}

	if (byte)
		*byte = bs->data[0] << (8 - bs->num_valid_bits);

	bs->off++;

	if ((size_t) bs->off == bs->len)
		return BS_EOF;

	/* We just advanced the stream and can assume the shift to be 0. */
	if (byte)
		*byte |= bs->data[0] >> bs->num_valid_bits;

	return 0;
}

static int
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

		u = (u << 8) | (uint64) byte;
		nbits -= 8;
	}

	if (nbits == 0)
	{
		if (bits)
			*bits = u;

		return 0;
	}

	if (nbits > bs->num_valid_bits)
	{
		u = (u << bs->num_valid_bits) | ((uint64) (bs->data[0]<<(8-bs->num_valid_bits))>>(8-bs->num_valid_bits));
		nbits -= bs->num_valid_bits;
		bs->off++;

		if ((size_t) bs->off == bs->len)
			return BS_EOF;

		bs->num_valid_bits = 8;
	}

	u = (u << nbits) | (uint64) ((bs->data[0]<<(8-bs->num_valid_bits))>>(8-nbits));

	bs->num_valid_bits -= nbits;

	if (bits)
		*bits = u;

	return 0;
}

static int
bitstream_read_uvarint(Bitstream *bs, uint64 *value)
{
	uint16 varintlen;
	uint64 v = uint64_unpack(&bs->data[bs->off], bs->len - bs->off, &varintlen);

	if (value)
		*value = v;

	bs->off += varintlen;

	return varintlen;
}

static int
bitstream_read_varint(Bitstream *bs, int64 *value)
{
	uint16 varintlen;
	int64 v = int64_unpack(&bs->data[bs->off], bs->len - bs->off, &varintlen);

	if (value)
		*value = v;

	bs->off += varintlen;

	return varintlen;
}

typedef struct SampleIterator {
	Bitstream bs;
	int err;
	uint16 numread;
	uint16 numtotal;
	uint8 leading;
	uint8 trailing;
	uint64 offset;
	uint64 tdelta;
	int64 timestamp;
	float64 value;
} SampleIterator;

SampleIterator *
sample_iter_init(SampleIterator *it, Chunk *chunk)
{
	memset(it, 0, sizeof(SampleIterator));
	bitstream_init(&it->bs, chunk->data + sizeof(uint16), chunk->len);
	it->numtotal |= chunk->data[0] << 8;
	it->numtotal |= chunk->data[1];

	return it;
}

static bool
sample_iter_read_value(SampleIterator *it)
{
	Bit b;

	it->err = bitstream_read_bit(&it->bs, &b);

	if (it->err != 0)
		return false;

	if (b == ZERO)
	{
		/* it.val = it.val */
	}
	else
	{
		uint8 mbits;
		uint64 vbits;
		uint64 bits;

		it->err = bitstream_read_bit(&it->bs, &b);

		if (it->err != 0)
			return false;

		if (b == ZERO)
		{
			/* reuse leading/trailing zero bits

			   it.leading, it.trailing = it.leading, it.trailing
			*/
		}
		else
		{

			it->err = bitstream_read_bits(&it->bs, 5, &bits);

			if (it->err != 0)
				return false;


			it->leading = (uint8) bits;

			it->err = bitstream_read_bits(&it->bs, 6, &bits);

			if (it->err != 0)
				return false;

			mbits = (uint8) bits;

			/* 0 significant bits here means we overflowed and we actually need
			 * 64. */
			if (mbits == 0)
				mbits = 64;

			it->trailing = 64 - it->leading - mbits;
		}

		mbits = 64 - it->leading - it->trailing;
		it->err = bitstream_read_bits(&it->bs, mbits, &bits);

		if (it->err != 0)
			return false;

		vbits = *((uint64 *) &it->value);
		vbits ^= (bits << it->trailing);
		it->value = *((float64 *) &vbits);
	}

	it->numread++;
	return true;
}

static bool
sample_iter_next(SampleIterator *it)
{
	uint64 bits;
	Byte d = 0;
	uint8 sz = 0;
	int64 dod = 0;
	int i;

	if (it->err != 0 || it->numread == it->numtotal)
	{
		if (it->err != 0)
			printf("Error: %d\n", it->err);
		else
			printf("REached numtotal\n");
		return false;
	}

	elog(DEBUG, "Next: numread=%u numtotal=%u bytes 0x%02x 0x%02x",
		 it->numread, it->numtotal, it->bs.data[0], it->bs.data[1]);

	if (it->numread == 0)
	{
		uint64 bits;

		bitstream_read_varint(&it->bs, &it->timestamp);

		it->err = bitstream_read_bits(&it->bs, 64, &bits);

		if (it->err != 0)
			return false;

	   it->value = *((float64 *) &bits);
	   it->numread++;

	   return true;
	}

	if (it->numread == 1)
	{
		bitstream_read_uvarint(&it->bs, &it->tdelta);
		it->timestamp += (int64) it->tdelta;

		return sample_iter_read_value(it);
	}

	// read delta-of-delta
	for (i = 0; i < 4; i++)
	{
		Bit b;

		d <<= 1;

		it->err = bitstream_read_bit(&it->bs, &b);

		if (it->err != 0)
			return false;

		if (b == ZERO)
			break;

		d |= 1;
	}

	switch (d)
	{
	case 0x00:
		// dod == 0
	case 0x02:
		sz = 14;
	case 0x06:
		sz = 17;
	case 0x0e:
		sz = 20;
	case 0x0f:
		it->err = bitstream_read_bits(&it->bs, 64, &bits);

		if (it->err != 0)
			return false;

		dod = (int64) bits;
	}

	if (sz != 0)
	{
		it->err = bitstream_read_bits(&it->bs, sz, &bits);

		if (it->err != 0)
			return false;

		if (bits > (1 << (sz - 1)))
		{
			// or something
			bits = bits - (1 << sz);
		}

		dod = (int64) bits;
	}

	it->tdelta = (uint64)(((int64) it->tdelta) + dod);
	it->timestamp += (int64) it->tdelta;

	return sample_iter_read_value(it);
}


/*
00000000  85 bd 40 dd 01 00 00 00  13 01 [00 05] 88 a2 ef d4  |..@.............|
00000010  cc 5b 3e f0 73 c0 97 09  71 6e 98 75 00 8c a4 d1  |.[>.s...qn.u....|
00000020  84 13 01 00 05 88 a2 ef  d4 cc 5b 3e f1 78 ab eb  |..........[>.x..|

*/
static off_t
fill_chunk(Chunk *chunk, const void *const data, size_t len)
{
	const uchar *const bytes = (const uchar *const) data;
	uint16 varintlen;
	uint32 checksum;

	chunk->len = uint64_unpack(bytes, len, &varintlen);
	//chunk->len = uvarint_decode(bytes, &varintlen);

	if (chunk->len < varintlen)
		elog(ERROR, "Bad chunk format varintlen %u vs chunk->len %" PRIu64 "", varintlen, chunk->len);

	printf("chunk len %" PRIu64 " varintlen=%u\n", chunk->len, varintlen);

	chunk->encoding = bytes[varintlen];
	chunk->data = &bytes[varintlen + 1];
	chunk->crc32 = ntohl(*((uint32 *) &chunk->data[chunk->len]));

	crc32((uint8 *)&chunk->data[0], chunk->len, &checksum);

	printf("crc32: 0x%02x%02x%02x%02x   (0x%08x) verify: (0x%08x)\n",
		   chunk->data[chunk->len],
		   chunk->data[chunk->len + 1],
		   chunk->data[chunk->len + 2],
		   chunk->data[chunk->len + 3],
		   chunk->crc32,
		   checksum);

	/* if (checksum != chunk->crc32)
	   elog(ERROR, "Bad chunk checksum"); */

	return chunk->len + varintlen + 1 + sizeof(chunk->crc32);
}

static const uchar MAGIC[] = {
	0x85, 0xBD, 0x40, 0xDD
};

int
main(int argc, char **argv)
{
	const char *filepath;
	struct stat sb;
	ChunkFile *chunkfile;
	size_t length;
	ssize_t remaining;
	off_t offset;
	unsigned chunk_seqno = 0;
	SampleIterator it;
	//void *raw_chunk;
	int ret;
	int fd;

	if (argc < 2)
		elog(ERROR, "wrong number of arguments");

	filepath = argv[1];

	fd = open (filepath, O_RDONLY);

	if (fd == -1)
		elog(ERROR, "Could not open file: %s", strerror(errno));

	ret = fstat(fd, &sb);

	if (ret == -1)
		elog(ERROR, "Could not stat file: %s", strerror(errno));

	length = sb.st_size;

	chunkfile = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, 0);

	printf("magic: 0x%02x%02x%02x%02x version %u\n",
		   chunkfile->magic[0],
		   chunkfile->magic[1],
		   chunkfile->magic[2],
		   chunkfile->magic[3],
		   chunkfile->version);

	remaining = length;
	remaining -= sizeof(ChunkFile);
	offset = 0;

	if (memcmp(chunkfile->magic, MAGIC, sizeof(MAGIC)) != 0)
		elog(ERROR, "Invalid magic number 0x%02x%02x%02x%02x\n",
			 chunkfile->magic[0],
			 chunkfile->magic[1],
			 chunkfile->magic[2],
			 chunkfile->magic[3]);

	printf("offset: %zu\n", (uchar *) &chunkfile->chunks[0] - (uchar *) chunkfile);


	while (remaining > 0)
	{
		Chunk chunk;

		offset += fill_chunk(&chunk, &chunkfile->chunks[offset], remaining);
		remaining -= offset;
		chunk_seqno++;

		sample_iter_init(&it, &chunk);

		while (sample_iter_next(&it))
		{
			printf("sample: %" PRIi64 " %lf\n", it.timestamp, it.value);
		}

		if (it.err < 0)
		{
			elog(DEBUG, "Iterator err: %d", it.err);
		}

		printf("offset=%zd remaining=%zd\n", offset, remaining);
	}

	munmap(chunkfile, length);

	return close(fd);
}
