#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <assert.h>

#include "varint.h"
#include "bitstream.h"

typedef struct ChunkFile
{
	uint8 magic[4];
	uint8 version;
	uint8 padding[3];
	uint8 chunks[0];
} ChunkFile;

typedef struct Chunk
{
	uint64 len;
	uint8 encoding;
	const uint8 *data;
	uint32 crc32;
} Chunk;


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

static SampleIterator *
sample_iter_init(SampleIterator *it, Chunk *chunk)
{
	memset(it, 0, sizeof(SampleIterator));
	bitstream_init(&it->bs, chunk->data + 2, chunk->len - 2);
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
		uint8 mbits = 0;
		uint64 vbits = 0;
		uint64 bits = 0;

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
			/* Read leading bits */
			it->err = bitstream_read_bits(&it->bs, 5, &bits);
			assert((uint8) (bits & 0xff) <= 0x1f);

			if (it->err != 0)
				return false;

			it->leading = bits & 0xff;
			assert(it->leading <= 64);

			/* Read meaningful bits */
			it->err = bitstream_read_bits(&it->bs, 6, &bits);

			if (it->err != 0)
				return false;

			mbits = bits & 0xff;

			/* 0 significant bits here means we overflowed and we actually need
			 * 64. */
			if (mbits == 0)
				mbits = 64;

			/* Calculate trailing bits */
			it->trailing = 64 - it->leading - mbits;
			assert(it->trailing <= 64);
		}

		assert(it->leading  + it->trailing <= 64);
		mbits = 64 - it->leading - it->trailing;
		it->err = bitstream_read_bits(&it->bs, mbits, &bits);

		if (it->err != 0)
			return false;

		memcpy(&vbits, &it->value, 8);
		//vbits = *((uint64 *) &it->value);
		vbits ^= (bits << it->trailing);
		memcpy(&it->value, &vbits, 8);
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

	if (it->numread == 0)
	{
		uint64 bits;

		bitstream_read_varint(&it->bs, &it->timestamp);
		it->err = bitstream_read_bits(&it->bs, 64, &bits);

		if (it->err != 0)
			return false;

		memcpy(&it->value, &bits, 8);
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
	/*printf("Reading delta of delta @ 0x%02x 0x%02x 0x%02x 0x%02x count=%d\n",
		   it->bs.data[it->bs.off + 0],
		   it->bs.data[it->bs.off + 1],
		   it->bs.data[it->bs.off + 2],
		   it->bs.data[it->bs.off + 3],
		   it->bs.count); */

	for (i = 0; i < 4; i++)
	{
		Bit b;

		d = d << 1;

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
		break;
	case 0x02:
		sz = 14;
		break;
	case 0x06:
		sz = 17;
		break;
	case 0x0e:
		sz = 20;
		break;
	case 0x0f:
		it->err = bitstream_read_bits(&it->bs, 64, &bits);

		if (it->err != 0)
			return false;

		dod = (int64) bits;
		break;
	default:
		assert(false);
		exit(-1);
		break;
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
	const uint8 *const bytes = (const uint8 *const) data;
	uint16 varintlen;
	uint32 checksum;

	printf("reading chunk len: 0x%02x 0x%02x\n", bytes[0], bytes[1]);
	chunk->len = uint64_unpack(bytes, len, &varintlen);
	//chunk->len = uvarint_decode(bytes, &varintlen);
	//chunk->len = decode_unsigned_varint(bytes, &varintlen);

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

static const uint8 MAGIC[] = {
	0x85, 0xBD, 0x40, 0xDD
};

// 1000 0101 - 1011 1101 - 0100 0000 - 1101 1101
static Bit magic_bits[] = {
	1, 0, 0, 0, 0, 1, 0, 1,
	1, 0, 1, 1, 1, 1, 0, 1,
	0, 1, 0, 0, 0, 0, 0, 0,
	1, 1, 0, 1, 1, 1, 0, 1
};

static void
test_read_bit(void)
{
	Bitstream bs;
	Bit b;
	int err;
	int i;

	bitstream_init(&bs, &MAGIC[0], sizeof(MAGIC));

	for (i = 0; i < sizeof(magic_bits); i++)
	{
		err = bitstream_read_bit(&bs, &b);
		assert(err == 0);
		assert(b == magic_bits[i]);
	}
}

static void
test_read_bits(void)
{
	Bitstream bs;
	uint64 bits;
	uint32 result;
	int err;

	bitstream_init(&bs, &MAGIC[0], sizeof(MAGIC));
	err = bitstream_read_bits(&bs, 32, &bits);
	assert(err == 0);

	result = ntohl(bits & 0xffffffff);
	assert(memcmp(&result, &MAGIC[0], 4) == 0);
}

static void
test_read_5_bits(void)
{
	Bitstream bs;
	uint64 bits;
	uint8 allones[2] = { 0xff, 0xff };
	int err;

	bitstream_init(&bs, &MAGIC[0], sizeof(MAGIC));
	err = bitstream_read_bits(&bs, 5, &bits);
	assert(err == 0);

	printf("bits: 0x%02x\n", (uint8) (bits & 0xff));
	assert((bits & 0xff) == 0x10);

	err = bitstream_read_bits(&bs, 5, &bits);
	assert(err == 0);

	printf("bits: 0x%02x\n", (uint8) (bits & 0xff));
	assert((bits & 0xff) == 0x16);

	bitstream_init(&bs, &allones[0], sizeof(allones));
	err = bitstream_read_bits(&bs, 2, &bits);
	assert(err == 0);

	printf("bits: 0x%02x\n", (uint8) (bits & 0xff));
	assert((bits & 0xff) == 0x03);

	err = bitstream_read_bits(&bs, 5, &bits);
	assert(err == 0);

	printf("bits: 0x%02x\n", (uint8) (bits & 0xff));
	assert((bits & 0xff) == 0x1f);

}

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

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

	test_read_bit();
	test_read_bits();
	test_read_5_bits();

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

	printf("ChunkFile size %zu magic: 0x%02x%02x%02x%02x version %u\n",
		   sizeof(ChunkFile),
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

	while (remaining > 0)
	{
		Chunk chunk;

		offset += fill_chunk(&chunk, &chunkfile->chunks[offset], remaining);
		printf("Chunk starts at offset %ld\n",  chunk.data - ((uint8 *)chunkfile));
		remaining -= offset;
		chunk_seqno++;

		sample_iter_init(&it, &chunk);

		while (sample_iter_next(&it))
		{
			printf("%" PRIi64 " %lf\n", it.timestamp, it.value);
		}

		if (it.err != 0)
		{
			elog(DEBUG, "Iterator err: %d", it.err);
			break;
		}

		printf("offset=%lld remaining=%zd\n", offset, remaining);
	}

	munmap(chunkfile, length);

	return close(fd);
}
