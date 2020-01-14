#include <strings.h>
#include <assert.h>

#include "types.h"
#include "varint.h"
#include "crc32.h"

typedef struct __attribute__((__packed__)) TOC  {
	uint64 symbols;
	uint64 series;
	uint64 label_indices_start;
	uint64 label_offset_table;
	uint64 postings_start;
	uint64 postings_offset_start;
	uint8 crc32[4];
} TOC;

typedef struct SymbolTable
{
	uint32 len;
	uint32 num_symbols;
	const uint8 *symbols;
	uint8 crc32[4];
} SymbolTable;

typedef struct Series
{
	uint64 len;
	const uint8 *data;
	uint8 crc32[4];
} Series;

typedef struct LabelIndex
{
	uint32 len;
	uint32 num_names;
	uint32 num_entries;
	const uint32 *ref;
	uint8 crc32[4];
} LabelIndex;

typedef struct Postings
{
	uint32 len;
	uint32 num_entries;
	const uint32 *ref;
	uint8 crc32[4];
} Postings;

typedef struct LabelOffsetTable
{
	uint32 len;
	uint32 num_entries;
	const uint8 *data;
	uint8 crc32[4];
} LabelOffsetTable;

typedef struct PostingsOffsetTable
{
	uint32 len;
	uint32 num_entries;
	const uint8 *data;
	uint8 crc32[4];
} PostingsOffsetTable;

typedef struct IndexFile
{
	uint8 magic[4];
	uint8 version;
	SymbolTable stable;
	Series series;
	LabelIndex labelindex;
	Postings postings;
	LabelOffsetTable lot;
	PostingsOffsetTable pot;
	TOC toc;
} IndexFile;

static const uint8 MAGIC[] = {
	0xBA, 0xAA, 0xD7, 0x00
};

/*
static uint64
uint64_read(const uint8 *data)
{
	return ntohll(*((uint64 *) data));
}

static uint32
uint32_read(const uint8 *data)
{
	return ntohl(*((uint32 *) data));
	} */

/*
		uint64 symbols;
		uint64 series;
		uint64 label_indices_start;
		uint64 label_offset_table;
		uint64 postings_start;
		uint64 postings_offset_start;
*/
static size_t
toc_init(TOC *toc, const uint8 *data)
{
	uint64 *to = (uint64 *) toc;
	const uint64 *from = (const uint64 *) data;
	int i;

	for (i = 0; i < 6; i++)
		to[i] = ntohll(from[i]);

	memcpy(toc->crc32, &from[i], sizeof(toc->crc32));

	printf("TOC { "
		   "symbols=%" PRIu64 " "
		   "series=%" PRIu64 " "
		   "label_indices=%" PRIu64 " "
		   "postings_start=%" PRIu64 " "
		   "label_offset_table=%" PRIu64 " "
		   "postings_offset_start=%" PRIu64 "\n",
		   toc->symbols,
		   toc->series,
		   toc->label_indices_start,
		   toc->postings_start,
		   toc->label_offset_table,
		   toc->postings_offset_start);

	return sizeof(TOC);
}

static size_t
symboltable_init(SymbolTable *st, const uint8 *data, uint64 datalen)
{
	const uint32 *values = (const uint32 *) data;
	uint32 crc;

	st->len = ntohl(values[0]);
	st->num_symbols = ntohl(values[1]);
	st->symbols = (uint8 *) &values[2];
	memcpy(st->crc32, &data[st->len + sizeof(st->len)], sizeof(st->crc32));

	crc32(data, st->len, &crc);

	printf("SymbolTable { len=%u num_symbols=%u "
		   "crc32=[ 0x%02x 0x%02x 0x%02x 0x%02x ] "
		   "calc_crc=[ 0x%02x 0x%02x 0x%02x 0x%02x ]}\n",
		   st->len, st->num_symbols,
		   st->crc32[0],
		   st->crc32[1],
		   st->crc32[2],
		   st->crc32[3],
		   ((uint8 *)&crc)[0],
		   ((uint8 *)&crc)[1],
		   ((uint8 *)&crc)[2],
		   ((uint8 *)&crc)[3]);

	return st->len + sizeof(st->len);
}

static void
symboltable_dump(SymbolTable *st)
{
   uint32 off = 0;

   while (off < st->len - sizeof(st->len))
   {
	   uint16 varintlen;
	   uint64 strlen = uint64_unpack(&st->symbols[off], st->len - off, &varintlen);
	   char *str = malloc(strlen + 1);

	   str[strlen] = '\0';
	   off += varintlen;
	   memcpy(str, &st->symbols[off], strlen);
	   off += strlen;
	   printf("Symbol(%" PRIu64 "): %s\n", strlen, str);
	   free(str);
   }
}

static size_t
series_init(Series *series, const uint8 *data, uint64 datalen)
{
	uint16 varintlen;

	series->len = uint64_unpack(data, datalen, &varintlen);
	series->data = &data[varintlen];
	assert(series->len < datalen);
	printf("Series { len=%" PRIu64 "}\n", series->len);

	return series->len + sizeof(series->len);
}

static size_t
labelindex_init(LabelIndex *li, const uint8 *data, uint64 datalen)
{
	const uint32 *values = (const uint32 *) data;

	li->len = ntohl(values[0]);
	li->num_names = ntohl(values[1]);
	li->num_entries = ntohl(values[2]);
	li->ref = &values[3];
	assert(li->len < datalen);
	memcpy(li->crc32, &data[li->len + sizeof(li->len)], sizeof(li->crc32));

	printf("LabelIndex { len=%u num_names=%u num_entries=%u crc32=[ 0x%02x 0x%02x 0x%02x 0x%02x ] }\n",
		   li->len,
		   li->num_names,
		   li->num_entries,
		   li->crc32[0],
		   li->crc32[1],
		   li->crc32[2],
		   li->crc32[3]);

	return li->len + sizeof(li->len);
}

static size_t
postings_init(Postings *p, const uint8 *data, uint64 datalen)
{
	return datalen;
}


static size_t
labeloffset_table_init(LabelOffsetTable *lot, const uint8 *data, uint64 datalen)
{
	return datalen;
}


static size_t
postingsoffset_table_init(PostingsOffsetTable *pot, const uint8 *data, uint64 datalen)
{
	return datalen;
}

static void
indexfile_init(IndexFile *index, const uint8 *data,
			   size_t datalen)
{
	uint64 toc_offset = datalen - sizeof(TOC);

	memcpy(index->magic, data, 4);
	index->version = data[4];

	printf("MAGIC: [ 0x%02x 0x%02x 0x%02x 0x%02x ] version %u\n",
		   index->magic[0],
		   index->magic[1],
		   index->magic[2],
		   index->magic[3],
		   index->version);

	if (memcmp(MAGIC, index->magic, sizeof(MAGIC)) != 0)
	{
		fprintf(stderr, "Magic version does not match\n");
		exit(-1);
	}

	toc_init(&index->toc, &data[toc_offset]);
	symboltable_init(&index->stable, &data[index->toc.symbols],
					 index->toc.series - index->toc.symbols);
	series_init(&index->series, &data[index->toc.series],
				index->toc.label_indices_start - index->toc.series);
	labelindex_init(&index->labelindex, &data[index->toc.label_indices_start],
					index->toc.postings_start - index->toc.label_indices_start);
	postings_init(&index->postings, &data[index->toc.postings_start],
				  index->toc.label_offset_table - index->toc.postings_start);
	labeloffset_table_init(&index->lot, &data[index->toc.label_offset_table],
				  index->toc.postings_offset_start - index->toc.label_offset_table);
	postingsoffset_table_init(&index->pot, &data[index->toc.postings_offset_start],
							   toc_offset - index->toc.postings_offset_start);

}

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	IndexFile index;
	const char *filepath = NULL;
	struct stat sb;
	size_t length;
	uint8 *rawfile;
	int ret;
	int fd;
	bool do_dump = false;

	if (argc < 2)
		elog(ERROR, "wrong number of arguments");

	argv++;
	argc--;

	while (argc)
	{
		if (argv[0][0] == '-')
		{
			switch (argv[0][1])
			{
			case 'd':
				do_dump = true;
				break;
			case '\0':
				fprintf(stderr, "bad argument: %s\n", argv[0]);
				return -1;
			default:
				break;
			}
		}
		else
		{
			filepath = argv[0];
		}

		argv++;
		argc--;
	}

	if (filepath == NULL)
	{
		fprintf(stderr, "no indexfile given\n");
		return -1;
	}

	fd = open(filepath, O_RDONLY);

	if (fd == -1)
		elog(ERROR, "Could not open file: %s", strerror(errno));

	ret = fstat(fd, &sb);

	if (ret == -1)
		elog(ERROR, "Could not stat file: %s", strerror(errno));

	length = sb.st_size;

	printf("Size of file is %zu\n", length);

	rawfile = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, 0);

	indexfile_init(&index, rawfile, length);

	if (do_dump)
	{
		symboltable_dump(&index.stable);
	}

	munmap(rawfile, length);

	return close(fd);
}
