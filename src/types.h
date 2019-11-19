#ifndef PG_PROMETHEUS_TYPES_H
#define PG_PROMETHEUS_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>

enum {
	ERROR,
	WARNING,
	NOTICE,
	DEBUG,
};

#define elog(x, fmt, ...)									\
	{														\
		if (x == ERROR) {									\
			fprintf(stderr, fmt "\n", ##__VA_ARGS__);		\
			exit(-1);										\
		} else if (x == DEBUG) {							\
		} else	{											\
			fprintf(stdout, fmt "\n", ##__VA_ARGS__);		\
		}													\
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
typedef bool Bit;
typedef uint8 Byte;

#endif /* PG_PROMETHEUS_TYPES_H */
