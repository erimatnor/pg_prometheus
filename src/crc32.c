#include "crc32.h"

static uint32
crc32_for_byte(uint32 r)
{
    int j;

    for (j = 0; j < 8; ++j)
        r = (r & 1? 0: (uint32)0xEDB88320L) ^ r >> 1;

    return r ^ (uint32)0xFF000000L;
}

void
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
