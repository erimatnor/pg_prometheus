# Experimental Prometheus table access method for PostgreSQL

This version of `pg_prometheus` introduces and experimental table
access method for PostgreSQL that allows reading Prometheus data
chunks via a PostgreSQL table. The table access method functionality
requires PostgreSQL 12.

Initially, the table access method (`am.c`) will only be a shim. The
parsing of Prometheus chunk and index files are implemented
separately, but will be tied into the access method implementation
once complete.

## Parsing of Prometheus data format

Currently, it is possible to build two separate binaries for reading
Prometheus chunks and indexes:

* `PG_CONFIG=/path/to/pg_config make chunkfile`
* `PG_CONFIG=/path/to/pg_config make indexfile`


Point these binaries to a chunk or index file, respectively, to read
those files, for instance:

```
$ ./chunkfile /path/to/prometheus/data/01DSHRSGRR2X0Y4A7PA2PSXQ2Q/chunks/000001
```
