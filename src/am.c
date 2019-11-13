#include <postgres.h>
#include <access/tableam.h>
#include <access/table.h>
#include <access/transam.h>
#include <access/reloptions.h>
#include <access/multixact.h>
#include <catalog/pg_type.h>
#include <catalog/namespace.h>
#include <utils/syscache.h>

#include "am.h"
#include "utils/rel.h"

#define LOG_FUNCTION_LEVEL(level) elog(level, "%s not implemented", __func__)
#define LOG_FUNCTION LOG_FUNCTION_LEVEL(ERROR)
#define LOG_FUNCTION_NO_ERR LOG_FUNCTION_LEVEL(NOTICE)

static void prom_tupletableslot_init(TupleTableSlot *slot) {}
static void prom_tupletableslot_release(TupleTableSlot *slot) {}
static void prom_tupletableslot_clear(TupleTableSlot *slot) {}

static void
prom_tupletableslot_getsomeattrs(TupleTableSlot *slot, int natts)
{
	LOG_FUNCTION;
}

/*
 * Returns value of the given system attribute as a datum and sets isnull
 * to false, if it's not NULL. Throws an error if the slot type does not
 * support system attributes.
 */
static Datum
prom_tupletableslot_getsysattr(TupleTableSlot *slot, int attnum, bool *isnull)
{
	LOG_FUNCTION;
	return 0;
}

/*
 * Make the contents of the slot solely depend on the slot, and not on
 * underlying resources (like another memory context, buffers, etc).
 */
static void
prom_tupletableslot_materialize(TupleTableSlot *slot)
{
	LOG_FUNCTION;
}

/*
 * Copy the contents of the source slot into the destination slot's own
 * context. Invoked using callback of the destination slot.
 */
static void
prom_tupletableslot_copyslot(TupleTableSlot *dstslot, TupleTableSlot *srcslot)
{
	LOG_FUNCTION;
}

/*
 * Return a heap tuple "owned" by the slot. It is slot's responsibility to
 * free the memory consumed by the heap tuple. If the slot can not "own" a
 * heap tuple, it should not implement this callback and should set it as
 * NULL.
 */
static HeapTuple
prom_tupletableslot_get_heap_tuple(TupleTableSlot *slot)
{
	LOG_FUNCTION;
	return NULL;
}

/*
 * Return a minimal tuple "owned" by the slot. It is slot's responsibility
 * to free the memory consumed by the minimal tuple. If the slot can not
 * "own" a minimal tuple, it should not implement this callback and should
 * set it as NULL.
 */
static MinimalTuple
prom_tupletableslot_get_minimal_tuple(TupleTableSlot *slot)
{
	LOG_FUNCTION;
	return NULL;
}

/*
 * Return a copy of heap tuple representing the contents of the slot. The
 * copy needs to be palloc'd in the current memory context. The slot
 * itself is expected to remain unaffected. It is *not* expected to have
 * meaningful "system columns" in the copy. The copy is not be "owned" by
 * the slot i.e. the caller has to take responsibility to free memory
 * consumed by the slot.
 */
static HeapTuple
prom_tupletableslot_copy_heap_tuple(TupleTableSlot *slot)
{
	LOG_FUNCTION;
	return NULL;
}

/*
 * Return a copy of minimal tuple representing the contents of the slot.
 * The copy needs to be palloc'd in the current memory context. The slot
 * itself is expected to remain unaffected. It is *not* expected to have
 * meaningful "system columns" in the copy. The copy is not be "owned" by
 * the slot i.e. the caller has to take responsibility to free memory
 * consumed by the slot.
 */
static MinimalTuple
prom_tupletableslot_copy_minimal_tuple(TupleTableSlot *slot)
{
	LOG_FUNCTION;
	return NULL;
}

static const TupleTableSlotOps prom_tuple_table_slot_ops = {
	.base_slot_size = 1,
	.init = prom_tupletableslot_init,
	.release = prom_tupletableslot_release,
	.clear = prom_tupletableslot_clear,
	.getsomeattrs = prom_tupletableslot_getsomeattrs,
	.getsysattr = prom_tupletableslot_getsysattr,
	.materialize = prom_tupletableslot_materialize,
	.copyslot = prom_tupletableslot_copyslot,
	.get_heap_tuple = prom_tupletableslot_get_heap_tuple,
	.get_minimal_tuple = prom_tupletableslot_get_minimal_tuple,
	.copy_heap_tuple = prom_tupletableslot_copy_heap_tuple,
	.copy_minimal_tuple = prom_tupletableslot_copy_minimal_tuple,
};

static const TupleTableSlotOps *
prom_slot_callbacks(Relation rel)
{
	return &prom_tuple_table_slot_ops;
}

static TableScanDesc
prom_scan_begin(Relation rel,
				Snapshot snapshot,
				int nkeys, struct ScanKeyData *key,
				ParallelTableScanDesc pscan,
				uint32 flags)
{
	LOG_FUNCTION;
	return NULL;
}

static	void
prom_scan_end(TableScanDesc scan)
{
	LOG_FUNCTION;
}

/*
 * Restart relation scan.  If set_params is set to true, allow_{strat,
 * sync, pagemode} (see scan_begin) changes should be taken into account.
 */
static void
prom_scan_rescan(TableScanDesc scan, struct ScanKeyData *key,
				 bool set_params, bool allow_strat,
				 bool allow_sync, bool allow_pagemode)
{
	LOG_FUNCTION;
}

/*
 * Return next tuple from `scan`, store in slot.
 */
static bool
prom_scan_getnextslot(TableScanDesc scan,
						   ScanDirection direction,
						   TupleTableSlot *slot)
{
	LOG_FUNCTION;
	return false;
}


/* ------------------------------------------------------------------------
 * Parallel table scan related functions.
 * ------------------------------------------------------------------------
 */

/*
 * Estimate the size of shared memory needed for a parallel scan of this
 * relation. The snapshot does not need to be accounted for.
 */
static Size
prom_parallelscan_estimate(Relation rel)
{
	LOG_FUNCTION;
	return 0;
}

/*
 * Initialize ParallelTableScanDesc for a parallel scan of this relation.
 * `pscan` will be sized according to parallelscan_estimate() for the same
 * relation.
 */
static Size
prom_parallelscan_initialize(Relation rel, ParallelTableScanDesc pscan)
{
	LOG_FUNCTION;
	return 0;
}

/*
 * Reinitialize `pscan` for a new scan. `rel` will be the same relation as
 * when `pscan` was initialized by parallelscan_initialize.
 */
static void
prom_parallelscan_reinitialize(Relation rel, ParallelTableScanDesc pscan)
{
	LOG_FUNCTION;
}

/*
 * Prepare to fetch tuples from the relation, as needed when fetching
 * tuples for an index scan.  The callback has to return an
 * IndexFetchTableData, which the AM will typically embed in a larger
 * structure with additional information.
 *
 * Tuples for an index scan can then be fetched via index_fetch_tuple.
 */
static struct IndexFetchTableData *
prom_index_fetch_begin(Relation rel)
{
	LOG_FUNCTION;
	return NULL;
}

/*
 * Reset index fetch. Typically this will release cross index fetch
 * resources held in IndexFetchTableData.
 */
static void
prom_index_fetch_reset(struct IndexFetchTableData *data)
{
	LOG_FUNCTION;
}

/*
 * Release resources and deallocate index fetch.
 */
static void
prom_index_fetch_end(struct IndexFetchTableData *data)
{
	LOG_FUNCTION;
}

/*
 * Fetch tuple at `tid` into `slot`, after doing a visibility test
 * according to `snapshot`. If a tuple was found and passed the visibility
 * test, return true, false otherwise.
 *
 * Note that AMs that do not necessarily update indexes when indexed
 * columns do not change, need to return the current/correct version of
 * the tuple that is visible to the snapshot, even if the tid points to an
 * older version of the tuple.
 *
 * *call_again is false on the first call to index_fetch_tuple for a tid.
 * If there potentially is another tuple matching the tid, *call_again
 * needs be set to true by index_fetch_tuple, signalling to the caller
 * that index_fetch_tuple should be called again for the same tid.
 *
 * *all_dead, if all_dead is not NULL, should be set to true by
 * index_fetch_tuple iff it is guaranteed that no backend needs to see
 * that tuple. Index AMs can use that to avoid returning that tid in
 * future searches.
 */
static	bool
prom_index_fetch_tuple(struct IndexFetchTableData *scan,
					   ItemPointer tid,
					   Snapshot snapshot,
					   TupleTableSlot *slot,
					   bool *call_again, bool *all_dead)
{
	LOG_FUNCTION;
	return false;
}

/*
 * Fetch tuple at `tid` into `slot`, after doing a visibility test
 * according to `snapshot`. If a tuple was found and passed the visibility
 * test, returns true, false otherwise.
 */
static bool
prom_tuple_fetch_row_version(Relation rel,
							 ItemPointer tid,
							 Snapshot snapshot,
							 TupleTableSlot *slot)
{
	LOG_FUNCTION;
	return false;
}

/*
 * Is tid valid for a scan of this relation.
 */
static bool
prom_tuple_tid_valid(TableScanDesc scan,
					 ItemPointer tid)
{
	LOG_FUNCTION;
	return false;
}

/*
 * Return the latest version of the tuple at `tid`, by updating `tid` to
 * point at the newest version.
 */
static void
prom_tuple_get_latest_tid(TableScanDesc scan,
						  ItemPointer tid)
{
	LOG_FUNCTION;
}

/*
b
* Does the tuple in `slot` satisfy `snapshot`?  The slot needs to be of
 * the appropriate type for the AM.
 */
static bool
prom_tuple_satisfies_snapshot(Relation rel,
							  TupleTableSlot *slot,
							  Snapshot snapshot)
{
	LOG_FUNCTION;
	return false;
}

/* see table_compute_xid_horizon_for_tuples() */
static TransactionId
prom_compute_xid_horizon_for_tuples(Relation rel,
							   ItemPointerData *items,
							   int nitems)
{
	LOG_FUNCTION;
	return InvalidTransactionId;
}

/* see table_tuple_insert() for reference about parameters */
static void
prom_tuple_insert(Relation rel, TupleTableSlot *slot,
				  CommandId cid, int options,
				  struct BulkInsertStateData *bistate)
{
	LOG_FUNCTION;
}

/* see table_tuple_insert_speculative() for reference about parameters */
static void
prom_tuple_insert_speculative(Relation rel,
							  TupleTableSlot *slot,
							  CommandId cid,
							  int options,
							  struct BulkInsertStateData *bistate,
							  uint32 specToken)
{
	LOG_FUNCTION;
}

/* see table_tuple_complete_speculative() for reference about parameters */
static void
prom_tuple_complete_speculative(Relation rel,
								TupleTableSlot *slot,
								uint32 specToken,
								bool succeeded)
{
	LOG_FUNCTION;
}

/* see table_multi_insert() for reference about parameters */
static void
prom_multi_insert(Relation rel, TupleTableSlot **slots, int nslots,
				  CommandId cid, int options, struct BulkInsertStateData *bistate)
{
	LOG_FUNCTION;
}

/* see table_tuple_delete() for reference about parameters */
static TM_Result
prom_tuple_delete(Relation rel,
				  ItemPointer tid,
				  CommandId cid,
				  Snapshot snapshot,
				  Snapshot crosscheck,
				  bool wait,
				  TM_FailureData *tmfd,
				  bool changingPart)
{
	LOG_FUNCTION;
	return TM_Ok;
}

/* see table_tuple_update() for reference about parameters */
static TM_Result
prom_tuple_update(Relation rel,
			 ItemPointer otid,
			 TupleTableSlot *slot,
			 CommandId cid,
			 Snapshot snapshot,
			 Snapshot crosscheck,
			 bool wait,
			 TM_FailureData *tmfd,
			 LockTupleMode *lockmode,
			 bool *update_indexes)
{
	LOG_FUNCTION;
	return TM_Ok;

}

/* see table_tuple_lock() for reference about parameters */
static TM_Result
prom_tuple_lock(Relation rel,
				ItemPointer tid,
				Snapshot snapshot,
				TupleTableSlot *slot,
				CommandId cid,
				LockTupleMode mode,
				LockWaitPolicy wait_policy,
				uint8 flags,
				TM_FailureData *tmfd)
{
	LOG_FUNCTION;
	return TM_Ok;
}

/*
 * Perform operations necessary to complete insertions made via
 * tuple_insert and multi_insert with a BulkInsertState specified. This
 * may for example be used to flush the relation, when the
 * TABLE_INSERT_SKIP_WAL option was used.
 *
 * Typically callers of tuple_insert and multi_insert will just pass all
 * the flags that apply to them, and each AM has to decide which of them
 * make sense for it, and then only take actions in finish_bulk_insert for
 * those flags, and ignore others.
 *
 * Optional callback.
 */
static void
prom_finish_bulk_insert(Relation rel, int options)
{
	LOG_FUNCTION;
}

static Oid
get_type_by_name(Oid typnamespace, const char *typname)
{
	Relation rel;
	HeapTuple tup;
	Oid typid = InvalidOid;

	rel = table_open(TypeRelationId, AccessShareLock);

	tup = SearchSysCacheCopy2(TYPENAMENSP,
							  CStringGetDatum(typname),
							  ObjectIdGetDatum(typnamespace));

	if (HeapTupleIsValid(tup))
	{
		Form_pg_type form = (Form_pg_type) GETSTRUCT(tup);

		typid = form->oid;
	}

	table_close(rel, AccessShareLock);

	return typid;
}

/* ------------------------------------------------------------------------
 * DDL related functionality.
 * ------------------------------------------------------------------------
 */

/*
 * This callback needs to create a new relation filenode for `rel`, with
 * appropriate durability behaviour for `persistence`.
 *
 * Note that only the subset of the relcache filled by
 * RelationBuildLocalRelation() can be relied upon and that the relation's
 * catalog entries will either not yet exist (new relation), or will still
 * reference the old relfilenode.
 *
 * As output *freezeXid, *minmulti must be set to the values appropriate
 * for pg_class.{relfrozenxid, relminmxid}. For AMs that don't need those
 * fields to be filled they can be set to InvalidTransactionId and
 * InvalidMultiXactId, respectively.
 *
 * See also table_relation_set_new_filenode().
 */
static void
prom_relation_set_new_filenode(Relation rel,
							   const RelFileNode *newrnode,
							   char persistence,
							   TransactionId *freezeXid,
							   MultiXactId *minmulti)
{
	TupleDesc desc = rel->rd_att;
	Oid extnamespace = get_namespace_oid("public", false);
	Oid prom_sample_typid = get_type_by_name(extnamespace, "prom_sample");

	if (desc->natts != 1 || desc->attrs[0].atttypid != prom_sample_typid)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_TABLE_DEFINITION),
				 (errmsg("invalid table definition for prometheus storage"),
				  errhint("A table using prometheus storage must have a single column "
						  "of the prom_sample type."))));



	/*
	 * Initialize to the minimum XID that could put tuples in the table. We
	 * know that no xacts older than RecentXmin are still running, so that
	 * will do.
	 */
	*freezeXid = InvalidTransactionId;// FirstNormalTransactionId;

	/*
	 * Similarly, initialize the minimum Multixact to the first value that
	 * could possibly be stored in tuples in the table.  Running transactions
	 * could reuse values from their local cache, so we are careful to
	 * consider all currently running multis.
	 *
	 * XXX this could be refined further, but is it worth the hassle?
	 */
	*minmulti = InvalidMultiXactId; // GetOldestMultiXactId();

	LOG_FUNCTION_LEVEL(NOTICE);
}

/*
 * This callback needs to remove all contents from `rel`'s current
 * relfilenode. No provisions for transactional behaviour need to be made.
 * Often this can be implemented by truncating the underlying storage to
 * its minimal size.
 *
 * See also table_relation_nontransactional_truncate().
 */
static void
prom_relation_nontransactional_truncate(Relation rel)
{
	LOG_FUNCTION;
}

/*
 * See table_relation_copy_data().
 *
 * This can typically be implemented by directly copying the underlying
 * storage, unless it contains references to the tablespace internally.
 */
static void
prom_relation_copy_data(Relation rel,
						const RelFileNode *newrnode)
{
	LOG_FUNCTION;
}

/* See table_relation_copy_for_cluster() */
static void
prom_relation_copy_for_cluster(Relation NewTable,
							   Relation OldTable,
							   Relation OldIndex,
							   bool use_sort,
							   TransactionId OldestXmin,
							   TransactionId *xid_cutoff,
							   MultiXactId *multi_cutoff,
							   double *num_tuples,
							   double *tups_vacuumed,
							   double *tups_recently_dead)
{
	LOG_FUNCTION;
}

/*
 * React to VACUUM command on the relation. The VACUUM can be
 * triggered by a user or by autovacuum. The specific actions
 * performed by the AM will depend heavily on the individual AM.
 *
 * On entry a transaction is already established, and the relation is
 * locked with a ShareUpdateExclusive lock.
 *
 * Note that neither VACUUM FULL (and CLUSTER), nor ANALYZE go through
 * this routine, even if (for ANALYZE) it is part of the same VACUUM
 * command.
 *
 * There probably, in the future, needs to be a separate callback to
 * integrate with autovacuum's scheduling.
 */
static void
prom_relation_vacuum(Relation onerel,
					 struct VacuumParams *params,
					 BufferAccessStrategy bstrategy)
{
	LOG_FUNCTION;
}

/*
 * Prepare to analyze block `blockno` of `scan`. The scan has been started
 * with table_beginscan_analyze().  See also
 * table_scan_analyze_next_block().
 *
 * The callback may acquire resources like locks that are held until
 * table_scan_analyze_next_tuple() returns false. It e.g. can make sense
 * to hold a lock until all tuples on a block have been analyzed by
 * scan_analyze_next_tuple.
 *
 * The callback can return false if the block is not suitable for
 * sampling, e.g. because it's a metapage that could never contain tuples.
 *
 * XXX: This obviously is primarily suited for block-based AMs. It's not
 * clear what a good interface for non block based AMs would be, so there
 * isn't one yet.
 */
static bool
prom_scan_analyze_next_block(TableScanDesc scan,
							 BlockNumber blockno,
							 BufferAccessStrategy bstrategy)
{
	LOG_FUNCTION;
	return false;
}

/*
 * See table_scan_analyze_next_tuple().
 *
 * Not every AM might have a meaningful concept of dead rows, in which
 * case it's OK to not increment *deadrows - but note that that may
 * influence autovacuum scheduling (see comment for relation_vacuum
 * callback).
 */
static bool
prom_scan_analyze_next_tuple(TableScanDesc scan,
							 TransactionId OldestXmin,
							 double *liverows,
							 double *deadrows,
							 TupleTableSlot *slot)
{
	LOG_FUNCTION;
	return false;
}

	/* see table_index_build_range_scan for reference about parameters */
static double
prom_index_build_range_scan(Relation table_rel,
							Relation index_rel,
							struct IndexInfo *index_info,
							bool allow_sync,
							bool anyvisible,
							bool progress,
							BlockNumber start_blockno,
							BlockNumber numblocks,
							IndexBuildCallback callback,
							void *callback_state,
							TableScanDesc scan)
{
	LOG_FUNCTION;
	return 0.0;
}

/* see table_index_validate_scan for reference about parameters */
static void
prom_index_validate_scan(Relation table_rel,
						 Relation index_rel,
						 struct IndexInfo *index_info,
						 Snapshot snapshot,
						 struct ValidateIndexState *state)
{
	LOG_FUNCTION;
}


/* ------------------------------------------------------------------------
 * Miscellaneous functions.
 * ------------------------------------------------------------------------
 */

/*
 * See table_relation_size().
 *
 * Note that currently a few callers use the MAIN_FORKNUM size to figure
 * out the range of potentially interesting blocks (brin, analyze). It's
 * probable that we'll need to revise the interface for those at some
 * point.
 */
static uint64
prom_relation_size(Relation rel, ForkNumber forkNumber)
{
	LOG_FUNCTION;
	return 0;
}


/*
 * This callback should return true if the relation requires a TOAST table
 * and false if it does not.  It may wish to examine the relation's tuple
 * descriptor before making a decision, but if it uses some other method
 * of storing large values (or if it does not support them) it can simply
 * return false.
 */
static bool
prom_relation_needs_toast_table(Relation rel)
{
	LOG_FUNCTION_LEVEL(NOTICE);
	return false;
}


/* ------------------------------------------------------------------------
 * Planner related functions.
 * ------------------------------------------------------------------------
 */

/*
 * See table_relation_estimate_size().
 *
 * While block oriented, it shouldn't be too hard for an AM that doesn't
 * internally use blocks to convert into a usable representation.
 *
 * This differs from the relation_size callback by returning size
 * estimates (both relation size and tuple count) for planning purposes,
 * rather than returning a currently correct estimate.
 */
static void
prom_relation_estimate_size(Relation rel, int32 *attr_widths,
							BlockNumber *pages, double *tuples,
							double *allvisfrac)
{
	LOG_FUNCTION_LEVEL(NOTICE);
	*pages = 1;
	*attr_widths = 3;
	*tuples = 1000;
	*allvisfrac = 0.9;
}


/* ------------------------------------------------------------------------
 * Executor related functions.
 * ------------------------------------------------------------------------
 */

#if 0
/*
 * Prepare to fetch / check / return tuples from `tbmres->blockno` as part
 * of a bitmap table scan. `scan` was started via table_beginscan_bm().
 * Return false if there are no tuples to be found on the page, true
 * otherwise.
 *
 * This will typically read and pin the target block, and do the necessary
 * work to allow scan_bitmap_next_tuple() to return tuples (e.g. it might
 * make sense to perform tuple visibility checks at this time). For some
 * AMs it will make more sense to do all the work referencing `tbmres`
 * contents here, for others it might be better to defer more work to
 * scan_bitmap_next_tuple.
 *
 * If `tbmres->blockno` is -1, this is a lossy scan and all visible tuples
 * on the page have to be returned, otherwise the tuples at offsets in
 * `tbmres->offsets` need to be returned.
 *
 * XXX: Currently this may only be implemented if the AM uses md.c as its
 * storage manager, and uses ItemPointer->ip_blkid in a manner that maps
 * blockids directly to the underlying storage. nodeBitmapHeapscan.c
 * performs prefetching directly using that interface.  This probably
 * needs to be rectified at a later point.
 *
 * XXX: Currently this may only be implemented if the AM uses the
 * visibilitymap, as nodeBitmapHeapscan.c unconditionally accesses it to
 * perform prefetching.  This probably needs to be rectified at a later
 * point.
 *
 * Optional callback, but either both scan_bitmap_next_block and
 * scan_bitmap_next_tuple need to exist, or neither.
 */
static bool
prom_scan_bitmap_next_block(TableScanDesc scan,
							struct TBMIterateResult *tbmres)
{
	LOG_FUNCTION;
	return false;
}

/*
 * Fetch the next tuple of a bitmap table scan into `slot` and return true
 * if a visible tuple was found, false otherwise.
 *
 * For some AMs it will make more sense to do all the work referencing
 * `tbmres` contents in scan_bitmap_next_block, for others it might be
 * better to defer more work to this callback.
 *
 * Optional callback, but either both scan_bitmap_next_block and
 * scan_bitmap_next_tuple need to exist, or neither.
 */
static bool
prom_scan_bitmap_next_tuple(TableScanDesc scan,
							struct TBMIterateResult *tbmres,
							TupleTableSlot *slot)
{
	LOG_FUNCTION;
	return false;
}
#endif

/*
 * Prepare to fetch tuples from the next block in a sample scan. Return
 * false if the sample scan is finished, true otherwise. `scan` was
 * started via table_beginscan_sampling().
 *
 * Typically this will first determine the target block by calling the
 * TsmRoutine's NextSampleBlock() callback if not NULL, or alternatively
 * perform a sequential scan over all blocks.  The determined block is
 * then typically read and pinned.
 *
 * As the TsmRoutine interface is block based, a block needs to be passed
 * to NextSampleBlock(). If that's not appropriate for an AM, it
 * internally needs to perform mapping between the internal and a block
 * based representation.
 *
 * Note that it's not acceptable to hold deadlock prone resources such as
 * lwlocks until scan_sample_next_tuple() has exhausted the tuples on the
 * block - the tuple is likely to be returned to an upper query node, and
 * the next call could be off a long while. Holding buffer pins and such
 * is obviously OK.
 *
 * Currently it is required to implement this interface, as there's no
 * alternative way (contrary e.g. to bitmap scans) to implement sample
 * scans. If infeasible to implement, the AM may raise an error.
 */
static bool
prom_scan_sample_next_block(TableScanDesc scan,
							struct SampleScanState *scanstate)
{
	LOG_FUNCTION;
	return false;
}

/*
 * This callback, only called after scan_sample_next_block has returned
 * true, should determine the next tuple to be returned from the selected
 * block using the TsmRoutine's NextSampleTuple() callback.
 *
 * The callback needs to perform visibility checks, and only return
 * visible tuples. That obviously can mean calling NextSampleTuple()
 * multiple times.
 *
 * The TsmRoutine interface assumes that there's a maximum offset on a
 * given page, so if that doesn't apply to an AM, it needs to emulate that
 * assumption somehow.
 */
static bool
prom_scan_sample_next_tuple(TableScanDesc scan,
							struct SampleScanState *scanstate,
							TupleTableSlot *slot)
{
	LOG_FUNCTION;
	return false;
}

/*
		Assert(routine->scan_begin != NULL);
		Assert(routine->scan_end != NULL);
		Assert(routine->scan_rescan != NULL);
		Assert(routine->scan_getnextslot != NULL);

		Assert(routine->parallelscan_estimate != NULL);
		Assert(routine->parallelscan_initialize != NULL);
		Assert(routine->parallelscan_reinitialize != NULL);

		Assert(routine->index_fetch_begin != NULL);
		Assert(routine->index_fetch_reset != NULL);
		Assert(routine->index_fetch_end != NULL);
		Assert(routine->index_fetch_tuple != NULL);

		Assert(routine->tuple_fetch_row_version != NULL);
		Assert(routine->tuple_tid_valid != NULL);
		Assert(routine->tuple_get_latest_tid != NULL);
		Assert(routine->tuple_satisfies_snapshot != NULL);
		Assert(routine->compute_xid_horizon_for_tuples != NULL);

		Assert(routine->tuple_insert != NULL);
		Assert(routine->tuple_insert_speculative != NULL);
		Assert(routine->tuple_complete_speculative != NULL);

		Assert(routine->multi_insert != NULL);
		Assert(routine->tuple_delete != NULL);
		Assert(routine->tuple_update != NULL);
		Assert(routine->tuple_lock != NULL);

		Assert(routine->relation_set_new_filenode != NULL);
		Assert(routine->relation_nontransactional_truncate != NULL);
		Assert(routine->relation_copy_data != NULL);
		Assert(routine->relation_copy_for_cluster != NULL);
		Assert(routine->relation_vacuum != NULL);
		Assert(routine->scan_analyze_next_block != NULL);
		Assert(routine->scan_analyze_next_tuple != NULL);
		Assert(routine->index_build_range_scan != NULL);
		Assert(routine->index_validate_scan != NULL);

		Assert(routine->relation_size != NULL);
		Assert(routine->relation_needs_toast_table != NULL);

		Assert(routine->relation_estimate_size != NULL);

		// optional, but one callback implies presence of the other
		Assert((routine->scan_bitmap_next_block == NULL) ==
				   (routine->scan_bitmap_next_tuple == NULL));
		Assert(routine->scan_sample_next_block != NULL);
		Assert(routine->scan_sample_next_tuple != NULL);

*/

static const TableAmRoutine prom_routines = {
	.type = T_TableAmRoutine,
	.slot_callbacks = prom_slot_callbacks,
	.scan_begin = prom_scan_begin,
	.scan_end = prom_scan_end,
	.scan_rescan = prom_scan_rescan,
	.scan_getnextslot = prom_scan_getnextslot,
	.parallelscan_estimate = prom_parallelscan_estimate,
	.parallelscan_initialize = prom_parallelscan_initialize,
	.parallelscan_reinitialize = prom_parallelscan_reinitialize,
	.index_fetch_begin = prom_index_fetch_begin,
	.index_fetch_reset = prom_index_fetch_reset,
	.index_fetch_end = prom_index_fetch_end,
	.index_fetch_tuple = prom_index_fetch_tuple,
	.tuple_fetch_row_version = prom_tuple_fetch_row_version,
	.tuple_tid_valid = prom_tuple_tid_valid,
	.tuple_get_latest_tid = prom_tuple_get_latest_tid,
	.tuple_satisfies_snapshot = prom_tuple_satisfies_snapshot,
	.compute_xid_horizon_for_tuples = prom_compute_xid_horizon_for_tuples,
	.tuple_insert = prom_tuple_insert,
	.tuple_insert_speculative = prom_tuple_insert_speculative,
	.tuple_complete_speculative = prom_tuple_complete_speculative,
	.multi_insert = prom_multi_insert,
	.tuple_delete = prom_tuple_delete,
	.tuple_update = prom_tuple_update,
	.tuple_lock = prom_tuple_lock,
	.finish_bulk_insert = prom_finish_bulk_insert,
	.relation_set_new_filenode = prom_relation_set_new_filenode,
	.relation_nontransactional_truncate = prom_relation_nontransactional_truncate,
	.relation_copy_data = prom_relation_copy_data,
	.relation_copy_for_cluster = prom_relation_copy_for_cluster,
	.relation_vacuum = prom_relation_vacuum,
	.scan_analyze_next_block = prom_scan_analyze_next_block,
	.scan_analyze_next_tuple = prom_scan_analyze_next_tuple,
	.index_build_range_scan = prom_index_build_range_scan,
	.index_validate_scan = prom_index_validate_scan,
	.relation_size = prom_relation_size,
	.relation_needs_toast_table = prom_relation_needs_toast_table,
	.relation_estimate_size = prom_relation_estimate_size,
	.scan_sample_next_block = prom_scan_sample_next_block,
	.scan_sample_next_tuple = prom_scan_sample_next_tuple,
};

PG_FUNCTION_INFO_V1(prom_handler);

Datum
prom_handler(PG_FUNCTION_ARGS)
{
	PG_RETURN_POINTER(&prom_routines);
}

/* validation routines for strings */
static void
validate_prometheus_storage_relopt(const char *value)
{
	LOG_FUNCTION_LEVEL(NOTICE);
}

void _PG_init(void);
void _PG_fini(void);

void
_PG_init(void) {

	//add_string_reloption(RELOPT_KIND_HEAP, "prometheus_storage_path", "Path to prometheus storage", NULL, validate_prometheus_storage_relopt);
}


void
_PG_fini(void)
{

}
