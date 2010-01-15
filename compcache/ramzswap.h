/*
 * Compressed RAM based swap device
 *
 * Copyright (C) 2008, 2009  Nitin Gupta
 *
 * This code is released using a dual license strategy: BSD/GPL
 * You can choose the licence that better fits your requirements.
 *
 * Released under the terms of 3-clause BSD License
 * Released under the terms of GNU General Public License Version 2.0
 *
 * Project home: http://compcache.googlecode.com
 */

#ifndef _RAMZSWAP_H_
#define _RAMZSWAP_H_

#include "ramzswap_ioctl.h"
#include "sub-projects/allocators/xvmalloc-kmod/xvmalloc.h"

/*
 * Some arbitrary value. This is just to catch
 * invalid value for NUM_DEVICES module parameter.
 */
#define MAX_NUM_DEVICES 32

/*
 * Stored at beginning of each compressed object.
 *
 * It stores back-reference to table entry which points to this
 * object. This is required to support memory defragmentation or
 * migrating compressed pages to backing swap disk.
 */
struct zobj_header {
#if 0
	u32 table_idx;
#endif
};

/*-- Configurable parameters */

/* Default ramzswap disk size: 25% of total RAM */
#define DEFAULT_DISKSIZE_PERC_RAM	25
#define DEFAULT_MEMLIMIT_PERC_RAM	15

/*
 * Max compressed page size when backing device is provided.
 * Pages that compress to size greater than this are sent to
 * physical swap disk.
 */
#define MAX_CPAGE_SIZE_BDEV	(PAGE_SIZE / 2)

/*
 * Max compressed page size when there is no backing dev.
 * Pages that compress to size greater than this are stored
 * uncompressed in memory.
 */
#define MAX_CPAGE_SIZE_NOBDEV	(PAGE_SIZE / 4 * 3)

/*
 * NOTE: MAX_CPAGE_SIZE_{BDEV,NOBDEV} sizes must be
 * less than or equal to:
 *   XV_MAX_ALLOC_SIZE - sizeof(struct zobj_header)
 * since otherwise xvMalloc would always return failure.
 */

/*-- End of configurable params */

#define SECTOR_SHIFT		9
#define SECTOR_SIZE		(1 << SECTOR_SHIFT)
#define SECTORS_PER_PAGE_SHIFT	(PAGE_SHIFT - SECTOR_SHIFT)
#define SECTORS_PER_PAGE	(1 << SECTORS_PER_PAGE_SHIFT)

/* Message prefix */
#define C "ramzswap: "

/* Debugging and Stats */
#define NOP	do { } while (0)

#if defined(CONFIG_BLK_DEV_RAMZSWAP_STATS)
#define STATS
#endif

#if defined(STATS)
#define stat_inc(stat)			((stat)++)
#define stat_dec(stat)			((stat)--)
#define stat_inc_if_less(stat, val1, val2) \
				((stat) += ((val1) < (val2) ? 1 : 0))
#define stat_dec_if_less(stat, val1, val2) \
				((stat) -= ((val1) < (val2) ? 1 : 0))
#else	/* STATS */
#define stat_inc(x)			NOP
#define stat_dec(x)			NOP
#define stat_inc_if_less(x, v1, v2)	NOP
#define stat_dec_if_less(x, v1, v2)	NOP
#endif	/* STATS */

/* Flags for ramzswap pages (table[page_no].flags) */
enum rzs_pageflags {
	/* Page is stored uncompressed */
	RZS_UNCOMPRESSED,

	/* Page consists entirely of zeros */
	RZS_ZERO,

	__NR_RZS_PAGEFLAGS,
};

/*-- Data structures */

/* Indexed by page no. */
struct table {
	u32 pagenum;
	u16 offset;
	u8 count;	/* object ref count (not yet used) */
	u8 flags;
};

struct ramzswap_backing_extent {
	u32 phy_pagenum;
	u32 num_pages;
};

struct ramzswap_stats {
	/* basic stats */
	size_t compr_size;	/* compressed size of pages stored -
				 * needed to enforce memlimit */
	/* more stats */
#if defined(STATS)
	u64 num_reads;		/* failed + successful */
	u64 num_writes;		/* --do-- */
	u64 failed_reads;	/* can happen when memory is too low */
	u64 failed_writes;	/* should NEVER! happen */
	u64 invalid_io;		/* non-swap I/O requests */
	u64 notify_free;	/* no. of pages freed by swap free callback */
	u64 pages_discard;	/* no. of pages freed by discard callback */
	u32 pages_zero;		/* no. of zero filled pages */
	u32 pages_stored;	/* no. of pages currently stored */
	u32 good_compress;	/* % of pages with compression ratio<=50% */
	u32 pages_expand;	/* % of incompressible pages */
	u64 bdev_num_reads;	/* no. of reads on backing dev */
	u64 bdev_num_writes;	/* no. of writes on backing dev */
#endif
};

struct ramzswap {
	struct xv_pool *mem_pool;
	void *compress_workmem;
	void *compress_buffer;
	struct table *table;
	struct mutex lock;
	struct request_queue *queue;
	struct gendisk *disk;
	int init_done;
	int init_notify_callback;
	/*
	 * This is limit on compressed data size (stats.compr_size)
	 * Its applicable only when backing swap device is present.
	 */
	size_t memlimit;	/* bytes */
	/*
	 * This is limit on amount of *uncompressed* worth of data
	 * we can hold. When backing swap device is provided, it is
	 * set equal to device size.
	 */
	size_t disksize;	/* bytes */

	struct ramzswap_stats stats;

	/* backing swap device info */
	struct ramzswap_backing_extent *curr_extent;
	struct list_head backing_swap_extent_list;
	unsigned long num_extents;
	char backing_swap_name[MAX_SWAP_NAME_LEN];
	struct block_device *backing_swap;
	struct file *swap_file;
};

/*-- */
	
#endif
