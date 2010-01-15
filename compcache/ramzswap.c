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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bitops.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>
#include <linux/device.h>
#include <linux/genhd.h>
#include <linux/highmem.h>
#include <linux/lzo.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/vmalloc.h>
#include <linux/version.h>

#include "compat.h"
#include "ramzswap.h"

/* Globals */
static int RAMZSWAP_MAJOR;
static struct ramzswap *DEVICES;

/*
 * Pages that compress to larger than this size are
 * forwarded to backing swap, if present or stored
 * uncompressed in memory otherwise.
 */
static unsigned int MAX_CPAGE_SIZE;

/* Module params (documentation at end) */
static unsigned long NUM_DEVICES;

/* Function declarations */
static int __init ramzswap_init(void);
static int ramzswap_ioctl(struct block_device *, fmode_t, unsigned, unsigned long);
static int setup_swap_header(struct ramzswap *, union swap_header *);
static void ramzswap_set_memlimit(struct ramzswap *, size_t);
static void ramzswap_set_disksize(struct ramzswap *, size_t);
static void reset_device(struct ramzswap *rzs);

static struct block_device_operations ramzswap_devops = {
	.ioctl = ramzswap_ioctl,
	.owner = THIS_MODULE,
};

static int test_flag(struct ramzswap *rzs, u32 index, enum rzs_pageflags flag)
{
	return rzs->table[index].flags & BIT(flag);
}

static void set_flag(struct ramzswap *rzs, u32 index, enum rzs_pageflags flag)
{
	rzs->table[index].flags |= BIT(flag);
}

static void clear_flag(struct ramzswap *rzs, u32 index,
					enum rzs_pageflags flag)
{
	rzs->table[index].flags &= ~BIT(flag);
}

static int page_zero_filled(void *ptr)
{
	u32 pos;
	u64 *page;

	page = (u64 *)ptr;

	for (pos = 0; pos != PAGE_SIZE / sizeof(*page); pos++) {
		if (page[pos])
			return 0;
	}

	return 1;
}

/*
 * Given <pagenum, offset> pair, provide a dereferencable pointer.
 */
static void *get_ptr_atomic(u32 pagenum, u16 offset, enum km_type type)
{
	unsigned char *page;

	page = kmap_atomic(pfn_to_page(pagenum), type);
	return page + offset;
}

static void put_ptr_atomic(void *ptr, enum km_type type)
{
	kunmap_atomic(ptr, type);
}

static void ramzswap_flush_dcache_page(struct page *page)
{
#ifdef CONFIG_ARM
	int flag = 0;
	/*
	 * Ugly hack to get flush_dcache_page() work on ARM.
	 * page_mapping(page) == NULL after clearing this swap cache flag.
	 * Without clearing this flag, flush_dcache_page() will simply set
	 * "PG_dcache_dirty" bit and return.
	 */
	if (PageSwapCache(page)) {
		flag = 1;
		ClearPageSwapCache(page);
	}
#endif
	flush_dcache_page(page);
#ifdef CONFIG_ARM
	if (flag)
		SetPageSwapCache(page);
#endif
}

void ramzswap_ioctl_get_stats(struct ramzswap *rzs,
			struct ramzswap_ioctl_stats *s)
{
	strncpy(s->backing_swap_name, rzs->backing_swap_name,
		 			MAX_SWAP_NAME_LEN - 1);
	s->backing_swap_name[MAX_SWAP_NAME_LEN - 1] = '\0';

	s->disksize = rzs->disksize;
	s->memlimit = rzs->memlimit;

#if defined(STATS)
	{
	struct ramzswap_stats *rs = &rzs->stats;
	size_t succ_writes, mem_used;
	unsigned int good_compress_perc = 0, no_compress_perc = 0;

	mem_used = xv_get_total_size_bytes(rzs->mem_pool)
			+ (rs->pages_expand << PAGE_SHIFT);
	succ_writes = rs->num_writes - rs->failed_writes;

	if (succ_writes && rs->pages_stored) {
		good_compress_perc = rs->good_compress * 100
					/ rs->pages_stored;
		no_compress_perc = rs->pages_expand * 100
					/ rs->pages_stored;
	}
	
	s->num_reads = rs->num_reads;
	s->num_writes = rs->num_writes;
	s->failed_reads = rs->failed_reads;
	s->failed_writes = rs->failed_writes;
	s->invalid_io = rs->invalid_io;
	s->notify_free = rs->notify_free;
	s->pages_discard = rs->pages_discard;
	s->pages_zero = rs->pages_zero;

	s->good_compress_pct = good_compress_perc;
	s->pages_expand_pct = no_compress_perc;


	s->pages_stored = rs->pages_stored;
	s->pages_used = mem_used >> PAGE_SHIFT;
	s->orig_data_size = rs->pages_stored << PAGE_SHIFT;
	s->compr_data_size = rs->compr_size;
	s->mem_used_total = mem_used;
	
	s->bdev_num_reads = rs->bdev_num_reads;
	s->bdev_num_writes = rs->bdev_num_writes;
	}
#endif /* STATS */
}

static int add_backing_swap_extent(struct ramzswap *rzs,
				unsigned long phy_pagenum,
				unsigned long num_pages)
{
	unsigned int idx;
	struct list_head *head;
	struct page *curr_page, *new_page;
	unsigned int extents_per_page = PAGE_SIZE /
				sizeof(struct ramzswap_backing_extent);

	idx = rzs->num_extents % extents_per_page;
	if (!idx) {
		new_page = alloc_page(__GFP_ZERO);
		if (!new_page)
			return -ENOMEM;

		if (rzs->num_extents) {
			curr_page = virt_to_page(rzs->curr_extent);
			head = &curr_page->lru;
		} else {
			head = &rzs->backing_swap_extent_list;
		}

		list_add(&new_page->lru, head);
		rzs->curr_extent = page_address(new_page);
	}

	rzs->curr_extent->phy_pagenum = phy_pagenum;
	rzs->curr_extent->num_pages = num_pages;

	pr_debug(C "add_extent: idx=%u, phy_pgnum=%lu, num_pgs=%lu, "
		"pg_last=%lu, curr_ext=%p\n", idx, phy_pagenum,	num_pages,
		phy_pagenum + num_pages - 1, rzs->curr_extent);
	
	if (idx != extents_per_page - 1)
		rzs->curr_extent++;

	return 0;
}

static int setup_backing_swap_extents(struct ramzswap *rzs,
				struct inode *inode, unsigned long *num_pages)
{
	int ret = 0;
	unsigned blkbits;
	unsigned blocks_per_page;
	unsigned long contig_pages = 0, total_pages = 0;
	unsigned long pagenum = 0, prev_pagenum = 0;
	sector_t probe_block = 0;
	sector_t last_block;

	blkbits = inode->i_blkbits;
	blocks_per_page = PAGE_SIZE >> blkbits;

	last_block = i_size_read(inode) >> blkbits;
	while (probe_block + blocks_per_page <= last_block) {
		unsigned block_in_page;
		sector_t first_block;

		first_block = bmap(inode, probe_block);
		if (first_block == 0)
			goto bad_bmap;

		/* It must be PAGE_SIZE aligned on-disk */
		if (first_block & (blocks_per_page - 1)) {
			probe_block++;
			goto probe_next;
		}

		/* All blocks within this page must be contiguous on disk */
		for (block_in_page = 1; block_in_page < blocks_per_page;
					block_in_page++) {
			sector_t block;

			block = bmap(inode, probe_block + block_in_page);
			if (block == 0)
				goto bad_bmap;
			if (block != first_block + block_in_page) {
				/* Discontiguity */
				probe_block++;
				goto probe_next;
			}
		}

		/* We found a PAGE_SIZE-length, PAGE_SIZE-aligned run of blocks */
		pagenum = first_block >> (PAGE_SHIFT - blkbits);

		if (total_pages && (pagenum != prev_pagenum + 1)) {
			ret = add_backing_swap_extent(rzs, prev_pagenum -
					(contig_pages - 1), contig_pages);
			if (ret < 0)
				goto out;
			rzs->num_extents++;
			contig_pages = 0;
		}
		total_pages++;
		contig_pages++;
		prev_pagenum = pagenum;
		probe_block += blocks_per_page;

probe_next:
		continue;
	}

	if (contig_pages) {
		pr_debug(C "adding last extent: pagenum=%lu, contig_pages=%lu\n",
				pagenum, contig_pages);
		ret = add_backing_swap_extent(rzs,
			prev_pagenum - (contig_pages - 1), contig_pages);
		if (ret < 0)
			goto out;
		rzs->num_extents++;
	}
	if (!rzs->num_extents) {
		pr_err(C "No swap extents found!\n");
		ret = -EINVAL;
	}

	if (!ret) {
		*num_pages = total_pages;
		pr_info(C "Found %lu extents containing %luk\n",
			rzs->num_extents, *num_pages << PAGE_SHIFT);
	}
	goto out;

bad_bmap:
	pr_err(C "Backing swapfile has holes\n");
	ret = -EINVAL;
out:
	while(ret && !list_empty(&rzs->backing_swap_extent_list)) {
		struct page *page;
		struct list_head *entry = rzs->backing_swap_extent_list.next;
		page = list_entry(entry, struct page, lru);
		list_del(entry);
		__free_page(page);
	}
	return ret;
}

static void map_backing_swap_extents(struct ramzswap *rzs)
{
	struct ramzswap_backing_extent *se;
	struct page *table_page, *se_page;
	unsigned long num_pages, num_table_pages, entry;
	unsigned long se_idx, span;
	unsigned entries_per_page = PAGE_SIZE / sizeof(*rzs->table);
	unsigned extents_per_page = PAGE_SIZE / sizeof(*se);

	/* True for block device */
	if (!rzs->num_extents)
		return;

	se_page = list_entry(rzs->backing_swap_extent_list.next,
					struct page, lru);
	se = page_address(se_page);
	span = se->num_pages;
	num_pages = rzs->disksize >> PAGE_SHIFT;
	num_table_pages = DIV_ROUND_UP(num_pages * sizeof(*rzs->table),
							PAGE_SIZE);

	entry = 0;
	se_idx = 0;
	while(num_table_pages--) {
		table_page = vmalloc_to_page(&rzs->table[entry]);
		while (span <= entry) {
			se_idx++;
			if (se_idx == rzs->num_extents)
				BUG();

			if (!(se_idx % extents_per_page)) {
				se_page = list_entry(se_page->lru.next,
						struct page, lru);
				se = page_address(se_page);
			} else
				se++;

			span += se->num_pages;
		}
		table_page->mapping = (struct address_space *)se;
		table_page->private = se->num_pages - (span - entry);
		pr_debug(C "map_table: entry=%lu, span=%lu, map=%p, priv=%lu\n",
			entry, span, table_page->mapping, table_page->private);
		entry += entries_per_page;
	}
}

/*
 * Check if value of backing_swap module param is sane.
 * Claim this device and set ramzswap size equal to
 * size of this block device.
 */
static int setup_backing_swap(struct ramzswap *rzs)
{
	int ret = 0;
	size_t disksize;
	unsigned long num_pages = 0;
	struct inode *inode;
	struct file *swap_file;
	struct address_space *mapping;
	struct block_device *bdev = NULL;

	if (!rzs->backing_swap_name[0]) {
		pr_debug(C "backing_swap param not given\n");
		goto out;
	}

	pr_info(C "Using backing swap device: %s\n", rzs->backing_swap_name);

	swap_file = filp_open(rzs->backing_swap_name,
					O_RDWR | O_LARGEFILE, 0);
	if (IS_ERR(swap_file)) {
		pr_err(C "Error opening backing device: %s\n",
						rzs->backing_swap_name);
		ret = -EINVAL;
		goto out;
	}

	mapping = swap_file->f_mapping;
	inode = mapping->host;

	if (S_ISBLK(inode->i_mode)) {
		bdev = I_BDEV(inode);
		ret = bd_claim(bdev, setup_backing_swap);
		if (ret < 0) {
			bdev = NULL;
			goto bad_param;
		}
		disksize = i_size_read(inode);
	} else if (S_ISREG(inode->i_mode)) {
		bdev = inode->i_sb->s_bdev;
		if (IS_SWAPFILE(inode)) {
			ret = -EBUSY;
			goto bad_param;
		}
		ret = setup_backing_swap_extents(rzs, inode, &num_pages);
		if (ret < 0)
			goto bad_param;
		disksize = num_pages << PAGE_SHIFT;
	} else {
		goto bad_param;
	}

	rzs->swap_file = swap_file;
	rzs->backing_swap = bdev;
	rzs->disksize = disksize;
	BUG_ON(!rzs->disksize);

	return 0;

bad_param:
	if (bdev)
		bd_release(bdev);
	filp_close(swap_file, NULL);

out:
	rzs->backing_swap = NULL;
	return ret;
}

/*
 * Map logical page number 'pagenum' to physical page number
 * on backing swap device. For block device, this is a nop.
 */
u32 map_backing_swap_page(struct ramzswap *rzs, u32 pagenum)
{
	u32 skip_pages, entries_per_page;
	size_t delta, se_offset, skipped;
	struct page *table_page, *se_page;
	struct ramzswap_backing_extent *se;

	if (!rzs->num_extents)
		return pagenum;

	entries_per_page = PAGE_SIZE / sizeof(*rzs->table);

	table_page = vmalloc_to_page(&rzs->table[pagenum]);
	se = (struct ramzswap_backing_extent *)table_page->mapping;
	se_page = virt_to_page(se);

	skip_pages = pagenum - (pagenum / entries_per_page * entries_per_page);
	se_offset = table_page->private + skip_pages;

	if (se_offset < se->num_pages)
		return se->phy_pagenum + se_offset;

	skipped = se->num_pages - table_page->private;
	do {
		struct ramzswap_backing_extent *se_base;
		u32 se_entries_per_page = PAGE_SIZE / sizeof(*se);

		/* Get next swap extent */
		se_base = (struct ramzswap_backing_extent *)
						page_address(se_page);
		if (se - se_base == se_entries_per_page - 1) {
			se_page = list_entry(se_page->lru.next,
						struct page, lru);
			se = page_address(se_page);
		} else {
			se++;
		}
		
		skipped += se->num_pages;
	} while (skipped < skip_pages);
	
	delta = skipped - skip_pages;
	se_offset = se->num_pages - delta;

	return se->phy_pagenum + se_offset;
}

/*
 * Check if request is within bounds and page aligned.
 */
static inline int valid_swap_request(struct ramzswap *rzs, struct bio *bio)
{
	if (unlikely(
		(bio->bi_sector >= (rzs->disksize >> SECTOR_SHIFT)) ||
		(bio->bi_sector & (SECTORS_PER_PAGE - 1)) ||
		(bio->bi_vcnt != 1) ||
		(bio->bi_size != PAGE_SIZE) ||
		(bio->bi_io_vec[0].bv_offset != 0))) {

		return 0;
	}

	/* swap request is valid */
	return 1;
}

static void ramzswap_free_page(struct ramzswap *rzs, size_t index)
{
	u32 clen;
	void *obj;

	u32 pagenum = rzs->table[index].pagenum;
	u32 offset = rzs->table[index].offset;

	if (unlikely(test_flag(rzs, index, RZS_UNCOMPRESSED))) {
		clen = PAGE_SIZE;
		__free_page(pfn_to_page(pagenum));
		clear_flag(rzs, index, RZS_UNCOMPRESSED);
		stat_dec(rzs->stats.pages_expand);
		goto out;
	}

	obj = get_ptr_atomic(pagenum, offset, KM_USER0);
	clen = xv_get_object_size(obj) - sizeof(struct zobj_header);
	put_ptr_atomic(obj, KM_USER0);

	xv_free(rzs->mem_pool, pagenum, offset);
	stat_dec_if_less(rzs->stats.good_compress, clen, PAGE_SIZE / 2 + 1);

out:
	rzs->stats.compr_size -= clen;
	stat_dec(rzs->stats.pages_stored);

	rzs->table[index].pagenum = 0;
	rzs->table[index].offset = 0;
}

#ifdef CONFIG_SWAP_FREE_NOTIFY
/*
 * callback function called when swap_map[offset] == 0
 * i.e page at this swap offset is no longer used
 */
static void ramzswap_free_notify(struct block_device *bdev,
					unsigned long index)
{
	struct ramzswap *rzs = bdev->bd_disk->private_data;

	if (rzs->table[index].pagenum) {
		ramzswap_free_page(rzs, index);
		stat_inc(rzs->stats.notify_free);
	}
}
#endif

static int ramzswap_prepare_discard(struct request_queue *q,
					struct request *req)
{
	return 0;
}

/*
 * Called by main I/O handler function. This helper
 * function handles 'discard' I/O requests which means
 * that  some swap pages are no longer required, so
 * swap device can take needed action -- we free memory
 * allocated for these pages.
 */
static int ramzswap_discard(struct ramzswap *rzs, struct bio *bio)
{
	size_t index, start_page, num_pages;

	start_page = bio->bi_sector >> SECTORS_PER_PAGE_SHIFT;
	num_pages = bio->bi_size >> (SECTOR_SHIFT + SECTORS_PER_PAGE_SHIFT);

	for (index = start_page; index < start_page + num_pages; index++) {
		if (rzs->table[index].pagenum) {
			ramzswap_free_page(rzs, index);
			stat_inc(rzs->stats.pages_discard);
		}
	}

	set_bit(BIO_UPTODATE, &bio->bi_flags);
	bio_endio(bio, 0);
	return 0;
}

static int handle_zero_page(struct bio *bio)
{
	void *user_mem;
	struct page *page = bio->bi_io_vec[0].bv_page;

	user_mem = get_ptr_atomic(page_to_pfn(page), 0, KM_USER0);
	memset(user_mem, 0, PAGE_SIZE);
	put_ptr_atomic(user_mem, KM_USER0);

	ramzswap_flush_dcache_page(page);
	
	set_bit(BIO_UPTODATE, &bio->bi_flags);
	bio_endio(bio, 0);
	return 0;
}

static int handle_uncompressed_page(struct ramzswap *rzs, struct bio *bio)
{
	u32 index;
	struct page *page;
	unsigned char *user_mem, *cmem;

	page = bio->bi_io_vec[0].bv_page;
	index = bio->bi_sector >>SECTORS_PER_PAGE_SHIFT;

	user_mem = get_ptr_atomic(page_to_pfn(page), 0, KM_USER0);
	cmem = get_ptr_atomic(rzs->table[index].pagenum,
			rzs->table[index].offset, KM_USER1);

	memcpy(user_mem, cmem, PAGE_SIZE);
	put_ptr_atomic(user_mem, KM_USER0);
	put_ptr_atomic(cmem, KM_USER1);

	ramzswap_flush_dcache_page(page);
	
	set_bit(BIO_UPTODATE, &bio->bi_flags);
	bio_endio(bio, 0);
	return 0;
}


/*
 * Called when request page is not present in ramzswap.
 * Its either in backing swap device (if present) or
 * this is an attempt to read before any previous write
 * to this location - this happens due to readahead when
 * swap device is read from user-space (e.g. during swapon)
 */
static int handle_ramzswap_fault(struct ramzswap *rzs, struct bio *bio)
{
	/*
	 * Always forward such requests to backing swap
	 * device (if present)
	 */
	if (rzs->backing_swap) {
		u32 pagenum;
		stat_dec(rzs->stats.num_reads);
		stat_inc(rzs->stats.bdev_num_reads);
		bio->bi_bdev = rzs->backing_swap;

		/*
		 * In case backing swap is a file, find the right offset within
		 * the file corresponding to logical position 'index'. For block
		 * device, this is a nop.
		 */
		pagenum = bio->bi_sector >> SECTORS_PER_PAGE_SHIFT;
		bio->bi_sector = map_backing_swap_page(rzs, pagenum)
					<< SECTORS_PER_PAGE_SHIFT;
		return 1;
	}

	/*
	 * Its unlikely event in case backing dev is
	 * not present
	 */
	pr_debug(C "Read before write on swap device: "
		"sector=%lu, size=%u, offset=%u\n",
		(ulong)(bio->bi_sector), bio->bi_size,
		bio->bi_io_vec[0].bv_offset);

	/* Do nothing. Just return success */
	set_bit(BIO_UPTODATE, &bio->bi_flags);
	bio_endio(bio, 0);
	return 0;
}

static int ramzswap_read(struct ramzswap *rzs, struct bio *bio)
{
	int ret;
	u32 index;
	size_t clen;
	struct page *page;
	struct zobj_header *zheader;
	unsigned char *user_mem, *cmem;

	stat_inc(rzs->stats.num_reads);

	page = bio->bi_io_vec[0].bv_page;
	index = bio->bi_sector >> SECTORS_PER_PAGE_SHIFT;

#ifdef CONFIG_SWAP_FREE_NOTIFY
	if (unlikely(!rzs->init_notify_callback) && PageSwapCache(page)) {
		set_swap_free_notify(bio->bi_bdev, ramzswap_free_notify);
		rzs->init_notify_callback = 1;
	}
#endif

	if (test_flag(rzs, index, RZS_ZERO))
		return handle_zero_page(bio);

	/* Requested page is not present in compressed area */
	if (!rzs->table[index].pagenum)
		return handle_ramzswap_fault(rzs, bio);

	/* Page is stored uncompressed since its incompressible */
	if (unlikely(test_flag(rzs, index, RZS_UNCOMPRESSED)))
		return handle_uncompressed_page(rzs, bio);

	user_mem = get_ptr_atomic(page_to_pfn(page), 0, KM_USER0);
	clen = PAGE_SIZE;

	cmem = get_ptr_atomic(rzs->table[index].pagenum,
			rzs->table[index].offset, KM_USER1);

	ret = lzo1x_decompress_safe(
		cmem + sizeof(*zheader),
		xv_get_object_size(cmem) - sizeof(*zheader),
		user_mem, &clen);

	put_ptr_atomic(user_mem, KM_USER0);
	put_ptr_atomic(cmem, KM_USER1);

	/* should NEVER happen */
	if (unlikely(ret != LZO_E_OK)) {
		pr_err(C "Decompression failed! err=%d, page=%u\n",
			ret, index);
		stat_inc(rzs->stats.failed_reads);
		goto out;
	}

	ramzswap_flush_dcache_page(page);

	set_bit(BIO_UPTODATE, &bio->bi_flags);
	bio_endio(bio, 0);
	return 0;

out:
	bio_io_error(bio);
	return 0;
}

static int ramzswap_write(struct ramzswap *rzs, struct bio *bio)
{
	int ret, fwd_write_request = 0;
	u32 offset, index;
	size_t clen;
	struct zobj_header *zheader;
	struct page *page, *page_store;
	unsigned char *user_mem, *cmem, *src;

	stat_inc(rzs->stats.num_writes);

	page = bio->bi_io_vec[0].bv_page;
	index = bio->bi_sector >> SECTORS_PER_PAGE_SHIFT;

	src = rzs->compress_buffer;

	/*
	 * System swaps to same sector again when the stored page
	 * is no longer referenced by any process. So, its now safe
	 * to free the memory that was allocated for this page.
	 */
	if (rzs->table[index].pagenum)
		ramzswap_free_page(rzs, index);

	/*
	 * No memory ia allocated for zero filled pages.
	 * Simply clear zero page flag.
	 */
	if (test_flag(rzs, index, RZS_ZERO)) {
		stat_dec(rzs->stats.pages_zero);
		clear_flag(rzs, index, RZS_ZERO);
	}

	mutex_lock(&rzs->lock);

	user_mem = get_ptr_atomic(page_to_pfn(page), 0, KM_USER0);
	if (page_zero_filled(user_mem)) {
		put_ptr_atomic(user_mem, KM_USER0);
		mutex_unlock(&rzs->lock);
		stat_inc(rzs->stats.pages_zero);
		set_flag(rzs, index, RZS_ZERO);

		set_bit(BIO_UPTODATE, &bio->bi_flags);
		bio_endio(bio, 0);
		return 0;
	}

	if (rzs->backing_swap &&
		(rzs->stats.compr_size > rzs->memlimit - PAGE_SIZE)) {
		put_ptr_atomic(user_mem, KM_USER0);
		mutex_unlock(&rzs->lock);
		fwd_write_request = 1;
		goto out;
	}

	ret = lzo1x_1_compress(user_mem, PAGE_SIZE, src, &clen,
				rzs->compress_workmem);

	put_ptr_atomic(user_mem, KM_USER0);

	if (unlikely(ret != LZO_E_OK)) {
		mutex_unlock(&rzs->lock);
		pr_err(C "Compression failed! err=%d\n", ret);
		stat_inc(rzs->stats.failed_writes);
		goto out;
	}

	/*
	 * Page is incompressible. Forward it to backing swap
	 * if present. Otherwise, store it as-is (uncompressed)
	 * since we do not want to return too many swap write
	 * errors which has side effect of hanging the system.
	 */
	if (unlikely(clen > MAX_CPAGE_SIZE)) {
		if (rzs->backing_swap) {
			mutex_unlock(&rzs->lock);
			fwd_write_request = 1;
			goto out;
		}

		clen = PAGE_SIZE;
		page_store = alloc_page(GFP_NOIO | __GFP_HIGHMEM);
		if (unlikely(!page_store)) {
			mutex_unlock(&rzs->lock);
			pr_info(C "Error allocating memory for incompressible "
				"page: %u\n", index);
			stat_inc(rzs->stats.failed_writes);
			goto out;
		}

		offset = 0;
		set_flag(rzs, index, RZS_UNCOMPRESSED);
		stat_inc(rzs->stats.pages_expand);
		rzs->table[index].pagenum = page_to_pfn(page_store);
		src = get_ptr_atomic(page_to_pfn(page), 0, KM_USER0);
		goto memstore;
	}

	if (xv_malloc(rzs->mem_pool, clen + sizeof(*zheader),
			&rzs->table[index].pagenum, &offset,
			GFP_NOIO | __GFP_HIGHMEM)) {
		mutex_unlock(&rzs->lock);
		pr_info(C "Error allocating memory for compressed "
			"page: %u, size=%zu\n", index, clen);
		stat_inc(rzs->stats.failed_writes);
		if (rzs->backing_swap)
			fwd_write_request = 1;
		goto out;
	}

memstore:
	rzs->table[index].offset = offset;

	cmem = get_ptr_atomic(rzs->table[index].pagenum,
			rzs->table[index].offset, KM_USER1);

#if 0
	/* Back-reference needed for memory defragmentation */
	if (!test_flag(rzs, index, RZS_UNCOMPRESSED)) {
		zheader = (struct zobj_header *)cmem;
		zheader->table_idx = index;
		cmem += sizeof(*zheader);
	}
#endif

	memcpy(cmem, src, clen);

	put_ptr_atomic(cmem, KM_USER1);
	if (unlikely(test_flag(rzs, index, RZS_UNCOMPRESSED)))
		put_ptr_atomic(src, KM_USER0);

	/* Update stats */
	rzs->stats.compr_size += clen;
	stat_inc(rzs->stats.pages_stored);
	stat_inc_if_less(rzs->stats.good_compress, clen, PAGE_SIZE / 2 + 1);

	mutex_unlock(&rzs->lock);

	set_bit(BIO_UPTODATE, &bio->bi_flags);
	bio_endio(bio, 0);
	return 0;

out:
	if (fwd_write_request) {
		stat_inc(rzs->stats.bdev_num_writes);
		bio->bi_bdev = rzs->backing_swap;
#if 0
		/*
		 * TODO: We currently have linear mapping of ramzswap and
		 * backing swap sectors. This is not desired since we want
		 * to optimize writes to backing swap to minimize disk seeks
		 * or have effective wear leveling (for SSDs). Also, a non-linear
		 * mapping is required to implement compressed on-disk swapping
		 */
		 bio->bi_sector = get_backing_swap_page()
		 			<< SECTORS_PER_PAGE_SHIFT;
#endif
		/*
		 * In case backing swap is a file, find the right offset within
		 * the file corresponding to logical position 'index'. For block
		 * device, this is a nop.
		 */
		bio->bi_sector = map_backing_swap_page(rzs, index)
					<< SECTORS_PER_PAGE_SHIFT;
		return 1;
	}

	bio_io_error(bio);
	return 0;
}

/*
 * Handler function for all ramzswap I/O requests.
 */
static int ramzswap_make_request(struct request_queue *queue, struct bio *bio)
{
	int ret = 0;
	struct ramzswap *rzs = queue->queuedata;

	if (unlikely(!rzs->init_done)) {
		bio_io_error(bio);
		return 0;
	}

	if (bio_discard(bio))
		return ramzswap_discard(rzs, bio);

	if (!valid_swap_request(rzs, bio)) {
		stat_inc(rzs->stats.invalid_io);
		bio_io_error(bio);
		return 0;
	}

	switch (bio_data_dir(bio)) {
	case READ:
		ret = ramzswap_read(rzs, bio);
		break;

	case WRITE:
		ret = ramzswap_write(rzs, bio);
		break;
	}

	return ret;
}

static int ramzswap_ioctl_init_device(struct ramzswap *rzs)
{
	int ret;
	size_t num_pages, totalram_bytes;
	struct sysinfo i;
	struct page *page;
	void *swap_header;

	if (rzs->init_done) {
		pr_info(C "Device already initialized!\n");
		return -EBUSY;
	}
	
	ret = setup_backing_swap(rzs);
	if (ret)
		goto fail;

	si_meminfo(&i);
	/* Here is a trivia: guess unit used for i.totalram !! */
	totalram_bytes = i.totalram << PAGE_SHIFT;

	if (rzs->backing_swap)
		ramzswap_set_memlimit(rzs, totalram_bytes);
	else
		ramzswap_set_disksize(rzs, totalram_bytes);

	rzs->compress_workmem = kzalloc(LZO1X_MEM_COMPRESS, GFP_KERNEL);
	if (rzs->compress_workmem == NULL) {
		pr_err(C "Error allocating compressor working memory!\n");
		ret = -ENOMEM;
		goto fail;
	}

	rzs->compress_buffer = kzalloc(2 * PAGE_SIZE, GFP_KERNEL);
	if (rzs->compress_buffer == NULL) {
		pr_err(C "Error allocating compressor buffer space\n");
		ret = -ENOMEM;
		goto fail;
	}

	num_pages = rzs->disksize >> PAGE_SHIFT;
	rzs->table = vmalloc(num_pages * sizeof(*rzs->table));
	if (rzs->table == NULL) {
		pr_err(C "Error allocating ramzswap address table\n");
		ret = -ENOMEM;
		goto fail;
	}
	memset(rzs->table, 0, num_pages * sizeof(*rzs->table));

	map_backing_swap_extents(rzs);

	page = alloc_page(__GFP_ZERO);
	if (page == NULL) {
		pr_err(C "Error allocating swap header page\n");
		ret = -ENOMEM;
		goto fail;
	}
	rzs->table[0].pagenum = page_to_pfn(page);
	set_flag(rzs, 0, RZS_UNCOMPRESSED);

	swap_header = kmap(page);
	ret = setup_swap_header(rzs, (union swap_header *)(swap_header));
	kunmap(page);
	if (ret) {
		pr_err(C "Error setting swap header\n");
		goto fail;
	}

	set_capacity(rzs->disk, rzs->disksize >> SECTOR_SHIFT);

	/*
	 * We have ident mapping of sectors for ramzswap and
	 * and the backing swap device. So, this queue flag
	 * should be according to backing dev.
	 */
	if (!rzs->backing_swap ||
			blk_queue_nonrot(rzs->backing_swap->bd_disk->queue))
		queue_flag_set_unlocked(QUEUE_FLAG_NONROT, rzs->disk->queue);

	blk_queue_set_discard(rzs->disk->queue, ramzswap_prepare_discard);

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,30))
        blk_queue_logical_block_size(rzs->disk->queue, PAGE_SIZE);
#else
        blk_queue_hardsect_size(rzs->disk->queue, PAGE_SIZE);
#endif

	rzs->mem_pool = xv_create_pool();
	if (!rzs->mem_pool) {
		pr_err(C "Error creating memory pool\n");
		ret = -ENOMEM;
		goto fail;
	}

	/*
	 * Pages that compress to size greater than this are forwarded
	 * to physical swap disk (if backing dev is provided)
	 * TODO: make this configurable
	 */
	if (rzs->backing_swap)
		MAX_CPAGE_SIZE = MAX_CPAGE_SIZE_BDEV;
	else
		MAX_CPAGE_SIZE = MAX_CPAGE_SIZE_NOBDEV;

	pr_debug(C "Max compressed page size: %u bytes\n", MAX_CPAGE_SIZE);

	rzs->init_done = 1;

	pr_debug(C "Initialization done!\n");
	return 0;

fail:
	if (rzs->table && rzs->table[0].pagenum)
		__free_page(pfn_to_page(rzs->table[0].pagenum));
	kfree(rzs->compress_workmem);
	kfree(rzs->compress_buffer);
	vfree(rzs->table);
	xv_destroy_pool(rzs->mem_pool);

	pr_err(C "Initialization failed: err=%d\n", ret);
	return ret;
}

static int ramzswap_ioctl_reset_device(struct ramzswap *rzs)
{
	reset_device(rzs);
	return 0;
}

static int ramzswap_ioctl(struct block_device *bdev, fmode_t mode,
			unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	size_t disksize_kb, memlimit_kb;

	struct ramzswap *rzs = bdev->bd_disk->private_data;

	switch (cmd) {
	case RZSIO_SET_DISKSIZE_KB:
		if (rzs->init_done) {
			ret = -EBUSY;
			goto out;
		}
		if (copy_from_user(&disksize_kb, (void *)arg,
						_IOC_SIZE(cmd))) {
			ret = -EFAULT;
			goto out;
		}
		rzs->disksize = disksize_kb << 10;
		pr_info(C "Disk size set to %zu KB\n", disksize_kb);
		break;

	case RZSIO_SET_MEMLIMIT_KB:
		if (rzs->init_done) {
			/* TODO: allow changing memlimit */
			ret = -EBUSY;
			goto out;
		}
		if (copy_from_user(&memlimit_kb, (void *)arg,
						_IOC_SIZE(cmd))) {
			ret = -EFAULT;
			goto out;
		}
		rzs->memlimit = memlimit_kb << 10;
		pr_info(C "Memory limit set to %zu KB\n", memlimit_kb);
		break;

	case RZSIO_SET_BACKING_SWAP:
		if (rzs->init_done) {
			ret = -EBUSY;
			goto out;
		}

		if (copy_from_user(&rzs->backing_swap_name, (void *)arg,
						_IOC_SIZE(cmd))) {
			ret = -EFAULT;
			goto out;
		}
		rzs->backing_swap_name[MAX_SWAP_NAME_LEN - 1] = '\0';
		pr_info(C "Backing swap set to %s\n", rzs->backing_swap_name);
		break;

	case RZSIO_GET_STATS:
	{
		struct ramzswap_ioctl_stats *stats;
		if (!rzs->init_done) {
			ret = -ENOTTY;
			goto out;
		}
		stats = kzalloc(sizeof(*stats), GFP_KERNEL);
		if (!stats) {
			ret = -ENOMEM;
			goto out;
		}
		ramzswap_ioctl_get_stats(rzs, stats);
		if (copy_to_user((void *)arg, stats, sizeof(*stats))) {
			kfree(stats);
			ret = -EFAULT;
			goto out;
		}
		kfree(stats);
		break;
	}
	case RZSIO_INIT:
		ret = ramzswap_ioctl_init_device(rzs);
		break;

	case RZSIO_RESET:
		/* Do not reset an active device! */
		if (bdev->bd_holders) {
			ret = -EBUSY;
			goto out;
		}
		ret = ramzswap_ioctl_reset_device(rzs);
#ifdef CONFIG_SWAP_FREE_NOTIFY
		/*
		 * Racy! Device has already been swapoff'ed.  Bad things
		 * can happen if another swapon is done before this reset.
		 * TODO: A callback from swapoff() will solve this problem.
		 */
		set_swap_free_notify(bdev, NULL);
		rzs->init_notify_callback = 0;
#endif
		break;

	default:
		pr_info(C "Invalid ioctl %u\n", cmd);
		ret = -ENOTTY;
	}

out:
	return ret;
}

/*
 * Swap header (1st page of swap device) contains information
 * to indentify it as a swap partition. Prepare such a header
 * for ramzswap device (ramzswap0) so that swapon can identify
 * it as swap partition. In case backing swap device is provided,
 * copy its swap header.
 */
static int setup_swap_header(struct ramzswap *rzs, union swap_header *s)
{
	int ret = 0;
	struct page *page;
	struct address_space *mapping;
	union swap_header *backing_swap_header;

	/*
	 * There is no backing swap device. Create a swap header
	 * that is acceptable by swapon.
	 */
	if (rzs->backing_swap == NULL) {
		s->info.version = 1;
		s->info.last_page = rzs->disksize >> PAGE_SHIFT;
		s->info.nr_badpages = 0;
		memcpy(s->magic.magic, "SWAPSPACE2", 10);
		return 0;
	}

	/*
	 * We have a backing swap device. Copy its swap header
	 * to ramzswap device header. If this header contains
	 * invalid information (backing device not a swap
	 * partition, etc.), swapon will fail for ramzswap
	 * which is correct behavior - we don't want to swap
	 * over filesystem partition!
	 */

	/* Read the backing swap header (code from sys_swapon) */
	mapping = rzs->swap_file->f_mapping;
	if (!mapping->a_ops->readpage) {
		ret = -EINVAL;
		goto out;
	}

	page = read_mapping_page(mapping, 0, rzs->swap_file);
	if (IS_ERR(page)) {
		ret = PTR_ERR(page);
		goto out;
	}

	backing_swap_header = kmap(page);
	*s = *backing_swap_header;

	pr_debug("setup_swap_header: last_page = %u\n", s->info.last_page);

	kunmap(page);

out:
	return ret;
}

static void ramzswap_set_disksize(struct ramzswap *rzs, size_t totalram_bytes)
{
	if (!rzs->disksize) {
		pr_info(C
		"disk size not provided. You can use disksize_kb module "
		"param to specify size.\nUsing default: (%u%% of RAM).\n",
		DEFAULT_DISKSIZE_PERC_RAM
		);
		rzs->disksize = DEFAULT_DISKSIZE_PERC_RAM *
					(totalram_bytes / 100);
	}

	if (rzs->disksize > 2 * (totalram_bytes)) {
		pr_info(C
		"There is little point creating a ramzswap of greater than "
		"twice the size of memory since we expect a 2:1 compression "
		"ratio. Note that ramzswap uses about 0.1%% of the size of "
		"the swap device when not in use so a huge ramzswap is "
		"wasteful.\n"
		"\tMemory Size: %zu kB\n"
		"\tSize you selected: %zu kB\n"
		"Continuing anyway ...\n",
		totalram_bytes >> 10, rzs->disksize
		);
	}

	rzs->disksize &= PAGE_MASK;
	pr_info(C "disk size set to %zu kB\n", rzs->disksize >> 10);
}

/*
 * memlimit cannot be greater than backing disk size.
 */
static void ramzswap_set_memlimit(struct ramzswap *rzs, size_t totalram_bytes)
{
	int memlimit_valid = 1;

	if (!rzs->memlimit) {
		pr_info(C "Memory limit not set.\n");
		memlimit_valid = 0;
	}

	if (rzs->memlimit > rzs->disksize) {
		pr_info(C "Memory limit cannot be greater than "
			"disksize: limit=%zu, disksize=%zu\n",
			rzs->memlimit, rzs->disksize);
		memlimit_valid = 0;
	}

	if (!memlimit_valid) {
		size_t mempart, disksize;
		pr_info(C "Using default: smaller of (%u%% of RAM) and "
			"(backing disk size).\n",
			DEFAULT_MEMLIMIT_PERC_RAM);
		mempart = DEFAULT_MEMLIMIT_PERC_RAM * (totalram_bytes / 100);
		disksize = rzs->disksize;
		rzs->memlimit = mempart > disksize ? disksize : mempart;
	}

	if (rzs->memlimit > totalram_bytes / 2) {
		pr_info(C
		"Its not advisable setting limit more than half of "
		"size of memory since we expect a 2:1 compression ratio. "
		"Limit represents amount of *compressed* data we can keep "
		"in memory!\n"
		"\tMemory Size: %zu kB\n"
		"\tLimit you selected: %zu kB\n"
		"Continuing anyway ...\n",
		totalram_bytes >> 10, rzs->memlimit >> 10
		);
	}

	rzs->memlimit &= PAGE_MASK;
	BUG_ON(!rzs->memlimit);

	pr_info(C "Memory limit set to %zu kB\n", rzs->memlimit >> 10);
}

static void create_device(struct ramzswap *rzs, int device_id)
{
	mutex_init(&rzs->lock);
	INIT_LIST_HEAD(&rzs->backing_swap_extent_list);
	
	rzs->queue = blk_alloc_queue(GFP_KERNEL);
	if (!rzs->queue) {
		pr_err(C "Error allocating disk queue for device %d\n", device_id);
		return;
	}

	blk_queue_make_request(rzs->queue, ramzswap_make_request);

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,30))
	blk_queue_logical_block_size(rzs->queue, PAGE_SIZE);
#else
	blk_queue_hardsect_size(rzs->queue, PAGE_SIZE);
#endif
	rzs->queue->queuedata = rzs;

	 /* gendisk structure */
	rzs->disk = alloc_disk(1);
	if (!rzs->disk) {
		blk_cleanup_queue(rzs->queue);
		pr_warning(C "Error allocating disk structure for device %d\n",
								device_id);
		return;
	}

	rzs->disk->major = RAMZSWAP_MAJOR;
	rzs->disk->first_minor = device_id;
	rzs->disk->fops = &ramzswap_devops;
	rzs->disk->queue = rzs->queue;
	rzs->disk->private_data = rzs;
	snprintf(rzs->disk->disk_name, 16, "ramzswap%d", device_id);

	/*
	 * Actual capacity set using RZSIO_SET_DISKSIZE_KB ioctl
	 * or set equal to backing swap device (if provided)
	 */
	set_capacity(rzs->disk, 0);
	add_disk(rzs->disk);

	rzs->init_done = 0;

	return;
}

static void destroy_device(struct ramzswap *rzs)
{
	if (rzs->disk) {
		del_gendisk(rzs->disk);
		put_disk(rzs->disk);
	}

	if (rzs->queue)
		blk_cleanup_queue(rzs->queue);
}

static void reset_device(struct ramzswap *rzs)
{
	int is_backing_blkdev = 0;
	size_t index, num_pages;
	unsigned entries_per_page;
	unsigned long entry, num_table_pages;

	if (!rzs->init_done)
		return;

	if (rzs->backing_swap && !rzs->num_extents)
		is_backing_blkdev = 1;
	
	num_pages = rzs->disksize >> PAGE_SHIFT;

	/* Free various per-device buffers */
	kfree(rzs->compress_workmem);
	kfree(rzs->compress_buffer);

	rzs->compress_workmem = NULL;
	rzs->compress_buffer = NULL;

	/* Free all pages that are still in this ramzswap device */
	for (index = 0; index < num_pages; index++) {
		u32 pagenum, offset;

		pagenum = rzs->table[index].pagenum;
		offset = rzs->table[index].offset;

		if (!pagenum)
			continue;

		if (unlikely(test_flag(rzs, index, RZS_UNCOMPRESSED)))
			__free_page(pfn_to_page(pagenum));
		else
			xv_free(rzs->mem_pool, pagenum, offset);
	}

	entry = 0;
	entries_per_page = PAGE_SIZE / sizeof(*rzs->table);
	num_table_pages = DIV_ROUND_UP(num_pages * sizeof(*rzs->table),
							PAGE_SIZE);
	/*
	 * Set page->mapping to NULL for every table page.
	 * Otherwise, we will hit bad_page() during free.
	 */
	while (rzs->num_extents && num_table_pages--) {
		struct page *page;
		page = vmalloc_to_page(&rzs->table[entry]);
		page->mapping = NULL;
		entry += entries_per_page;
	}
	vfree(rzs->table);
	rzs->table = NULL;

	xv_destroy_pool(rzs->mem_pool);
	rzs->mem_pool = NULL;

	/* Free all swap extent pages */
	while (!list_empty(&rzs->backing_swap_extent_list)) {
		struct page *page;
		struct list_head *entry;
		entry = rzs->backing_swap_extent_list.next;
		page = list_entry(entry, struct page, lru);
		list_del(entry);
		__free_page(page);
	}
	INIT_LIST_HEAD(&rzs->backing_swap_extent_list);
	rzs->num_extents = 0;

	/* Close backing swap device, if present */
	if (rzs->backing_swap) {
		if (is_backing_blkdev)
			bd_release(rzs->backing_swap);
		filp_close(rzs->swap_file, NULL);
		rzs->backing_swap = NULL;
	}

	/* Reset stats */
	memset(&rzs->stats, 0, sizeof(rzs->stats));

	rzs->disksize = 0;
	rzs->memlimit = 0;
	
	/* Back to uninitialized state */
	rzs->init_done = 0;
}

static int __init ramzswap_init(void)
{
	int i;

	if (NUM_DEVICES > MAX_NUM_DEVICES) {
		pr_warning(C "Invalid value for NUM_DEVICES: %lu\n",
						NUM_DEVICES);
		return -EINVAL;
	}

	RAMZSWAP_MAJOR = register_blkdev(0, "ramzswap");
	if (RAMZSWAP_MAJOR <= 0) {
		pr_warning(C "Unable to get major number\n");
		return -EBUSY;
	}

	if (!NUM_DEVICES) {
		pr_info(C "NUM_DEVICES not specified. Using default: 1\n");
		NUM_DEVICES = 1;
	}

	/* Allocate the device array and initialize each one */
	pr_info(C "Creating %lu devices ...\n", NUM_DEVICES);
	DEVICES = kzalloc(NUM_DEVICES * sizeof(struct ramzswap), GFP_KERNEL);
	if (!DEVICES)
		goto out;

	for (i = 0; i < NUM_DEVICES; i++)
		create_device(&DEVICES[i], i);

	return 0;

out:
	unregister_blkdev(RAMZSWAP_MAJOR, "ramzswap");
	return -ENOMEM;
}

static void __exit ramzswap_exit(void)
{
	int i;

	for (i = 0; i < NUM_DEVICES; i++) {
		destroy_device(&DEVICES[i]);
		reset_device(&DEVICES[i]);
	}

	unregister_blkdev(RAMZSWAP_MAJOR, "ramzswap");

	kfree(DEVICES);
	pr_debug(C "Cleanup done!\n");
}

module_param(NUM_DEVICES, ulong, 0);
MODULE_PARM_DESC(NUM_DEVICES, "Number of ramzswap devices");

module_init(ramzswap_init);
module_exit(ramzswap_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Nitin Gupta <ngupta@vflare.org>");
MODULE_DESCRIPTION("Compressed RAM Based Swap Device");
