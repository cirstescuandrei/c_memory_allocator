// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include "block_list.h"

void *os_malloc(size_t size)
{
	if (!size)
		return NULL;

	// using mmap() for allocations > MMAP_THRESHOLD
	if (BLOCK_META_SIZE + ALIGN(size) > MMAP_THRESHOLD) {
		void *addr = mmap(NULL, BLOCK_META_SIZE + ALIGN(size), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

		DIE(addr == MAP_FAILED, "mmap failed");

		// add memory block to list
		add_block(&list_head, addr, size, STATUS_MAPPED);

		return (void *) ((char *) addr + BLOCK_META_SIZE);
	}

	// prealloc for first sbrk() call
	if (heap_preallocation == HEAP_NOT_PREALOC) {
		void *addr = sbrk(MMAP_THRESHOLD);

		DIE(addr == MAP_FAILED, "sbrk failed");

		heap_preallocation = HEAP_PREALLOC;
		struct block_meta *new_block = add_block(&list_head, addr, MMAP_THRESHOLD - BLOCK_META_SIZE, STATUS_ALLOC);

		// if split is possbile
		if (MMAP_THRESHOLD - (BLOCK_META_SIZE + ALIGN(size)) >= BLOCK_META_SIZE + ALIGNMENT)
			split_block(new_block, ALIGN(size));

		return (void *) ((char *) addr + BLOCK_META_SIZE);
	}

	// coalescing free blocks before search
	coalesce_blocks();

	// search for the best fitting block
	struct block_meta *best_block = find_best_block(ALIGN(size));

	// fitting block found
	if (best_block) {
		best_block->status = STATUS_ALLOC;

		if (best_block->size - ALIGN(size) >= BLOCK_META_SIZE + ALIGNMENT)
			split_block(best_block, ALIGN(size));

		return (void *) ((char *) best_block + BLOCK_META_SIZE);
	}

	struct block_meta *last_block = last_heap_block();

	// last block can be expanded
	if (last_block && last_block->status == STATUS_FREE) {
		void *addr = sbrk(ALIGN(size) - last_block->size);

		DIE(addr == MAP_FAILED, "sbrk failed");

		last_block->status = STATUS_ALLOC;
		last_block->size = ALIGN(size);

		return (void *) ((char *) last_block + BLOCK_META_SIZE);
	}

	// no fitting block found
	void *addr = sbrk(BLOCK_META_SIZE + ALIGN(size));

	DIE(addr == MAP_FAILED, "sbrk failed");

	add_block(&list_head, addr, size, STATUS_ALLOC);

	return (void *) ((char *) addr + BLOCK_META_SIZE);
}

void os_free(void *ptr)
{
	if (ptr == NULL)
		return;

	struct block_meta *block = find_block(ptr);

	if (block == NULL)
		return;

	if (block->status == STATUS_ALLOC) {
		block->status = STATUS_FREE;
		return;
	}

	if (block->status == STATUS_MAPPED) {
		del_block(block);

		int munmap_ret = munmap(block, BLOCK_META_SIZE + block->size);

		DIE(munmap_ret == -1, "munmap failed");
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	if (!nmemb || !size)
		return NULL;

	size = nmemb * size;

	long page_size = sysconf(_SC_PAGE_SIZE);

	DIE(page_size == -1, "sysconf failed");

	// using mmap() for allocations > page_size
	if (BLOCK_META_SIZE + ALIGN(size) > (size_t) page_size) {
		void *addr = mmap(NULL, BLOCK_META_SIZE + ALIGN(size), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

		DIE(addr == MAP_FAILED, "mmap failed");

		// add memory block to list
		add_block(&list_head, addr, size, STATUS_MAPPED);

		memset((void *) ((char *) addr + BLOCK_META_SIZE), 0, ALIGN(size));

		return (void *) ((char *) addr + BLOCK_META_SIZE);
	}

	// prealloc for first sbrk() call
	if (heap_preallocation == HEAP_NOT_PREALOC) {
		void *addr = sbrk(MMAP_THRESHOLD);

		DIE(addr == MAP_FAILED, "sbrk failed");

		heap_preallocation = HEAP_PREALLOC;
		struct block_meta *new_block = add_block(&list_head, addr, MMAP_THRESHOLD - BLOCK_META_SIZE, STATUS_ALLOC);

		// if split is possbile
		if (MMAP_THRESHOLD - (BLOCK_META_SIZE + ALIGN(size)) >= BLOCK_META_SIZE + ALIGNMENT)
			split_block(new_block, ALIGN(size));

		memset((void *) ((char *) addr + BLOCK_META_SIZE), 0, ALIGN(size));

		return (void *) ((char *) addr + BLOCK_META_SIZE);
	}

	// coalescing free blocks before search
	coalesce_blocks();

	// search for the best fitting block
	struct block_meta *best_block = find_best_block(ALIGN(size));

	// fitting block found
	if (best_block) {
		best_block->status = STATUS_ALLOC;

		if (best_block->size - ALIGN(size) >= BLOCK_META_SIZE + ALIGNMENT)
			split_block(best_block, ALIGN(size));

		memset((void *) ((char *) best_block + BLOCK_META_SIZE), 0, ALIGN(size));

		return (void *) ((char *) best_block + BLOCK_META_SIZE);
	}

	struct block_meta *last_block = last_heap_block();

	// last block can be expanded
	if (last_block && last_block->status == STATUS_FREE) {
		void *addr = sbrk(ALIGN(size) - last_block->size);

		DIE(addr == MAP_FAILED, "sbrk failed");

		last_block->status = STATUS_ALLOC;
		last_block->size = ALIGN(size);

		memset((void *) ((char *) last_block + BLOCK_META_SIZE), 0, ALIGN(size));

		return (void *) ((char *) last_block + BLOCK_META_SIZE);
	}

	// no fitting block found
	void *addr = sbrk(BLOCK_META_SIZE + ALIGN(size));

	DIE(addr == MAP_FAILED, "sbrk failed");

	add_block(&list_head, addr, size, STATUS_ALLOC);

	memset((void *) ((char *) addr + BLOCK_META_SIZE), 0, ALIGN(size));

	return (void *) ((char *) addr + BLOCK_META_SIZE);
}

void *os_realloc(void *ptr, size_t size)
{
	if (ptr == NULL)
		return os_malloc(size);

	if (!size) {
		os_free(ptr);
		return NULL;
	}

	struct block_meta *block = find_block(ptr);

	// ptr doesn't belong to any memory block or is freed
	if (block == NULL || block->status == STATUS_FREE)
		return NULL;

	// block is the correct size; do nothing
	if (ALIGN(size) == block->size)
		return ptr;

	// allocation exceeds MMAP_THRESHOLD or block is mapped and must be moved
	if (BLOCK_META_SIZE + ALIGN(size) > MMAP_THRESHOLD || block->status == STATUS_MAPPED) {
		void *addr = os_malloc(size);

		// copy depends on whether size is bigger or smaller than block->size
		if (block->size < ALIGN(size))
			memmove(addr, ptr, block->size);
		else
			memmove(addr, ptr, ALIGN(size));

		os_free(ptr);

		return addr;
	}

	// size < block->size; try to split the block
	if (ALIGN(size) < block->size) {
		if (block->size - ALIGN(size) >= BLOCK_META_SIZE + ALIGNMENT)
			split_block(block, ALIGN(size));

		return ptr;
	}

	// size > block->size; try to expand the last block
	if (block == last_heap_block()) {
		void *addr = sbrk(ALIGN(size) - block->size);

		DIE(addr == MAP_FAILED, "sbrk failed");

		block->size = ALIGN(size);

		return ptr;
	}

	coalesce_blocks();

	// size > block->size; try to merge with adjacent free block
	if (block->next->status == STATUS_FREE && (ALIGN(size) <= block->size + BLOCK_META_SIZE + block->next->size)) {
		block->size += BLOCK_META_SIZE + block->next->size;

		del_block(block->next);

		if (block->size - ALIGN(size) >= BLOCK_META_SIZE + ALIGNMENT)
			split_block(block, ALIGN(size));

		return ptr;
	}

	// allocate a new block
	void *addr = os_malloc(size);

	memmove(addr, ptr, block->size);

	os_free(ptr);

	return addr;
}
