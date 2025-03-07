// SPDX-License-Identifier: BSD-3-Clause

#include "block_list.h"

struct block_meta list_head = {0, -1, &list_head, &list_head};
size_t heap_preallocation = HEAP_NOT_PREALOC;

struct block_meta *add_block(struct block_meta *node, void *addr, size_t size, int status)
{
	struct block_meta *new_block = (struct block_meta *) addr;

	new_block->size = ALIGN(size);
	new_block->status = status;

	new_block->next = node;
	new_block->prev = node->prev;
	node->prev->next = new_block;
	node->prev = new_block;

	return new_block;
}

void del_block(struct block_meta *block)
{
	block->prev->next = block->next;
	block->next->prev = block->prev;
}

struct block_meta *find_block(void *addr)
{
	struct block_meta *block = list_head.next;

	while (block != &list_head) {
		void *block_addr = (void *) ((char *) block + BLOCK_META_SIZE);

		if (block_addr == addr)
			return block;

		block = block->next;
	}

	return NULL;
}

struct block_meta *find_best_block(size_t size)
{
	struct block_meta *block = list_head.next;
	struct block_meta *best_block = NULL;
	size_t best_block_size = __SIZE_MAX__;

	while (block != &list_head) {
		if (block->status == STATUS_FREE && block->size >= ALIGN(size) && block->size < best_block_size) {
			best_block = block;
			best_block_size = block->size;
		}

		block = block->next;
	}

	return best_block;
}

struct block_meta *last_heap_block(void)
{
	struct block_meta *block = list_head.prev;

	while (block != &list_head) {
		if (block->status == STATUS_ALLOC || block->status == STATUS_FREE)
			return block;

		block = block->prev;
	}

	return NULL;
}

void split_block(struct block_meta *block, size_t split_size)
{
	struct block_meta *new_block = (struct block_meta *) ((char *) block + BLOCK_META_SIZE + ALIGN(split_size));

	add_block(block->next, new_block, block->size - ALIGN(split_size) - BLOCK_META_SIZE, STATUS_FREE);

	block->size = ALIGN(split_size);
}

void coalesce_blocks(void)
{
	struct block_meta *block = list_head.next;

	while (block->next != &list_head) {
		if (block->status == STATUS_FREE && block->next->status == STATUS_FREE) {
			block->size += BLOCK_META_SIZE + block->next->size;

			del_block(block->next);

			block = block->prev;
		}

		block = block->next;
	}
}
