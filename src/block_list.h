/* SPDX-License-Identifier: BSD-3-Clause */

#pragma once

#include "../utils/block_meta.h"
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>

#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))

#define BLOCK_META_SIZE (ALIGN(sizeof(struct block_meta)))
#define MMAP_THRESHOLD (128 * 1024)
#define HEAP_PREALLOC 1
#define HEAP_NOT_PREALOC 0

extern struct block_meta list_head;
extern size_t heap_preallocation;

struct block_meta* add_block(struct block_meta *node, void *addr, size_t size, int status);
void del_block(struct block_meta *block);
struct block_meta* find_block(void *addr);
struct block_meta* find_best_block(size_t size);
struct block_meta* last_heap_block(void);
void split_block(struct block_meta *block, size_t split_size);
void coalesce_blocks(void);
