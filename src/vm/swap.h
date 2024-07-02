#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "threads/synch.h"
#include "devices/block.h"
#include "threads/pte.h"
#include <bitmap.h>

#define PG_DIV_SEC (PGSIZE / BLOCK_SECTOR_SIZE)

struct lock swap_lock;      /**< swap lock, for synchronization */
struct block *swap_block;   /**< swap lock devices */
struct bitmap *swap_bitmap; /**< bitmap for availble swap slot*/
int swap_size;              /**< size of the swap device, 4096bytes */

void swap_init(void);
void swap_read(void *addr, int *place);
void swap_write(void *addr, int *place);

#endif /**< vm/swap.h */