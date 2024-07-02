#include "vm/swap.h"
#include <stdio.h>

/* initialize the frame table system */
void swap_init(void)
{
    lock_init(&swap_lock);
    swap_block = block_get_role(BLOCK_SWAP);
    swap_size = block_size(swap_block) / PG_DIV_SEC;
    swap_bitmap = bitmap_create(swap_size);
    return;
}

/* read from the swap */
void swap_read(void *addr, int *place)
{
    lock_acquire(&swap_lock);
    bitmap_set(swap_bitmap, *place, 0);
    int sec = (*place) * PG_DIV_SEC;
    for (int i = 0; i < PG_DIV_SEC; i++)
    {
        block_read(swap_block, sec, addr);
        sec++;
        addr += BLOCK_SECTOR_SIZE;
    }
    lock_release(&swap_lock);
}

/* write to the swap, save the write place in the 'place' */
void swap_write(void *addr, int *place)
{
    lock_acquire(&swap_lock);
    *place = bitmap_scan_and_flip(swap_bitmap, 0, 1, 0);
    int sec = (*place) * PG_DIV_SEC;
    for (int i = 0; i < PG_DIV_SEC; i++)
    {
        block_write(swap_block, sec, addr);
        sec++;
        addr += BLOCK_SECTOR_SIZE;
    }
    lock_release(&swap_lock);
}
