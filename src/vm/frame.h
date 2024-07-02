#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <stdbool.h>
#include <stdint.h>
#include <list.h>
#include "threads/synch.h"
#include "vm/page.h"

struct frame
{
    void *faddr;           /**< The frame address*/
    struct page *p;        /**< Map to supplemental page table */
    struct list_elem elem; /**< List element. */
};

struct list frame_list;    /**< frame list */
struct lock frame_lock;    /**< frame lock, for synchronization */

void frame_init(void);
struct frame *falloc(struct page *p);

#endif /**< vm/frame.h */