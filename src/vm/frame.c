#include <stdbool.h>
#include <stdint.h>
#include <list.h>
#include "threads/synch.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include <string.h>
#include <stdio.h>

static struct frame *clock_algo_select(void);
static void evict_and_clear(struct frame *evict_f);

/* initialize the frame table system */
void frame_init(void)
{
    list_init(&frame_list);
    lock_init(&frame_lock);
}

/* allocate a frame, if no frame is availble, evict one
   and allocate again */
struct frame *
falloc(struct page *p)
{
    struct frame *f;
    void *faddr = palloc_get_page(PAL_USER | PAL_ZERO);
    if (!faddr)
    {
        /*No free frame, select one, evict and clear it*/
        lock_acquire(&frame_lock);
        f = clock_algo_select();
        evict_and_clear(f);
        lock_release(&frame_lock);
    }
    else
    {
        f = malloc(sizeof(struct frame));
        if (f == NULL)
            return NULL;
        f->faddr = faddr;
    }
    f->p = p;
    /* put the new frame to the list */
    lock_acquire(&frame_lock);
    list_push_back(&frame_list, &f->elem);
    lock_release(&frame_lock);
    return f;
}

/*evict one frame and clear it again*/
static void evict_and_clear(struct frame *evict_f)
{
    struct page *evict_p = evict_f->p;
    uint32_t *evict_pd = evict_p->t->pagedir;
    uint32_t *evict_vaddr = evict_p->vaddr;
    uint32_t *evict_faddr = evict_f->faddr;

    bool dirty = pagedir_is_dirty(evict_pd, evict_vaddr);
    /* clear pagedir entry */
    pagedir_clear_page(evict_pd, evict_vaddr);
    evict_f->p = NULL;
    evict_p->f = NULL;

    if (evict_p->src != MMAP)
    {
        /* If it is not frome a mmap file */
        if (dirty)
            /* If it is dirty, change the src to the swap place */
            /* or it can be load from the disk again */
            evict_p->src = SWAP;
        if (evict_p->src == SWAP)
            swap_write(evict_faddr, &evict_p->swap_place);
    }
    else
    {
        /* If it is from a mmap file and is dirty, write back to the file */
        if (dirty)
        {
            lock_acquire(&filesys_lock);
            file_write_at(evict_p->fp, evict_faddr,
                          evict_p->read_bytes, evict_p->ofs);
            lock_release(&filesys_lock);
        }
    }

    evict_p->active = false;

    /* clear it so we can reuse it */
    memset(evict_faddr, 0, PGSIZE);
}

/* Clock Algorithm, select one frame to evict */
static struct frame *
clock_algo_select()
{
    while (1)
    {
        bool accessed;
        struct list_elem *e = list_pop_front(&frame_list);
        struct frame *f = list_entry(e, struct frame, elem);
        /*if it is pinned, pass*/
        if (!f->p->pinned)
        {
            accessed = pagedir_is_accessed(f->p->t->pagedir, f->p->vaddr);
            if (!accessed)
                /* if not accessed, select it */
                return f;
            /* if accessed, clear the access bit, give it second chance */
            pagedir_set_accessed(f->p->t->pagedir, f->p->vaddr, false);
        }
        /*push the front node to the back, simulate the "clock cycle"*/
        list_push_back(&frame_list, e);
    }
}