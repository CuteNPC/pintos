#include <hash.h>
#include <stdbool.h>
#include <stdint.h>
#include "filesys/off_t.h"
#include "vm/page.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/pte.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"
#include "vm/swap.h"

/* Hash function of the supplemental page table */
unsigned int hash_page_func(const struct hash_elem *e, void *aux UNUSED)
{
   struct page *page = hash_entry(e, struct page, elem);
   int hash_key = (int)(page->vaddr);
   int hash_value = hash_int(hash_key);
   return hash_value;
}

/* Compare function of the supplemental page table */
bool less_page_func(const struct hash_elem *elem_a,
                    const struct hash_elem *elem_b, void *aux UNUSED)
{
   struct page *page_a = hash_entry(elem_a, struct page, elem);
   struct page *page_b = hash_entry(elem_b, struct page, elem);
   return ((int)(page_a->vaddr)) < ((int)(page_b->vaddr));
}

/* Find the corresponding supplemental page table entry of
   the current thread by the virtual address */
struct page *get_entry(void *vaddr)
{
   // get the bucket
   struct hash *page_table = &(thread_current()->page_table);
   size_t bucket_idx = hash_int((int)vaddr) & (page_table->bucket_cnt - 1);
   struct list *bucket = &page_table->buckets[bucket_idx];
   // find the elem in the bucket.
   for (struct list_elem *e = list_begin(bucket);
        e != list_end(bucket); e = list_next(e))
   {
      struct hash_elem *he = list_entry(e, struct hash_elem, list_elem);
      struct page *p = hash_entry(he, struct page, elem);
      if (vaddr == p->vaddr)
         return p;
   }
   // NULL when find nothing.
   return NULL;
}

/* free one page */
void free_one_page(struct page *p)
{
   if (p->active == true)
   {
      /* If it is from a mmap file, write back to the file  */
      if (p->src == MMAP && pagedir_is_dirty(p->t->pagedir, p->vaddr))
      {
         lock_acquire(&filesys_lock);
         file_write_at(p->fp, p->f->faddr,
                       p->read_bytes, p->ofs);
         lock_release(&filesys_lock);
      }
      /* If the page is in the physics memory, free the frame.*/
      lock_acquire(&frame_lock);
      list_remove(&p->f->elem);
      palloc_free_page(p->f->faddr);
      lock_release(&frame_lock);
      free(p->f);
      /* Clear the page table */
      pagedir_clear_page(thread_current()->pagedir, p->vaddr);
   }
   /* If it is in the swap space, clear the slot  */
   else if (p->src == SWAP)
      bitmap_set(swap_bitmap, p->swap_place, 0);
   /* Free the space of the supplemental page table */
   free(p);
}

/* Set a new page, fill the supplementary page table entry */
struct page *new_page(void *vaddr, bool rw, enum page_src src,
                      struct file *fp, off_t ofs, off_t read_bytes)
{
   struct page *p = malloc(sizeof(struct page));
   if (p == NULL)
      return NULL;
   p->t = thread_current();
   p->vaddr = vaddr;
   p->writable = rw;
   p->pinned = 0;
   p->swap_place = -1;
   p->f = NULL;
   p->fp = fp;
   p->ofs = ofs;
   p->read_bytes = read_bytes;
   p->src = src;
   if (src == DISK && read_bytes == 0)
      p->src = ZERO;
   p->active = false;
   hash_insert(&p->t->page_table, &p->elem);
   return p;
}

/* Set a new stack page */
bool new_stack_page(void *stack_page)
{
   /* initialize the stack to zero */
   return (bool)new_page(stack_page, true, ZERO, NULL, 0, 0);
}

/* When page fault happened, the function is called and
   try to load the page into the physics memory */
bool page_fault_fix(void *fault_addr, void *esp)
{
   struct thread *t = thread_current();
   void *vaddr = pg_round_down(fault_addr);
   /* find the supplemental page table entry of the address */
   struct page *p = get_entry(vaddr);
   if (!p)
   {
      /* Is it a stack growth */
      if (!(fault_addr >= esp - 0x20 &&
            fault_addr < PHYS_BASE && fault_addr >= PHYS_BASE - LIM_STACK))
         return false;
      /* Allocate new stack page */
      while (t->stack_bound > vaddr)
      {
         t->stack_bound -= PGSIZE;
         if (!new_stack_page(t->stack_bound))
            return false;
      }
      return true;
   }
   p->pinned++;
   /* allocate a frame for the page */
   p->f = falloc(p);
   if (!p->f || p->active)
      return false;
   void *faddr = p->f->faddr;

   switch (p->src)
   {
   case DISK:
   case MMAP:
      /* if the page is in the disk or mmap file, load it from the file */
      lock_acquire(&filesys_lock);
      file_read_at(p->fp, faddr, p->read_bytes, p->ofs);
      lock_release(&filesys_lock);
      break;

   case SWAP:
      /* if the page is in the disk, load it from the swap */
      swap_read(faddr, &p->swap_place);
      break;

   case ZERO:
      /* if the page is in a zero page, do nothing */
      break;
   }

   /* set the page in the real page table */
   pagedir_set_page(t->pagedir, vaddr, faddr, p->writable);
   p->active = true;
   p->pinned--;
   return true;
}

/* Similar design to file descriptor
   Always allocate the smallest unused mmap descriptor
   Then insert to mmap_list */
int allocate_mapid(void *vaddr, off_t size)
{
   struct list *lst;
   struct list_elem *e;
   lst = &thread_current()->mmap_list;
   int mapid = 0;
   for (e = list_begin(lst); e != list_end(lst); e = list_next(e))
   {
      if (list_entry(e, struct mmap_file, elem)->mapid != mapid)
         break;
      mapid++;
   }
   struct mmap_file *new_m = malloc(sizeof(struct mmap_file));
   if (!new_m)
      return -1;
   new_m->size = size;
   new_m->vaddr = vaddr;
   new_m->mapid = mapid;
   list_insert(e, &new_m->elem);
   return new_m->mapid;
}

/* Free a mmap descriptor */
void free_mapid(int mapid)
{
   struct list *lst = &thread_current()->mmap_list;
   for (struct list_elem *e = list_begin(lst);
        e != list_end(lst); e = list_next(e))
   {
      struct mmap_file *m = list_entry(e, struct mmap_file, elem);
      if (m->mapid == mapid)
      {
         /*remove the mmap descriptor from the list*/
         list_remove(&m->elem);
         for (void *addr = m->vaddr; addr < m->vaddr + m->size;
              addr += PGSIZE)
         {
            struct page *p = get_entry(addr);
            /* remove the supplemental page table entry from the hash table */
            hash_delete(&p->t->page_table, &p->elem);
            /* Free the page */
            free_one_page(p);
         }
         free(m);
         return;
      }
   }
}