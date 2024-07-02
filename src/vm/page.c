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

/* Free all the frame, and destroy the supplemental page table, free the space */
void free_page_table(struct hash *page_table)
{
   for (size_t i = 0; i < page_table->bucket_cnt; i++)
   {
      while (!list_empty(&page_table->buckets[i]))
      {
         /* for all elem in the hash table */
         struct list_elem *e = list_pop_front(&page_table->buckets[i]);
         struct hash_elem *he = list_entry(e, struct hash_elem, list_elem);
         lock_acquire(&frame_lock);
         struct page *p = hash_entry(he, struct page, elem);
         if (p->active == true)
         {
            /* if the page is in the physics memory, free the frame
               and clear the page table */
            list_remove(&p->f->elem);
            palloc_free_page(p->f->faddr);
            free(p->f);
            pagedir_clear_page(thread_current()->pagedir, p->vaddr);
         }
         /* free the space of the supplemental page table */
         free(p);
         lock_release(&frame_lock);
      }
   }
   /* free the bucket of hash table */
   free(page_table->buckets);
}

/* When page fault happened, the function is called and
   try to load the page into the physics memory */
bool page_fault_fix(void *vaddr)
{
   /* find the supplemental page table entry of the address */
   struct page *p = get_entry(vaddr);
   if (!p)
      return false;
   p->pinned++;
   /* allocate a frame for the page */
   p->f = falloc(p);
   if (!p->f || p->active)
      return false;
   void *faddr = p->f->faddr;

   switch (p->src)
   {
   case DISK:
      /* if the page is in the disk, load it from the file */
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
   pagedir_set_page(thread_current()->pagedir, vaddr, faddr, p->writable);
   p->active = true;
   p->pinned--;
   return true;
}
