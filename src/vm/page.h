#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include <stdbool.h>
#include <stdint.h>
#include "filesys/off_t.h"

/* The resource of the page, when we load the page, where it should from? */

enum page_src
{
    DISK, // from disk
    SWAP, // from swap
    ZERO, // all zreo page
};

struct page
{
    struct thread *t;      /**< The thread that hold the page */
    void *vaddr;           /**< The virutal address */
    struct frame *f;       /**< Frame mapped */
    bool writable;         /**< Writable */
    int pinned;            /**< Positive when processed in page_fault_fix */
    int swap_place;        /**< The place in the swap device */
    bool active;           /**< Be true if the page is on a frame */
    enum page_src src;     /**< The resource of the page */

    /**< For lazy loading from the disk */
    struct file *fp;       /**< File pointer */
    off_t ofs;             /**< offset of the file */
    off_t read_bytes;      /**< read bytes */

    struct hash_elem elem; /**< List element. */
};

unsigned hash_page_func(const struct hash_elem *e, void *aux);
bool less_page_func(const struct hash_elem *elem_a,
                    const struct hash_elem *elem_b, void *aux);
struct page *get_entry(void *vaddr);
void free_page_table(struct hash* page_table);
bool page_fault_fix(void* fault_vaddr);

#endif /**< vm/page.h */
