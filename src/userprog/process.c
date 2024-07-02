#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"
#include <hash.h>

/** This structure is used to pass parameters 
 *  It also contains a semaphore and a loading status, which is used to 
 *  transfer the loading status from the child to the parent process */
/*  See comment of 'args_parsing' function for more detail */
struct args_info
{
  int ret_addr;    /**< Return address, must be set to zero */
  int argc;        /**< Number of arguments */
  char **argv;     /**< Pointer of argv[], must be set to the address of buffer*/
  char buffer[LOADER_ARGS_LEN * 3 + 12];
                   /**< Buffer used to store argv pointers and strings */
  char copy_of_cmd_line[LOADER_ARGS_LEN + 4];
                   /**< Used to handle strings  */
  int stack_size;  /**< Stack size */
  char *name;      /**< Name of the new thread, */

  int load_success;/**< Flag of loading. The child passed to the parent */
  struct semaphore load_lock;
                   /**< Lock used by the parent to wait for the child to load */
};

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
void args_parsing(const char *, struct args_info *);

/** Parsing argument function */
/*  In this function, we construct 'struct arg_info' like
 *  the stack of the new thread. So in start_process function,
 *  we just copy the memory directly to the real stack!
 *  we only copy the useful part, so the memory space is not wasted*/
void
args_parsing(const char *cmd_line, struct args_info *args)
{
  /* Set ret_addr, argc, the end of the buffer to 0 */
  args->ret_addr = args->argc = args->copy_of_cmd_line[-1] = 0;
  args->argv = (char **)&(args->buffer);

  /* Copy cmd_line to args->copy_of_cmd_line for processing*/
  strlcpy(args->copy_of_cmd_line, cmd_line, LOADER_ARGS_LEN);

  /* Turn all spaces of copy_of_cmd_line into \0
     Record the number of arguments.*/
  char *p1;
  for (p1 = args->copy_of_cmd_line; *p1; p1++)
    if (*p1 == ' ')
      *p1 = 0;
    else if (!*(p1 - 1))
      args->argc++;
  args->argv[args->argc] = NULL;

  /* Now that we know the number of arguments, we can determine 
     the place to store the argument string.
     Now copy the arguments string from copy_of_cmd_line to the 
     right place, and make argv[] point to them*/
  char *psrc = args->copy_of_cmd_line;
  char *pdes = (char *)(args->argv + args->argc + 1);
  char *pend = p1 + 1;
  int index = 0;
  while (psrc != pend)
  {
    if (*psrc)
    {
      if (!*(psrc - 1))
        args->argv[index++] = pdes;
      *pdes++ = *psrc;
    }
    else
    {
      if (*(psrc - 1))
        *pdes++ = 0;
    }
    psrc++;
  }
  /*Program Name*/
  args->name = args->argv[0];
  /* The size of the stack, which should include the range from 
   * ret_addr to a portion of the buffer */
  args->stack_size = (pdes - (char *)args + 3) & (-4);

  /*When we copy, the memory location changes,
  So we need to make an offset to the pointer beforehand*/
  int offset = (PHYS_BASE - args->stack_size - (void *)(args));
  for (int i = 0; i < args->argc; i++)
    args->argv[i] += offset;
  args->argv += offset / 4;
}

/** Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */

tid_t process_execute(const char *cmd_line)
{
  struct args_info *args = malloc(sizeof(struct args_info));
  if (args == NULL)
    return TID_ERROR;
  /* Parsing argument */
  args_parsing(cmd_line, args);
  /* Stack too large, refused to load */
  if(args->stack_size > PGSIZE)
  {
    free(args);
    return TID_ERROR;
  }

  sema_init(&args->load_lock, 0);
  /* Create a new thread to execute FILE_NAME. */
  tid_t tid;
  tid = thread_create(args->name, PRI_DEFAULT, start_process, args);
  if (tid != TID_ERROR)
  {
    /*Waiting for child to load*/
    sema_down(&args->load_lock);
    if (!args->load_success)
      tid = TID_ERROR;
  }
  free(args);
  return tid;
}

/** A thread function that loads a user process and starts it
   running. */
static void
start_process(void *args_)
{
  struct args_info *args = args_;
  struct thread *cur = thread_current();
  struct intr_frame if_;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  lock_acquire(&filesys_lock);
  /*Pass information of loading result to the parent by 'args'*/
  args->load_success = load(args->name, &if_.eip, &if_.esp);
  lock_release(&filesys_lock);

  if (args->load_success)
  {
    /*Set esp pointer*/
    if_.esp = PHYS_BASE - args->stack_size;
    /* Copy the memory directly! */
    memcpy(if_.esp, args, args->stack_size);

    /* Release the semaphore to wake up parent*/
    sema_up(&args->load_lock);
  }
  else
  {
    /* Release the semaphore to wake up parent*/
    sema_up(&args->load_lock);
    cur->return_value = -1;
    /* If loading fails, exit*/
    thread_exit();
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/** Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting. */
int process_wait(tid_t child_tid)
{
  struct list *lst = &thread_current()->child_list;
  struct list_elem *e;
  for (e = list_begin(lst); e != list_end(lst); e = list_next(e))
  {
    struct child_info *cinfo = list_entry(e, struct child_info, elem);
    if (cinfo->tid == child_tid)
    {
      if (cinfo->wait_once == 1)
      /* Called twice */
        return -1;
      sema_down(&cinfo->wait_sema);
      cinfo->wait_once = 1;
      return cinfo->return_value;
    }
  }
  return -1;
}

/** Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Destroy and free the supplemental page table,
     free the space of the frame*/
  struct hash* page_table =&cur->page_table;
  for (size_t i = 0; i < page_table->bucket_cnt; i++)
    while (!list_empty(&page_table->buckets[i]))
    {
      struct list_elem *e = list_pop_front(&page_table->buckets[i]);
      free_one_page(hash_entry((struct hash_elem *)e, struct page, elem));
    }
  free(page_table->buckets);
  while (!list_empty(&cur->mmap_list))
    free(list_entry(list_pop_front(&cur->mmap_list), struct mmap_file, elem));

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }

  struct list *lst;
  struct list_elem *e;

  /* Close all open files and file descriptor */
  lst = &cur->file_list;
  lock_acquire(&filesys_lock);
  file_close(cur->exec_file); /* Cancel the protect of executed files */
  for (e = list_begin(lst); e != list_end(lst); e = list_next(e))
    file_close(list_entry(e, struct file_fd, elem)->file);
  lock_release(&filesys_lock);
  while (!list_empty(lst))
    free(list_entry(list_pop_front(lst), struct file_fd, elem));

  printf("%s: exit(%d)\n", cur->name, cur->return_value);
  /* Set exit value, and release waiting semaphore */
  cur->cinfo->return_value = cur->return_value;
  sema_up(&cur->cinfo->wait_sema);

  /* As a child process, Check if 'child_info' needs freed*/
  try_free_cinfo(cur->cinfo, CHILD_EXIT);
  lst = &cur->child_list;
  e = list_begin(lst);
  while (e != list_end(lst))
  {
    struct list_elem *tmpe = list_next(e);
  /* As a parent process, Check if 'child_info' needs freed*/
    try_free_cinfo(list_entry(e, struct child_info, elem), PARENT_EXIT);
    e = tmpe;
  }
  return;
}

/** Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/** We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/** ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/** For use with ELF types in printf(). */
#define PE32Wx PRIx32   /**< Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /**< Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /**< Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /**< Print Elf32_Half in hexadecimal. */

/** Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/** Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/** Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /**< Ignore. */
#define PT_LOAD    1            /**< Loadable segment. */
#define PT_DYNAMIC 2            /**< Dynamic linking info. */
#define PT_INTERP  3            /**< Name of dynamic loader. */
#define PT_NOTE    4            /**< Auxiliary info. */
#define PT_SHLIB   5            /**< Reserved. */
#define PT_PHDR    6            /**< Program header table. */
#define PT_STACK   0x6474e551   /**< Stack segment. */

/** Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /**< Executable. */
#define PF_W 2          /**< Writable. */
#define PF_R 4          /**< Readable. */

static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/** Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open and protect executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }
  file_deny_write(file);
  t->exec_file = file;

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  t->stack_bound = *esp = PHYS_BASE - PGSIZE;
  if (!new_stack_page (PHYS_BASE - PGSIZE))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  return success;
}


/** Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/** Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Set the supplemental page table for lazy loading */
      if(!new_page(upage, writable, DISK, file, ofs, page_read_bytes))
        return false;

      /* Advance. */
      ofs += page_read_bytes;
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}
