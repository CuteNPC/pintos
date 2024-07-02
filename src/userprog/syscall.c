#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/input.h"
#include "vm/page.h"

#define SYSCALL_MAX 20
typedef void syscall_handler_func(int *, int *);

/** Function pointer, used to find the corresponding system call handler */
static syscall_handler_func *syscall_handler_ptr[SYSCALL_MAX];

/** The number of parameters required for each function. */
const int arg_num[SYSCALL_MAX] =
    {0, 1, 1, 1, 2, 1, 1, 1, 3, 3, 2, 1, 1, 2, 1, 1, 1, 2, 1, 1};

static void syscall_handler(struct intr_frame *);
static void syscall_handler_error(void);
static int test_args(void *esp);
static void test_read(char *str);
static void test_read_size(char *str, int size);
static void test_write_size(char *str, int size);
static void set_pinned(void *addr, int size, bool pinned);
static void syscall_handler_halt(int *, int *);
static void syscall_handler_exit(int *, int *);
static void syscall_handler_exec(int *, int *);
static void syscall_handler_wait(int *, int *);
static void syscall_handler_create(int *, int *);
static void syscall_handler_remove(int *, int *);
static void syscall_handler_open(int *, int *);
static void syscall_handler_filesize(int *, int *);
static void syscall_handler_read(int *, int *);
static void syscall_handler_write(int *, int *);
static void syscall_handler_seek(int *, int *);
static void syscall_handler_tell(int *, int *);
static void syscall_handler_close(int *, int *);
static void syscall_handler_mmap(int *, int *);
static void syscall_handler_munmap(int *, int *);
static void syscall_handler_chdir(int *, int *);
static void syscall_handler_mkdir(int *, int *);
static void syscall_handler_readdir(int *, int *);
static void syscall_handler_isdir(int *, int *);
static void syscall_handler_inumber(int *, int *);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  syscall_handler_ptr[SYS_HALT] = syscall_handler_halt;
  syscall_handler_ptr[SYS_EXIT] = syscall_handler_exit;
  syscall_handler_ptr[SYS_EXEC] = syscall_handler_exec;
  syscall_handler_ptr[SYS_WAIT] = syscall_handler_wait;
  syscall_handler_ptr[SYS_CREATE] = syscall_handler_create;
  syscall_handler_ptr[SYS_REMOVE] = syscall_handler_remove;
  syscall_handler_ptr[SYS_OPEN] = syscall_handler_open;
  syscall_handler_ptr[SYS_FILESIZE] = syscall_handler_filesize;
  syscall_handler_ptr[SYS_READ] = syscall_handler_read;
  syscall_handler_ptr[SYS_WRITE] = syscall_handler_write;
  syscall_handler_ptr[SYS_SEEK] = syscall_handler_seek;
  syscall_handler_ptr[SYS_TELL] = syscall_handler_tell;
  syscall_handler_ptr[SYS_CLOSE] = syscall_handler_close;
  syscall_handler_ptr[SYS_MMAP] = syscall_handler_mmap;
  syscall_handler_ptr[SYS_MUNMAP] = syscall_handler_munmap;
  syscall_handler_ptr[SYS_CHDIR] = syscall_handler_chdir;
  syscall_handler_ptr[SYS_MKDIR] = syscall_handler_mkdir;
  syscall_handler_ptr[SYS_READDIR] = syscall_handler_readdir;
  syscall_handler_ptr[SYS_ISDIR] = syscall_handler_isdir;
  syscall_handler_ptr[SYS_INUMBER] = syscall_handler_inumber;
}

static void
syscall_handler(struct intr_frame *f)
{
  int syscall_no = test_args(f->esp);
  syscall_handler_ptr[syscall_no]((int *)f->esp, (int *)&f->eax);
}

static void
syscall_handler_error(void)
{
  thread_current()->return_value = -1;
  thread_exit();
}

/* Test whether system call number legal
   Test whether the argument address is user address space */
static int
test_args(void *esp)
{
  int syscall_no = *(int *)esp;
  if (syscall_no < 0 ||
      syscall_no >= SYSCALL_MAX ||
      esp >= PHYS_BASE ||
      esp + arg_num[syscall_no] * 4 + 3 >= PHYS_BASE)
    syscall_handler_error();
  return syscall_no;
}

/* Test whether the string is readable */
static void
test_read(char *str)
{
  if ((void *)str >= PHYS_BASE)
    syscall_handler_error();
  /* Try to read*/
  while (*str)
    str++;
  if ((void *)str >= PHYS_BASE)
    syscall_handler_error();
}

/* Test whether the memory space is readable */
static void
test_read_size(char *str, int size)
{
  int result;
  if ((void *)str >= PHYS_BASE || (void *)str + size - 1 >= PHYS_BASE)
    syscall_handler_error();
  for (char *p = str; p != str + size; p++)
  {
  /* Try to read*/
    asm("movl $1f, %0; movzbl %1, %0; 1:"
        : "=&a"(result)
        : "m"(*p));
  }
}

/* Test whether the memory space is writable */
static void
test_write_size(char *str, int size)
{
  if ((void *)str >= PHYS_BASE || (void *)str + size - 1 >= PHYS_BASE)
    syscall_handler_error();
  /* Try to write*/
  for (int i = 0; i < size; i++)
    str[i] = 0;
}

/* Pin the page or cancel the pinning, prevent it from eviction */
static void set_pinned(void *addr, int size, bool pinned)
{
  if(size <= 0)
    return;
  void *page = pg_round_down(addr);
  while(page < addr + size)
  {
    struct page *p = get_entry(page);
    if(!p)
      syscall_handler_error();
    p->pinned += (pinned ? 1 : -1);
    page += PGSIZE;
  }
  return;
}

/* The following are the functions that handle system calls */

static void
syscall_handler_halt(int *esp UNUSED, int *eax UNUSED)
{
  shutdown_power_off();
}

static void
syscall_handler_exit(int *esp, int *eax UNUSED)
{
  int status = esp[1];
  thread_current()->return_value = status;
  thread_exit();
}

static void
syscall_handler_exec(int *esp, int *eax)
{
  char *file = (char *)esp[1];
  test_read(file);
  *eax = process_execute(file);
}

static void
syscall_handler_wait(int *esp, int *eax)
{
  int pid = esp[1];
  *eax = process_wait(pid);
}

static void
syscall_handler_create(int *esp, int *eax)
{
  char *file = (char *)esp[1];
  unsigned initial_size = (unsigned)esp[2];
  test_read(file);
  lock_acquire(&filesys_lock);
  *eax = filesys_create(file, initial_size);
  lock_release(&filesys_lock);
}

static void
syscall_handler_remove(int *esp, int *eax)
{
  char *file = (char *)esp[1];
  test_read(file);
  lock_acquire(&filesys_lock);
  *eax = filesys_remove(file);
  lock_release(&filesys_lock);
}

static void
syscall_handler_open(int *esp, int *eax)
{
  char *file = (char *)esp[1];
  test_read(file);
  *eax = -1;
  lock_acquire(&filesys_lock);
  struct file *fp = filesys_open(file);
  lock_release(&filesys_lock);
  if (!fp)
    return;
  *eax = allocate_fd(fp);
}

static void
syscall_handler_filesize(int *esp, int *eax)
{
  int fd = esp[1];
  struct file *fp = fd_to_fp(fd);
  if (!fp)
    syscall_handler_error();
  lock_acquire(&filesys_lock);
  *eax = file_length(fp);
  lock_release(&filesys_lock);
}

static void
syscall_handler_read(int *esp, int *eax)
{
  int fd = esp[1];
  char *buffer = (void *)esp[2];
  unsigned size = (unsigned)esp[3];
  test_write_size(buffer, size);
  set_pinned(buffer, size, true); // pinning
  if (fd == 0)
  {
    for (uint32_t i = 0; i < size; i++)
      buffer[i] = (char)input_getc();
    *eax = size;
  }
  else if (fd == 1)
    syscall_handler_error();
  else
  {
    struct file *fp = fd_to_fp(fd);
    if (!fp)
      syscall_handler_error();
    lock_acquire(&filesys_lock);
    *eax = file_read(fp, buffer, size);
    lock_release(&filesys_lock);
  }
  set_pinned(buffer, size, false); // not pinning
}

static void
syscall_handler_write(int *esp, int *eax)
{
  int fd = esp[1];
  char *buffer = (void *)esp[2];
  unsigned size = (unsigned)esp[3];
  test_read_size(buffer, size);
  set_pinned(buffer, size, true); // pinning
  if (fd == 0)
    syscall_handler_error();
  else if (fd == 1)
  {
    putbuf(buffer, size);
    *eax = size;
  }
  else
  {
    struct file *fp = fd_to_fp(fd);
    if (!fp)
      syscall_handler_error();
    lock_acquire(&filesys_lock);
    *eax = file_write(fp, buffer, size);
    lock_release(&filesys_lock);
  }
  set_pinned(buffer, size, false); // not pinning
}

static void
syscall_handler_seek(int *esp, int *eax UNUSED)
{
  int fd = esp[1];
  unsigned position = (unsigned)esp[2];
  struct file *fp = fd_to_fp(fd);
  if (!fp)
    syscall_handler_error();
  lock_acquire(&filesys_lock);
  file_seek(fp, position);
  lock_release(&filesys_lock);
}

static void
syscall_handler_tell(int *esp, int *eax)
{
  int fd = esp[1];
  struct file *fp = fd_to_fp(fd);
  if (!fp)
    syscall_handler_error();
  lock_acquire(&filesys_lock);
  *eax = file_tell(fp);
  lock_release(&filesys_lock);
}

static void
syscall_handler_close(int *esp, int *eax UNUSED)
{
  int fd = esp[1];
  struct file *fp = fd_to_fp(fd);
  if (!fp)
    syscall_handler_error();
  lock_acquire(&filesys_lock);
  file_close(fp);
  lock_release(&filesys_lock);
  free_fd(fd);
}

static void
syscall_handler_mmap(int *esp UNUSED, int *eax UNUSED)
{
  printf("Not implemented yet!\n");
  thread_exit();
}

static void
syscall_handler_munmap(int *esp UNUSED, int *eax UNUSED)
{
  printf("Not implemented yet!\n");
  thread_exit();
}

static void
syscall_handler_chdir(int *esp UNUSED, int *eax UNUSED)
{
  printf("Not implemented yet!\n");
  thread_exit();
}

static void
syscall_handler_mkdir(int *esp UNUSED, int *eax UNUSED)
{
  printf("Not implemented yet!\n");
  thread_exit();
}

static void
syscall_handler_readdir(int *esp UNUSED, int *eax UNUSED)
{
  printf("Not implemented yet!\n");
  thread_exit();
}

static void
syscall_handler_isdir(int *esp UNUSED, int *eax UNUSED)
{
  printf("Not implemented yet!\n");
  thread_exit();
}

static void
syscall_handler_inumber(int *esp UNUSED, int *eax UNUSED)
{
  printf("Not implemented yet!\n");
  thread_exit();
}
