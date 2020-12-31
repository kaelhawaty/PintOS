#include "devices/shutdown.h"
#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"

#define STDIN 0
#define STDOUT 1

typedef int pid_t;

struct lock file_lock;
int fd_num;

static void syscall_handler(struct intr_frame *);
static void sys_halt();
void sys_exit(int status);
static pid_t sys_exec(const char *cmd_line);
static int sys_wait(pid_t pid);
static bool sys_create(const char *file, unsigned initial_size);
static bool sys_remove(const char *file);
static int sys_open(const char *file);
static int sys_file_size(int fd_num);
static int sys_read(int fd_num, void *buffer, unsigned size);
static int sys_write(int fd_num, const void *buffer, unsigned size);
static void sys_seek(int fd_num, unsigned position);
static unsigned sys_tell(int fd_num);
static void sys_close(int fd_num);


/* Reads a byte at user virtual address UADDR.
UADDR must be below PHYS_BASE.
Returns the byte value if successful, -1 if a segfault
occurred. */
static int
get_data (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
  : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
UDST must be below PHYS_BASE.
Returns true if successful, false if a segfault occurred. */
static bool
put_data (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
  : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}


void 
syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
  fd_num = 2;
}

static bool 
validate(void *ptr) {
  return ptr != NULL && is_user_vaddr(ptr) && get_data(ptr) != ERROR;
}

static void 
validate_multiple(void *ptr, int size) {
  char *temp = ptr;
  if (!validate(temp + size - 1)) {
    sys_exit(ERROR);
  }
}

static int 
GET_ARG(void *ptr, int offset)
{
  int *temp = (int*) ptr + offset;
  validate_multiple(temp, 4);
  return *temp;
}


static void
syscall_handler(struct intr_frame *f)
{
  switch ((int)GET_ARG(f->esp, 0))
  {
  case SYS_HALT:
    sys_halt();
    break;
  case SYS_EXIT:
    sys_exit(GET_ARG(f->esp, 1));
    break;
  case SYS_EXEC:
    f->eax = sys_exec(GET_ARG(f->esp, 1));
    break;
  case SYS_WAIT:
    f->eax = sys_wait(GET_ARG(f->esp, 1));
    break;
  case SYS_CREATE:
    f->eax = sys_create(GET_ARG(f->esp, 1), GET_ARG(f->esp, 2));
    break;
  case SYS_REMOVE:
    f->eax = sys_remove(GET_ARG(f->esp, 1));
    break;
  case SYS_OPEN:
    f->eax = sys_open(GET_ARG(f->esp, 1));
    break;
  case SYS_FILESIZE:
    f->eax = sys_file_size(GET_ARG(f->esp, 1));
    break;
  case SYS_READ:
    f->eax = sys_read(GET_ARG(f->esp, 1), GET_ARG(f->esp, 2), GET_ARG(f->esp, 3));
    break;
  case SYS_WRITE:
    f->eax = sys_write(GET_ARG(f->esp, 1), GET_ARG(f->esp, 2), GET_ARG(f->esp, 3));
    break;
  case SYS_SEEK:
    sys_seek(GET_ARG(f->esp, 1), GET_ARG(f->esp, 2));
    break;
  case SYS_TELL:
    f->eax = sys_tell(GET_ARG(f->esp, 1));
    break;
  case SYS_CLOSE:
    sys_close(GET_ARG(f->esp, 1));
    break;
  default:
    break;
  }
}

/* Get pointer to file descriptor struct with fd_num. */
struct 
file_descriptor *get_fd(int fd_num) {
  struct file_descriptor key;
  key.fd_num = fd_num;
  struct hash_elem *fd_elem = hash_find(&thread_current()->opened_files, &key.fd_elem);
  if (fd_elem == NULL) {
    return NULL;
  }
  struct file_descriptor *fd = hash_entry(fd_elem, struct file_descriptor, fd_elem);
  return fd;
}

static void
sys_halt()
{
  shutdown_power_off();
  NOT_REACHED();
}

void
sys_exit(int status)
{
  printf("%s: exit(%d)\n", thread_current()->name, status);
  if(thread_current()->self != NULL)
  {
    thread_current()->self->exit_status = status;
    thread_current()->self->ptr =NULL;
  }
  thread_exit();
  NOT_REACHED();
}

static pid_t
sys_exec(const char *cmd_line)
{
  validate_multiple(cmd_line, 4);
  return process_execute(cmd_line);
}

static int
sys_wait(pid_t pid)
{
  return process_wait(pid);
}

static bool
sys_create(const char *file, unsigned initial_size)
{
  validate_multiple(file, 4);
  lock_acquire(&file_lock);
  bool ans = filesys_create(file, initial_size);
  lock_release(&file_lock);
  return ans;
}

static bool
sys_remove(const char *file)
{
  validate_multiple(file, 4);
  
  bool success;
  lock_acquire(&file_lock);
  success = filesys_remove(file);
  lock_release(&file_lock);

  return success;
}

static int
sys_open(const char *file_name)
{
  validate_multiple(file_name, 4);
  lock_acquire(&file_lock);
  struct file *file = filesys_open(file_name);
  lock_release(&file_lock);
  if (file == NULL) {
    return ERROR;
  }
  struct file_descriptor *fd = malloc(sizeof(struct file_descriptor));
  fd->file = file;
  fd->fd_num = fd_num++;
  hash_insert(&thread_current()->opened_files, &fd->fd_elem);
  return fd->fd_num;
}

static int
sys_file_size(int fd_num)
{
  struct file_descriptor *fd = get_fd(fd_num);
  if (fd == NULL) {
    return ERROR;
  }
  lock_acquire(&file_lock);
  int ans = file_length(fd->file);
  lock_release(&file_lock);
  return ans;
}

static int
sys_read(int fd_num, void *buffer, unsigned size)
{
  validate_multiple(buffer, size);
  if (fd_num == STDIN) {
    input_getc(buffer, size);
    return size;
  }
  else if (fd_num == STDOUT) {
    /* Can't read from the STDOUT. */
    return 0;
  }
  struct file_descriptor *fd = get_fd(fd_num);
  if (fd == NULL) {
    return ERROR;
  }
  lock_acquire(&file_lock);
  int ans = file_read(fd->file, buffer, size);
  lock_release(&file_lock);
  return ans;
}

static int
sys_write(int fd_num, const void *buffer, unsigned size)
{
  validate_multiple(buffer, size);
  if (fd_num == STDIN) {
    /* Can't write to the STDIN. */
    return 0;
  }
  else if (fd_num == STDOUT) {
    putbuf(buffer, size);
    return size;
  }
  struct file_descriptor *fd = get_fd(fd_num);
  if (fd == NULL) {
    return ERROR;
  }
  lock_acquire(&file_lock);
  int ans = file_write(fd->file, buffer, size);
  lock_release(&file_lock);
  return ans;
}

static void
sys_seek(int fd_num, unsigned position)
{
  struct file_descriptor *fd = get_fd(fd_num);
  if (fd == NULL) {
    return;
  }
  lock_acquire(&file_lock);
  file_seek(fd->file, position);
  lock_release(&file_lock);
}

static unsigned
sys_tell(int fd_num)
{
  struct file_descriptor *fd = get_fd(fd_num);
  if (fd == NULL) {
    return ERROR;
  }
  lock_acquire(&file_lock);
  file_tell(fd->file);
  lock_release(&file_lock);
}

static void
sys_close(int fd_num)
{
  struct file_descriptor *fd = get_fd(fd_num);
  if (fd == NULL) {
    return ERROR;
  }
  lock_acquire(&file_lock);
  file_close(fd->file);
  lock_release(&file_lock);
  hash_delete(&thread_current()->opened_files, &fd->fd_elem);
  free(fd);
}
