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

void 
syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
  fd_num = 2;
}

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

/* Validates user pointers as the kernel must be very careful about doing so, because the user can
   pass a null pointer, a pointer to unmapped virtual memory, or a pointer to kernel virtual
   address space (above PHYS_BASE). */
static bool 
validate(void *ptr) {
  return ptr != NULL && is_user_vaddr(ptr) && get_data(ptr) != ERROR;
}

/* Validates a block of memory by just validating the end pointer of the block which is 
   a necessary and sufficient condition. */
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

/* Returns a pointer to file descriptor struct with fd_num. */
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

/* Terminates Pintos by calling shutdown_power_off(). */
static void
sys_halt()
{
  shutdown_power_off();
  NOT_REACHED();
}

/* Terminates the current user program, returning status to the kernel. If the process’s
   parent waits for it (see below), this is the status that will be returned. Conventionally,
   a status of 0 indicates success and nonzero values indicate errors. */
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

/* Runs the executable whose name is given in cmd line, passing any given arguments,
   and returns the new process’s program id (pid). If the program cannot load or run for any reason,
   then pid -1 is returned. */
static pid_t
sys_exec(const char *cmd_line)
{
  validate_multiple(cmd_line, 4);
  return process_execute(cmd_line);
}

/* Waits for a child process pid and retrieves the child’s exit status. If PID is 
   invalid or if it was not a child of the calling process, or if process_wait() has already
   been successfully called for the given PID, returns -1 immediately, without waiting */
static int
sys_wait(pid_t pid)
{
  return process_wait(pid);
}

/* Creates a new file called file initially initial size bytes in size. Returns true if 
   successful, false otherwise. */
static bool
sys_create(const char *file, unsigned initial_size)
{
  validate_multiple(file, 4);
  lock_acquire(&file_lock);
  bool ans = filesys_create(file, initial_size);
  lock_release(&file_lock);
  return ans;
}

/* Deletes the file called file. Returns true if successful, false otherwise. A file may be
  removed regardless of whether it is open or closed, and removing an open file does
  not close it. */
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

/* Opens the file called file. Returns a nonnegative integer handle called a “file descrip-
   tor” (fd), or -1 if the file could not be opened. */
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

/* Returns the size, in bytes, of the file open as fd. */
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

/* Reads size bytes from the file open as fd into buffer. Returns the number of bytes
   actually read (0 at end of file), or -1 if the file could not be read (due to a condition
   other than end of file). Fd 0 reads from the keyboard using input_getc(). */
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

/* Writes size bytes from buffer to the open file fd. Returns the number of bytes actually
   written, which may be less than size if some bytes could not be written. */
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

/* Changes the next byte to be read or written in open file fd to position, expressed in
   bytes from the beginning of the file. (Thus, a position of 0 is the file’s start.) */
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

/* Returns the position of the next byte to be read or written in open file fd, expressed
   in bytes from the beginning of the file. */
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

/* Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open
   file descriptors, as if by calling this function for each one. */
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
