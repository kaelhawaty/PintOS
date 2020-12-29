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
#define ERROR -1
#define STDIN 0
#define STDOUT 1

typedef int pid_t;

struct lock file_lock;
int fd_num;

static void syscall_handler(struct intr_frame *);
static void sys_halt();
static void sys_exit(int status);
static pid_t sys_exec(const char *cmd_line);
static int sys_wait(pid_t pid);
static bool sys_create(const char *file, unsigned initial_size);
static bool sys_remove(const char *file);
static int sys_open(const char *file);
static int sys_file_size(int fd);
static int sys_read(int fd, void *buffer, unsigned size);
static int sys_write(int fd, const void *buffer, unsigned size);
static void sys_seek(int fd, unsigned position);
static unsigned sys_tell(int fd);
static void sys_close(int fd);

unsigned hash_fd(const struct hash_elem *elem, void *aux UNUSED) {
  const struct file_descriptor *fd = hash_entry(elem, struct file_descriptor, fd_elem);
  return hash_bytes(&fd->fd_num, sizeof fd->fd_num);
}

unsigned fd_cmp(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
  const struct file_descriptor *fd_a = hash_entry(a, struct file_descriptor, fd_elem);
  const struct file_descriptor *fd_b = hash_entry(b, struct file_descriptor, fd_elem);

  return fd_a->fd_num < fd_b->fd_num;
}

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
  fd_num = 2;
}

static bool validate(void *ptr) {
  return is_user_vaddr(ptr) && pagedir_get_page(thread_current()->pagedir, ptr) != NULL;
}

static void validate_multiple(void *ptr, int size) {
  char *temp = ptr;
  for(int i = 0; i < size; i++){
    if(!validate(temp + i)){
      sys_exit(ERROR);
    }
  }
}

static int GET_ARG(void *ptr, int offset)
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

struct file_descriptor *get_fd(int fd_num) {
  struct file_descriptor key;
  key.fd_num = fd_num;
  struct hash_elem *fd_elem = hash_find(&thread_current()->opened_files, &key.fd_elem);
  if (!fd_elem) {
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

static void
sys_exit(int status)
{
  printf("%s: exit(%d)\n", thread_current()->name, status);
  if(thread_current()->self != NULL)
  {
    thread_current()->self->exit_status = status;
    thread_current()->self->ptr =NULL;
  }
  sema_up(&thread_current()->wait_child);
  lock_acquire(&file_lock);
  file_close(thread_current()->exec_file);
  lock_release(&file_lock);
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
  if (fd_num == STDOUT) {
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
    return ERROR;
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
