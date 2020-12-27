#include "devices/shutdown.h"
#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#define GET_ARG(PTR, OFFSET) (validate_reference((void *)PTR + OFFSET) ? (*((int *)PTR + OFFSET)) : (sys_exit(-1), 0))

typedef int pid_t;

static void syscall_handler(struct intr_frame *);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

bool validate_reference(void *ptr)
{
  return pagedir_get_page(thread_current()->pagedir, ptr) != NULL;
}

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

static void
syscall_handler(struct intr_frame *f)
{
  if (!validate_reference(f->esp))
  {
    sys_exit(-1);
  }

  switch (GET_ARG(f->esp, 0))
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
  //sema_up(&thread_current()->wait_sema);
  thread_exit();
}

static pid_t
sys_exec(const char *cmd_line)
{
}

static int
sys_wait(pid_t pid)
{
}

static bool
sys_create(const char *file, unsigned initial_size)
{
}

static bool
sys_remove(const char *file)
{
}

static int
sys_open(const char *file)
{
}

static int
sys_file_size(int fd)
{
}

static int
sys_read(int fd, void *buffer, unsigned size)
{
}

static int
sys_write(int fd, const void *buffer, unsigned size)
{
  putbuf(buffer, size);
  return size;
}

static void
sys_seek(int fd, unsigned position)
{
}

static unsigned
sys_tell(int fd)
{
}

static void
sys_close(int fd)
{
}