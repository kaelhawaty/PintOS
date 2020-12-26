#include "devices/shutdown.h"
#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#define get_arg(TYPE, OFFSET, PTR) (validate_reference((void*) PTR + OFFSET) ? (*((TYPE*) PTR + OFFSET)) : (sys_exit(-1), 0))

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

bool
validate_reference (void* ptr) {
  
  return pagedir_get_page(thread_current()->pagedir, ptr) != NULL;
}



void 
sys_halt () {
  
  shutdown_power_off();
  NOT_REACHED();
}


void 
sys_exit (int status) {
  
  //sema_up(&thread_current()->wait_sema);
  thread_exit ();
  
}


pid_t  
sys_exec (const char *cmd_line) {



}


int 
sys_wait (pid_t pid) {

}

bool 
sys_create (const char *file, unsigned initial_size) {

}


bool 
sys_remove (const char *file) {

}

int 
sys_open (const char *file) {

}


int 
sys_file_size (int fd) {

}

int
sys_read(int fd, void *buffer, unsigned size) {

}

int
sys_write(int fd, const void *buffer, unsigned size) {
    
  putbuf(buffer, size);
  return size;

}

void
sys_seek (int fd, unsigned position) {

}

unsigned
sys_tell (int fd) {

}

void 
sys_close (int fd) {

}

static void
syscall_handler(struct intr_frame *f)
{
  printf("system call!\n");

  if (!validate_reference(f->esp))
  {
    sys_exit(-1);
  }

  switch (*(int *)f->esp)
  {
  case SYS_HALT:
    sys_halt();
    break;

  case SYS_EXIT:

    int status = get_arg(int, 1, f->esp);
    sys_exit(status);

    break;

  case SYS_EXEC:

    char *cmd_line = get_arg(char *, 1, f->esp);
    f->eax = sys_exec(cmd_line);

    break;

  case SYS_WAIT:

    pid_t pid = get_arg(pid_t, 1, f->esp);
    f->eax = sys_wait(pid);

    break;

  case SYS_CREATE:

    char *file = get_arg(char *, 1, f->esp);
    unsigned init_size = get_arg(unsigned, 2, f->esp);
    f->eax = sys_create(file, init_size);

    break;

  case SYS_REMOVE:

    char *file = get_arg(char *, 1, f->esp);
    f->eax = sys_remove(file);

    break;

  case SYS_OPEN:

    char *file = get_arg(char *, 1, f->esp);
    f->eax = sys_open(file);
    break;

  case SYS_FILESIZE:

    int fd = get_arg(int, 1, f->esp);
    f->eax = sys_file_size(fd);

    break;

  case SYS_READ:

    int fd = get_arg(int, 1, f->esp);
    char *buffer = get_arg(char *, 2, f->esp);
    unsigned size = get_arg(unsigned, 3, f->esp);

    f->eax = sys_read(fd, buffer, size);

    break;

  case SYS_WRITE:

    int fd = get_arg(int, 1, f->esp);
    char *buffer = get_arg(char *, 2, f->esp);
    unsigned size = get_arg(unsigned, 3, f->esp);

    f->eax = sys_write(fd, buffer, size);

    break;

  case SYS_SEEK:

    int fd = get_arg(int, 1, f->esp);
    unsigned position = get_arg(unsigned, 2, f->esp);

    sys_seek(fd, position);

    break;

  case SYS_TELL:
    int fd = get_arg(int, 1, f->esp);
    f->eax = sys_tell(fd);
    break;

  case SYS_CLOSE:
    int fd = get_arg(int, 1, f->esp);
    sys_close(fd);
    break;

  default:
    break;
  }
}
