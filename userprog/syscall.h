#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <hash.h>

#define ERROR -1
/* Lock used to ensure mutual exclusion for the file system. */
extern struct lock file_lock;
/* Contains fd_num which is a unique number for an image of the file and the file itself. 
   Each file in the system may have different fd_num for each process currently open it. */
struct file_descriptor {
    int fd_num;
    struct hash_elem fd_elem;
    struct file *file;
};
void sys_exit(int status);
void syscall_init (void);

#endif /* userprog/syscall.h */
