#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <hash.h>

#define ERROR -1

extern struct lock file_lock;
struct file_descriptor {
    int fd_num;
    struct hash_elem fd_elem;
    struct file *file;
};
void sys_exit(int status);
void syscall_init (void);

#endif /* userprog/syscall.h */
