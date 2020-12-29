#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <hash.h>

extern struct lock file_lock;
struct file_descriptor {
    int fd_num;
    struct hash_elem fd_elem;
    struct file *file;
};
unsigned hash_fd(const struct hash_elem *elem, void *aux UNUSED);
unsigned fd_cmp(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
void syscall_init (void);

#endif /* userprog/syscall.h */
