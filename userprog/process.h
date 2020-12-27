#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

struct child {
    tid_t tid;
    struct hash_elem child_elem;
    struct thread *ptr;
    int exit_status;
};

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
unsigned hash_tid(const struct hash_elem *elem, void *aux UNUSED);
unsigned child_cmp(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);

#endif /* userprog/process.h */
