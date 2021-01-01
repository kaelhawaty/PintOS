#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

/* A shared struct between the parent thread and the child thread which is created in the parent 
   thread's memory to act as a message box for the exit_status between it and the child. 
   
   It is contained in the parent thread as a element in a hashtable to quickly find a child thread with a 
   specific tid. Additionally, it exists in the child thread's struct so it is able to set the exit_status
   before it terminates. */
struct child {
    tid_t tid;
    struct thread *ptr;
    int exit_status;
    struct hash_elem child_elem;
};

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
unsigned hash_tid(const struct hash_elem *elem, void *aux UNUSED);
unsigned child_cmp(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
unsigned hash_fd(const struct hash_elem *elem, void *aux UNUSED);
unsigned fd_cmp(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);


#endif /* userprog/process.h */
