#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/timer.h"
#include "userprog/syscall.h"

/* Used as arguments wrapper for start_process. */
struct process_args {
  int len;
  char **command;
  bool status;
  struct semaphore wait_load;
};

static thread_func start_process NO_RETURN;
static bool load (struct process_args *args, void (**eip) (void), void **esp);

#define BUFF_SIZE 10    /* Initial buffer size for args */

/* Takes a command as string and splits into strings delimited by whitespaces which are returned as 
   char** -array of strings- dynamically resized to fit the number of arguments of any command.
   It additionally takes an integer pointer to return the number of arguments of the current command. */
char **parse_args(char *line, int *arg_length)
{
  // 2D-array to store the splits of line around white spaces.
  char **args = malloc(BUFF_SIZE * sizeof(char *));
  char *save_ptr;
  int curSize = BUFF_SIZE;
  ASSERT(args != NULL);
  char delimits[] = " \n'";
  int it = 0;
  char *token = strtok_r(line, delimits, &save_ptr);
  while (token != NULL)
  {
      args[it] = token;
      token = strtok_r(NULL, delimits, &save_ptr);

      it++;
      if (it == curSize)
      {
          // Vector implementation: Multiply each time the size by two and reallocate more memory.
          curSize *= 2;
          args = realloc(args, curSize * sizeof(char *));
          ASSERT(args != NULL);
      }
  }
  *arg_length = it;
  args[it] = NULL;
  return args;
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  ASSERT(file_name != NULL);
  
  /* Create a process_args struct 
  with parsed arguments and intialized semaphore to wait for child loading. */
  struct process_args args;
  args.command = parse_args(fn_copy, &args.len);
  sema_init(&args.wait_load, 0);
  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (args.command[0], PRI_DEFAULT, start_process, &args);

  /* Wait for child till it completes loading or fails,
  so that loading status can be returned to the parent process. */
  sema_down(&args.wait_load);
  
  /* If child loading fails. */
  if (!args.status) {
    return TID_ERROR;
  }
  return tid;
}

/* Hash function used to hash child struct. */
unsigned 
hash_tid(const struct hash_elem *elem, void *aux UNUSED) {
  const struct child *child = hash_entry(elem, struct child, child_elem);

  return hash_bytes(&child->tid, sizeof child->tid);
}

/* Comparator to compare between child structs according to their ID. */
unsigned 
child_cmp(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
  const struct child *child_a = hash_entry(a, struct child, child_elem);
  const struct child *child_b = hash_entry(b, struct child, child_elem);

  return child_a->tid < child_b->tid;
}


/* Hash function used to hash file_descriptor struct. */
unsigned 
hash_fd(const struct hash_elem *elem, void *aux UNUSED) {
  const struct file_descriptor *fd = hash_entry(elem, struct file_descriptor, fd_elem);
  return hash_bytes(&fd->fd_num, sizeof fd->fd_num);
}

/* Comparator to compare between file desscriptors according to their fd number. */
unsigned 
fd_cmp(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
  const struct file_descriptor *fd_a = hash_entry(a, struct file_descriptor, fd_elem);
  const struct file_descriptor *fd_b = hash_entry(b, struct file_descriptor, fd_elem);

  return fd_a->fd_num < fd_b->fd_num;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *args_)
{
  struct process_args *args = (struct process_args *) args_;
  struct intr_frame if_;
  bool *success = &args->status;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  *success = load (args, &if_.eip, &if_.esp);

  /* Wake up the parent since load is done. */
  sema_up(&args->wait_load);

  palloc_free_page (*args->command);
  free(args->command);

  /* If load failed, quit. */
  if (!*success)
    thread_exit ();

  /* Initialize the hash tables for open files and children. */
  #ifdef USERPROG
  hash_init(&thread_current()->children, hash_tid, child_cmp, NULL);
  hash_init(&thread_current()->opened_files, hash_fd, fd_cmp, NULL); 
  #endif
  
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting. */
int
process_wait (tid_t child_tid) 
{
  /* Get the record of the thread child_tid from children hashtable. */
  struct child temp;
  temp.tid = child_tid;
  struct hash_elem *elem = hash_find(&thread_current()->children, &temp.child_elem);
  
  /* If thread child_tid is not a direct child of the current thread. */
  if(elem == NULL) {
    return -1;
  }

  struct child *child = hash_entry(elem, struct child, child_elem);

  /* If the child->ptr is NULL means that the child terminated 
  and child struct is just a record. */  
  if(child->ptr != NULL) {
    sema_down(&(child->ptr->wait_child));
  }
  int exit_status = child->exit_status;
  hash_delete(&thread_current()->children, &child->child_elem);
  free(child);

  return exit_status;
}

void
child_free (struct hash_elem* elem, void* aux UNUSED)
{
  struct child *child = hash_entry(elem, struct child, child_elem);
  // Set pointers to NULL to indicate parent has died
  struct thread* thread = child->ptr;
  if (thread != NULL)
  {
    thread->parent = NULL;
    thread->self = NULL;
  }
  //free the memory
  free(child);
}

void
fd_free (struct hash_elem* elem, void* aux UNUSED)
{
  struct file_descriptor *fd = hash_entry(elem, struct file_descriptor, fd_elem);
  lock_acquire(&file_lock);
  file_close(fd->file);
  lock_release(&file_lock);
  free(fd);
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  sema_up(&thread_current()->wait_child);
  lock_acquire(&file_lock);
  file_close(thread_current()->exec_file);
  lock_release(&file_lock);

  /* Free up process allocated hashtable. */
  hash_destroy(&thread_current()->children, child_free);
  hash_destroy(&thread_current()->opened_files, fd_free);
  
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, char **args, int len);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (struct process_args *args, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  lock_acquire(&file_lock);
  file = filesys_open (args->command[0]);
  lock_release(&file_lock);

  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", args->command[0]);
      goto done; 
    }
    thread_current()->exec_file = file;
    /* Deny write to executable file. */
    file_deny_write(file);
  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", args->command[0]);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, args->command, args->len))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, char **args, int len) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
    if (success)
    {
      /* Writing each argument (including the executable name) in reverse order
         as well as in reverse for each string to the stack. Additionally
         we save the address of each string written. */
      int sum = 0;
      int address[len];
      for (int it = len - 1; it >= 0; it--)
      {
        int arg_len = strlen(args[it]) + 1;
        sum += arg_len;
        *esp -= arg_len;
        address[it] = *esp;
        memcpy(*esp, args[it], arg_len);
      }

      /* Writing necessary number of 0s to word alight to 4 bytes. */
      int padding_bytes = (4 - sum % 4) % 4;
      *esp -= padding_bytes;
      memset(*esp, 0, padding_bytes);

      /* The null pointer sentinel ensures that argv[argc] is a null pointer, as required
         by C standard. */
      *esp -= sizeof(int);
      memset(*esp, 0, sizeof(int));

      /* Write the addresses pointing to each of the arguments. */
      for (int it = len - 1; it >= 0; it--)
      {
        *esp -= sizeof(char *);
        memcpy(*esp, &address[it], sizeof(char *));
      }
      /* Write the address of argv[0]. This will be a char**. */
      *esp -= sizeof(char **);
      void *ptr = *esp + sizeof(char *);
      memcpy(*esp, &ptr, sizeof(char **));

      /* Write the number of arguments (argc). */
      *esp -= sizeof(int);
      memcpy(*esp, &len, sizeof(int));

      /* Write a NULL pointer as the return address. This will be a void*. */
      *esp -= sizeof(void *);
      memset(*esp, 0, sizeof(void *));
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
