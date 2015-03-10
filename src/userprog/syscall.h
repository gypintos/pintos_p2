#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

struct lock filesys_lock;

struct file_info {
	struct file* fp;
	int fid;
	struct list_elem elem;
};

void syscall_init (void);

bool is_valid(void* vaddr);
void* user_to_kernel(int uaddr);
void get_args(struct intr_frame *f, int *args, int n);

void syscall_halt();
void syscall_exit(int status);
void syscall_exec(char* cmd);
void syscall_wait(pit_t pid);
bool syscall_create(const char* name, int init_size);
bool syscall_remove(const char* name);
int syscall_open(const char* name);
int syscall_filesize(int fid);
int syscall_read(int fid, void *buffer, unsigned size);
int syscall_write(int fid, const void* buffer, unsigned size);
void syscall_seek(int fid, unsigned new_pos);
int syscall_tell(int fid);
void syscall_close(int fid);

int process_add_file(struct file* fp);
struct file* get_file_by_id(int fid);
bool close_file_by_id(int fid);

#endif /* userprog/syscall.h */
