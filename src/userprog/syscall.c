#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
}

static void syscall_handler (struct intr_frame *f) 
{
	if (!is_valid(f->esp)) 
		syscall_exit(-1);
	user_to_kernel(f->esp);
	int syscall_int = *(int *) f->esp;
	int args[3];
	switch(syscall_int)
	{
		case SYS_HALT:
			syscall_halt();
			break;
		case SYS_EXIT:
			get_args(f,args,1);
			syscall_exit(args[0]);
			break;
		case SYS_EXEC:
			get_args(f,args,1);
			args[0] = user_to_kernel(args[0]);
			f->eax = syscall_exec((char *) args[0]);
			break;
		case SYS_WAIT:
			get_args(f,args,1);
			f->eax = syscall_wait(args[0]);
			break;
		case SYS_CREATE:
			get_args(f,args,2);
			args[0] = user_to_kernel((const void*) args[0]);
			f->eax = syscall_create((const char*) args[0], (unsigned) args[1]);
			break;
		case SYS_REMOVE:
			get_args(f,args,1);
			args[0] = user_to_kernel(args[0]);
			f->eax = syscall_remove((char *)args[0]);
			break;
		case SYS_OPEN:
			get_args(f,args,1);
			args[0] = user_to_kernel(args[0]);
			f->eax = syscall_open((char *)args[0]);
			break;
		case SYS_FILESIZE:
			get_args(f,args,1);
			f->eax = syscall_filesize(args[0]);
			break;
		case SYS_READ:
			get_args(f,args,3);
			buffer_validate((void *) args[1], (unsigned) args[2]);
			args[1] = user_to_kernel(args[1]);
			f->eax = syscall_read(args[0], (void *)args[1], (unsigned)args[2]);
			break;
		case SYS_WRITE:
			get_args(f,args,3);
			buffer_validate((void *) args[1], (unsigned) args[2]);
			args[1] = user_to_kernel(args[1]);
			f->eax = syscall_write(args[0], (void *)args[1], (unsigned)args[2]);
			break;
		case SYS_SEEK:
			get_args(f,args,2);
			syscall_seek(args[0], (unsigned)args[1]);
			break;
		case SYS_TELL:
			get_args(f,args,1);
			f->eax = syscall_tell(args[0]);
			break;
		case SYS_CLOSE:
			get_args(f,args,1);
			syscall_close(args[0]);
			break;
		default:
			break; 
	}
}

/* Return true if given vaddr is vadlidated */
bool is_valid(void* vaddr)
{
	return (is_user_vaddr(vaddr) && vaddr >= (void *) 0x08048000);
}

void buffer_validate (void* buffer, unsigned size)
{
  char* buff = (char *) buffer;
  int i;
  for (i = 0; i < size; i++)
    {
      if (!is_valid((const void*) buff)){
      	syscall_exit(-1);
      }
      buff++;
    }
}

void* user_to_kernel(void* uaddr)
{
	void* kaddr;
	if(!is_valid(uaddr))
		syscall_exit(-1);
	kaddr = pagedir_get_page(thread_current()->pagedir,uaddr);
	if (kaddr == NULL)
		syscall_exit(-1);
	return kaddr;
}

void get_args(struct intr_frame *f, int *args, int n)
{
	ASSERT(n <= 3);
	int i;
  	int *ptr;
  	for (i = 0; i < n; i++)
  	{
		ptr = (int *) f->esp + i + 1;
		if (!is_valid(ptr)) 
			syscall_exit(-1);
		args[i] = *ptr;
//printf("arg%d = %d\n",i,args[i]);
	}
}

void syscall_halt()
{
	shutdown_power_off();
}
void syscall_exit(int status)
{
	struct thread *curr = thread_current();
	curr->child_process->status = status;
	curr->child_process->child_status = status < 0 ? KILLED : EXIT;

	//debug
	printf("%s: exit(%d)\n", curr->name, status);

	if (curr->exec_file)
	{
		lock_acquire(&filesys_lock);
		file_close(curr->exec_file);
		lock_release(&filesys_lock);
	}
	thread_exit();
}

pid_t syscall_exec(char* cmd)
{
	pid_t pid = process_execute(cmd);
	struct child_process *cp = get_child(pid);
	while (cp->load_status == NOT_LOADED)
	{
		barrier();

	}
	if (cp->load_status == LOAD_FAIL)
		return -1;
	return pid;
}

int syscall_wait(pid_t pid)
{
	return process_wait(pid);
}

bool syscall_create(const char* name, int init_size)
{
	if (name == NULL) syscall_exit(-1);
	lock_acquire(&filesys_lock);
	bool result = filesys_create(name, init_size);
	lock_release(&filesys_lock);
	return result;
}

bool syscall_remove(const char* name)
{
	lock_acquire(&filesys_lock);
	bool result = filesys_remove(name);
	lock_release(&filesys_lock);
	return result;
}

int syscall_open(const char* name)
{
	lock_acquire(&filesys_lock);
	struct file* fp = filesys_open(name);
	if (!fp){
		lock_release(&filesys_lock);
		return -1;
	}
	int fid = process_add_file(fp);
	lock_release(&filesys_lock);
	return fid;
}

int process_add_file(struct file* fp){
	struct thread* curr = thread_current();
	struct file_info* fi = malloc(sizeof(struct file_info));
	fi->fid = curr->f_num;
	curr->f_num++;
	fi->fp = fp;
	list_push_back(&curr->file_list, &fi->elem);
	return fi->fid;
}

int syscall_filesize(int fid)
{
	lock_acquire(&filesys_lock);
	struct file* fp = get_file_by_id(fid);
	if (!fp){
		lock_release(&filesys_lock);
		return -1;
	}
	int fileLen = file_length(fp);
	lock_release(&filesys_lock);
	return fileLen;
}


struct file* get_file_by_id(int fid){
	struct list *f_list = &thread_current()->file_list;
	struct list_elem* e;
	for (e = list_begin(f_list); e!=list_end(f_list); e=list_next(e)){
		struct file_info* file_info = list_entry(e, struct file_info, elem);
		if (fid == file_info->fid){
			return file_info->fp;
		}
	}
	return NULL;
}

int syscall_read(int fid, void *buffer, unsigned size)
{
	if (fid == STDIN_FILENO){
		int i;
		char* buf = buffer;
		for (i=0; i<size; i++){
			buf[i] = input_getc();
		}
		return size;
	} else {
		lock_acquire(&filesys_lock);
		struct file* fp = get_file_by_id(fid);
		if (!fp){
			lock_release(&filesys_lock);
			return -1;
		}
		int result = file_read(fp,buffer, size);
		lock_release(&filesys_lock);
		return result;
	}
}

int syscall_write(int fid, const void* buffer, unsigned size)
{
	if (fid == STDOUT_FILENO){
		putbuf(buffer,size);
		return size;
	} else {
		lock_acquire(&filesys_lock);
		struct file* fp = get_file_by_id(fid);
		if (!fp){
			lock_release(&filesys_lock);
			return -1;
		} 
		int result = file_write(fp, buffer, size);
		lock_release(&filesys_lock);
		return result;
	}
}


void syscall_seek(int fid, unsigned new_pos)
{
	lock_acquire(&filesys_lock);
	struct file* fp = get_file_by_id(fid);
	if (!fp){
		lock_release(&filesys_lock);
		return;
	}
	file_seek(fp,new_pos);
	lock_release(&filesys_lock);
}

int syscall_tell(int fid)
{
	lock_acquire(&filesys_lock);
	struct file* fp = get_file_by_id(fid);
	if (!fp){
		lock_release(&filesys_lock);
		return -1;
	}
	unsigned pos = file_tell(fp);
	lock_release(&filesys_lock);
	return pos;
}

void syscall_close(int fid)
{
	lock_acquire(&filesys_lock);
	close_file_by_id(fid);
	lock_release(&filesys_lock);
}

void close_file_by_id(int fid){
	struct list* file_list = &thread_current()->file_list;
	struct list_elem *e;
	for (e = list_begin(file_list); e != list_end(file_list); e = list_next(file_list)){
		struct file_info* file_info = list_entry(e, struct file_info, elem);
		if (fid == file_info->fid || fid == -1){ // -1 means close all files
			file_close(file_info->fp);
			list_remove(e);
			free(file_info);
			if (fid != -1)
				return;
		}
	}
}
