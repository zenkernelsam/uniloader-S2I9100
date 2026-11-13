#include <kern/thread.h>
#include <kern/task.h>
#include <sys/proc_internal.h>
int off_thread_task = offsetof(struct thread, task);
int off_task_bsdinfo = offsetof(struct task, bsd_info);
int off_proc_pid = offsetof(struct proc, p_pid);
int off_proc_comm = offsetof(struct proc, p_comm);
int off_proc_list = offsetof(struct proc, p_list);
int off_proc_task = offsetof(struct proc, task);
