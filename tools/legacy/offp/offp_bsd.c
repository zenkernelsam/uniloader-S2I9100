#include <sys/proc_internal.h>
int off_proc_pid = offsetof(struct proc, p_pid);
int off_proc_comm = offsetof(struct proc, p_comm);
int off_proc_list = offsetof(struct proc, p_list);
int off_proc_task = offsetof(struct proc, task);
