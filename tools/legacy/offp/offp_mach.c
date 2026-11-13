#include <kern/thread.h>
#include <kern/task.h>
int off_thread_task = offsetof(struct thread, task);
int off_task_bsdinfo = offsetof(struct task, bsd_info);
int off_task_map = offsetof(struct task, map);
