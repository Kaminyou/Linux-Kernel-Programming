# 2021q3 Homework1 (quiz1)
A kernel module `hideproc` that can hide specific process ID. Please refer to [link](https://hackmd.io/@sysprog/linux2021-summer-quiz1) for the original problems.
## 0x00 Environment
1. Although `Linux v5.4` is recommened to utilized for this test, I used `Linux v4.06` and successfully build this testing kernel module. 
2. However, two errors (`implicit declaration of function 'kmalloc'` and `implicit declaration of function 'copy_to_user'`) should be solved by appending two corresponding header files.
```c
#include <linux/slab.h>
#include <linux/uaccess.h>
```
3. Fill the AAA to DDD with
```
AAA = list_for_each_entry_safe
BBB = list_for_each_entry_safe
CCC = list_add_tail(&proc->list_node, &hidden_proc)
DDD = list_del(&proc->list_node)
```
4. Then everything will go smoothly.
5. To solve problem 0x02. A VM of `Linux v5.8`  is leveraged.

## 0x01 Explain the source code as well as the utilization of `ftrace`
1. `ftrace_hook` can hook a given function and execute what hacker (developer) wants to do.
2. So the whole concept is simple! First, maintain a list to store the `pid` that are sepcified to be hidden. Second, hook the `find_ge_pid` function. Third, when `find_ge_pid` is called, if the given `pid` is in the maintained list, we return what we want to do (in the provided source code, return a`pid` that is returned by `real_find_ge_pid(pid->numbers->nr + 1, ns)`); otherwise, we just return the `pid`.
```c
static struct pid *hook_find_ge_pid(int nr, struct pid_namespace *ns)
{
    struct pid *pid = real_find_ge_pid(nr, ns);
    while (pid && is_hidden_proc(pid->numbers->nr))
        pid = real_find_ge_pid(pid->numbers->nr + 1, ns);
    return pid;
}
```
3. It can be inferred that `pidof` would call `find_ge_pid` and check the return struct `pid`. If the one is correct, then print the pid to stdout. If not, do nothing.


## 0x02 Provide a solution for newer linux kernel
1. An error of `ERROR: modpost: "kallsyms_lookup_name" [.../hideproc.ko] undefined!` would be generated.
2. The primary problem is that `kallsyms_lookup_name()` can be utilized as a backdoor to exploit any symbol (func. or data structures) in the kernel's symbol table via the returned address. Hence, it was removed.
3. With a github repo of [`kallsyms-mod`](https://github.com/h33p/kallsyms-mod), this limitation can be circumvented!
4. Clone the repo and copy required files:
```bash
git clone https://github.com/h33p/kallsyms-mod
cp kallsyms-mod{kallsyms_kp.c, kallsyms_lp.c, kallsyms.c, kallsyms.h, ksyms.h} /<path-to-main.c>/
```
5. Revise `main.c` referring to the provided sample in the repo:
- Append headers
```c
#include "kallsyms.h"
#include "ksyms.h"   
```
- Modify `_hideproc_init()`
```c
KSYMDEF(kvm_lock);
KSYMDEF(vm_list);

static int _hideproc_init(void)
{   
    int r;
    int err, dev_major;
    dev_t dev;

	if ((r = init_kallsyms()))
		return r;

	KSYMINIT_FAULT(kvm_lock);
	KSYMINIT_FAULT(vm_list);

	if (r)
		return r;

    printk(KERN_INFO "@ %s\n", __func__);
    ...

}
```
- Append the dependency in `Makefile`
```makefile
$(MODULENAME)-y += main.o kallsyms.o
```
7.  Then, everything will go smoothly.
## 0x03 Enable hiding PPID
1. Enable searching for the PPID given a PID
```c
static pid_t get_PPID_from_pid(pid_t pid)
{
    struct pid *pid_self;
    struct task_struct *t;
    pid_t ppid = 0;   
    pid_self = find_get_pid(pid);
    if (!pid_self)
		return ppid;
    t = get_pid_task(pid_self, PIDTYPE_PID);
    if (!t){
        put_pid(pid_self);
        return ppid;
        }
    ppid = task_pid_vnr(t->real_parent);
    if (!ppid) {
        put_task_struct(t);
        return ppid;
    }
    return ppid;
}
```
2. Append this function to the original `hide_process()`
```c
static int hide_process(pid_t pid)
{   
    pid_t ppid;
    pid_node_t *proc = kmalloc(sizeof(pid_node_t), GFP_KERNEL);
    proc->id = pid;
    list_add_tail(&proc->list_node, &hidden_proc);

    ppid = get_PPID_from_pid(pid);
    if (ppid){
        pid_node_t *proc = kmalloc(sizeof(pid_node_t), GFP_KERNEL);
        proc->id = ppid;
        list_add_tail(&proc->list_node, &hidden_proc);
    }
    return SUCCESS;
}
```
## 0x04 Improve the source code
1. Enable the releasing of all allocated resources
```c
static void _hideproc_exit(void)
{   
    printk(KERN_INFO "@ %s\n", __func__);
    /* FIXME: ensure the release of all allocated resources */    
    
    dev_t dev = (&cdev)->dev;
    device_destroy(hideproc_class, dev);
    cdev_del(&cdev);
    class_destroy(hideproc_class);
    unregister_chrdev_region(dev, MINOR_VERSION);
}
```
2. Initially, these is no validation for a given `pid` during `unhide_process` but merely expunge everything in the list. Add this validation.
```c
static int unhide_process(pid_t pid)
{
    pid_node_t *proc, *tmp_proc;
    pid_t ppid = get_PPID_from_pid(pid);
    list_for_each_entry_safe(proc, tmp_proc, &hidden_proc, list_node) {
        if ((pid == proc->id) || ((ppid) && (ppid == proc->id))){
            list_del(&proc->list_node);
            kfree(proc);
        }
    }
    return SUCCESS;
}
```