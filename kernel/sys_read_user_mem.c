#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/pid.h>
#include <linux/security.h>
#include <linux/pid_types.h>

SYSCALL_DEFINE4(read_user_mem, pid_t, pid, void __user *, addr, size_t, len, void __user *, buf) {
    struct task_struct *task;
    struct mm_struct *mm;
    void *kernel_buffer;
    int ret = -EFAULT;

    printk("read_user_mem\tpid: %u\t addr: 0x%x\tlen: %u\t buf: 0x%x\n", pid, addr, len, buf);

    // Check if the current process has the right permissions
    if (!capable(CAP_SYS_ADMIN))
        return -EPERM;

    // Find the target process
    task = get_pid_task(find_get_pid(pid), PIDTYPE_PID);
    if (!task)
        return -ESRCH;

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return -EFAULT;
    }

    // Allocate kernel buffer
    kernel_buffer = kmalloc(len, GFP_KERNEL);
    if (!kernel_buffer) {
        mmput(mm);
        put_task_struct(task);
        return -ENOMEM;
    }

    // Lock memory and read from user address space
    down_read(&mm->mmap_lock);
    if (access_process_vm(task, (unsigned long)addr, kernel_buffer, len, 0) == len) {
        ret = copy_to_user(buf, kernel_buffer, len) ? -EFAULT : 0;
    }
    up_read(&mm->mmap_lock);

    kfree(kernel_buffer);
    mmput(mm);
    put_task_struct(task);

    return ret;
}

SYSCALL_DEFINE4(write_user_mem, pid_t, pid, void __user *, addr, size_t, len, void __user *, buf) {
    struct task_struct *task;
    struct mm_struct *mm;
    void *kernel_buffer;
    int ret = -EFAULT;
    
    printk("write_user_mem\tpid: %u\t addr: 0x%x\tlen: %u\t buf: 0x%x\n", pid, addr, len, buf);

    // Check if the current process has the right permissions
    if (!capable(CAP_SYS_ADMIN))
        return -EPERM;

    // Find the target process
    task = get_pid_task(find_get_pid(pid), PIDTYPE_PID);
    if (!task)
        return -ESRCH;

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return -EFAULT;
    }

    // Allocate kernel buffer
    kernel_buffer = kmalloc(len, GFP_KERNEL);
    if (!kernel_buffer) {
        mmput(mm);
        put_task_struct(task);
        return -ENOMEM;
    }

    // Lock memory and read from user address space
    down_write(&mm->mmap_lock);
    if (copy_from_user(kernel_buffer, buf, sizeof(void *)) == 0) {
        ret = access_process_vm(task, (unsigned long)addr, kernel_buffer, sizeof(void *), 1) == sizeof(void *) ? 0 : -EFAULT;
    }
    up_write(&mm->mmap_lock);

    kfree(kernel_buffer);
    mmput(mm);
    put_task_struct(task);

    return ret;
}


SYSCALL_DEFINE3(get_vma_base, pid_t, pid, unsigned char __user *, filename, size_t, filename_len, void __user **, base_address) {
    char *k_filename;
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;

    // Check if the current process has the right permissions
    if (!capable(CAP_SYS_ADMIN))
        return -EPERM;

    task = get_pid_task(pid);
    if (!task || !task->mm) {
        kfree(k_filename);
        return -ESRCH;  // No task or no memory mapping
    }

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return -EFAULT;
    }

    k_filename = kmalloc(filename_len, GFP_KERNEL);
    if (!k_filename) return -ENOMEM;

    down_read(&mm->mmap_lock);
    if (copy_from_user(k_filename, filename, filename_len)) return -EFAULT;
    up_read(&mm->mmap_lock);

    vma = task->mm->mmap;

    while (vma != NULL) {
	printk("[%lx-%lx]: %s\n", vma->vm_start, vma->vm_end, vma->vm_file ? vma->vm_file->f_path.dentry->d_name.name : NULL);
	if (vma->vm_file && strcmp(vma->vm_file->f_path.dentry->d_name.name, filename) == 0) {
	    kfree(k_filename);
	    down_write(&mm->mmap_lock);
	    if (copy_to_user(base_address, &vma->vm_start, sizeof(void*))) return -EFAULT;
	    up_write(&mm->mmap_lock);
	    return 0;
	}
	vma = vma->vm_next;
    }

    kfree(k_filename);
    return -EFAULT;
}

