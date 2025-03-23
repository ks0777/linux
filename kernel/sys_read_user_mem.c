#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/pid.h>
#include <linux/security.h>
#include <linux/pid_types.h>
#include <linux/slab.h>	   // For kmalloc and kfree
#include <linux/fs.h>		 // For struct file and file paths
#include <linux/string.h>	 // For strncmp

SYSCALL_DEFINE4(read_user_mem, pid_t, pid, void __user *, addr, size_t, len, void __user *, buf) {
	struct task_struct *task;
	struct mm_struct *mm;
	void *kernel_buffer;
	int ret = -EFAULT;

	printk("read_user_mem\tpid: %u\t addr: 0x%p\tlen: %lu\t buf: 0x%p\n", pid, addr, len, buf);

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
	
	printk("write_user_mem\tpid: %u\t addr: 0x%p\tlen: %lu\t buf: 0x%p\n", pid, addr, len, buf);

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
	const unsigned char* null_str = "(null)";
	int ret = -EFAULT;

	// Check if the current process has the right permissions
	if (!capable(CAP_SYS_ADMIN)) return -EPERM;

	task = get_pid_task(find_get_pid(pid), PIDTYPE_PID);
	if (!task) return -ESRCH;  // No task

	mm = get_task_mm(task);
	if (!mm) {
		put_task_struct(task);
		return -EFAULT;
	}

	k_filename = kmalloc(filename_len + 1, GFP_KERNEL);
	if (!k_filename) {
		put_task_struct(task);
		mmput(mm);
		return -ENOMEM;
	}

	if (copy_from_user(k_filename, filename, filename_len)) {
		ret = -EFAULT;
		goto out;
	}
	k_filename[filename_len] = '\0';

	VMA_ITERATOR(vmi, mm, 0);
	down_read(&mm->mmap_lock);
	for_each_vma(vmi, vma) {
		const char *vma_filename = vma->vm_file ? vma->vm_file->f_path.dentry->d_name.name : null_str;
		printk("[%lx-%lx]: %s\n", vma->vm_start, vma->vm_end, vma_filename);
		if (vma->vm_file && strcmp(vma_filename, k_filename) == 0) {
			unsigned long vma_start = vma->vm_start;
			up_read(&mm->mmap_lock);
			ret = (copy_to_user(base_address, &vma_start, sizeof(vma_start))) ? -EFAULT : 0;
			goto out;
		}
	}
	up_read(&mm->mmap_lock);

	out:
	kfree(k_filename);
	put_task_struct(task);
	mmput(mm);
	return ret;
}

