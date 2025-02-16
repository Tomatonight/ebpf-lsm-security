#define __TARGET_ARCH_x86 1
#include "vmlinux.h"
#include <linux/module.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/unistd.h>
#include <string.h>
#include "header.h"

struct process_audit
{
    int trigger;
    int action;
};
struct process_audit_events
{
    union
    {
        int pid;
        int exe_file_inode;
    };
    int audit_nb;
    struct process_audit audits[MAX_AUDIT];
};
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048);
    __type(key, int);
    __type(value, struct process_audit_events);
} process_pid_map SEC(".maps");
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048);
    __type(key, int);
    __type(value, struct process_audit_events);
} process_inode_map SEC(".maps");
/*LSM_HOOK(int, 0, bprm_check_security, struct linux_binprm *bprm)*/

/*LSM_HOOK(int, 0, task_alloc, struct task_struct *task,
     unsigned long clone_flags)*/

static int search_process_audits(struct process_audit_events *audit_events, int trigger, char *out)
{

    if (!audit_events)
        return 0;
    // bpf_printk("search");
    int ret = 0;
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    for (int i = 0; i < audit_events->audit_nb && i < MAX_AUDIT; i++)
    {
        //  bpf_printk("%d",i);
        struct process_audit *audit = &audit_events->audits[i];
        if (audit->trigger != trigger)
            continue;
        if (audit->action == ACTION_DENY)
        {

            // bpf_printk("search aaaaa");
            BPF_RING_OUTPUT("[time:]\nDeny %s\n", (__u64)out);
            ret = -1;
            continue;
        }
        else if (audit->action == ACTION_RECORD)
        {

            //   bpf_printk("search bbbbb");
            BPF_RING_OUTPUT("[time:]\nRecord %s\n", (__u64)out);
            continue;
        }
        else
        {
            bpf_printk("action err");
        }
    }
    return ret;
};
SEC("lsm/task_alloc")
int BPF_PROG(lsm_task_create, struct task_struct *task, unsigned long clone_flags)
{
    int ret = 0;
    int pid = bpf_get_current_pid_tgid() >> 32;
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    int exe_inode = get_exe_inode();
    struct process_audit_events *pid_audits = bpf_map_lookup_elem(&process_pid_map, &pid);
    struct process_audit_events *inode_audits = bpf_map_lookup_elem(&process_inode_map, &exe_inode);
    if (!((u64)pid_audits + (u64)inode_audits))
        return 0;
    char process_path[PATH_LEN];
    char *out = get_buffer();
    if (!out)
        return 0;
    get_now_task_path(process_path, PATH_LEN);
    //   bpf_printk("%s",process_path);
    if (clone_flags & CLONE_VM) // thread
    {
        //  bpf_printk("%s thread",process_path);
        SNPRINTF(out, MSG_DATA_LEN, "process:%s pid:%d user:[uid:%d] create_thread", (u64)process_path, pid, uid);
        ret = search_process_audits(pid_audits, TRIGGER_CREATE_THREAD, out);
        if (ret < 0)
            goto exit;
        ret = search_process_audits(inode_audits, TRIGGER_CREATE_THREAD, out);
        if (ret < 0)
            goto exit;
    }
    else // fork
    {
        //  bpf_printk("%s fork",process_path);
        SNPRINTF(out, MSG_DATA_LEN, "process:%s pid:%d user:[uid:%d] fork", (u64)process_path, pid, uid);
        ret = search_process_audits(pid_audits, TRIGGER_FORK, out);
        if (ret < 0)
            goto exit;
        ret = search_process_audits(inode_audits, TRIGGER_FORK, out);
        if (ret < 0)
            goto exit;
    }

exit:

    return ret;
}
SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_execve, struct linux_binprm *bprm)
{
    int ret = 0;
    struct linux_binprm *b;
    // bpf_printk("execve 1 %s\n2 %s\n3 %s %d", bprm->filename, bprm->interp, bprm->fdpath, bprm->have_execfd);
    struct file *file = BPF_CORE_READ(bprm, file);
    // if (is_suid_file(file))
    // {
    // }
    int exe_inode = BPF_CORE_READ(file, f_inode, i_ino);
    int pid = bpf_get_current_pid_tgid() >> 32;
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    struct process_audit_events *pid_audits = bpf_map_lookup_elem(&process_pid_map, &pid);
    struct process_audit_events *inode_audits = bpf_map_lookup_elem(&process_inode_map, &exe_inode);
    // bpf_printk("%s %d %d",bprm->filename,exe_inode,pid);
    if (!((u64)pid_audits + (u64)inode_audits))
        return 0;
    char *out = get_buffer();
    if (!out)
        return 0;
    char process_path[PATH_LEN];
    get_now_task_path(process_path, PATH_LEN);
    SNPRINTF(out, MSG_DATA_LEN, "process:%s pid:%d user:[uid:%d] execve path:%s", (u64)process_path, pid, uid, (__u64)bprm->filename);
    if (search_process_audits(pid_audits, TRIGGER_EXECVE, out) < 0)
    {
        // bpf_printk("deny");
        ret = -1;
        goto exit;
    }
    if (search_process_audits(inode_audits, TRIGGER_EXECVE, out) < 0)
    {
        //  bpf_printk("deny");
        ret = -1;
        goto exit;
    }
    // bpf_printk("%s pass",bprm->filename);
exit:

    return 0;
}
/*
LSM_HOOK(int, 0, ptrace_access_check, struct task_struct *child,
     unsigned int mode)
LSM_HOOK(int, 0, ptrace_traceme, struct task_struct *parent)
*/

SEC("lsm/ptrace_access_check")
int BPF_PROG(lsm_ptrace, struct task_struct *child, unsigned int mode)
{
    int ret = 0;
    int pid = bpf_get_current_pid_tgid() >> 32;
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    int child_pid = BPF_CORE_READ(child, pid);
    int exe_inode = get_exe_inode();
    struct process_audit_events *pid_audits = bpf_map_lookup_elem(&process_pid_map, &pid);
    struct process_audit_events *inode_audits = bpf_map_lookup_elem(&process_inode_map, &exe_inode);

    if (!((u64)pid_audits + (u64)inode_audits))
        return 0;
    char *out = get_buffer();
    if (!out)
        return 0;
    char process_path[PATH_LEN];
    char process_path_[PATH_LEN];
    get_task_path(child, process_path_, PATH_LEN);
    get_now_task_path(process_path, PATH_LEN);
    //   bpf_printk("ptrace %s %s",process_path,process_path_);
    int child_exe_inode = BPF_CORE_READ(child, mm, exe_file, f_inode, i_ino);
    SNPRINTF(out, MSG_DATA_LEN, "process:%s pid:%d user:[uid:%d] ptrace process:%s pid:%d", (u64)process_path, pid, uid, (u64)process_path_, child_pid);
    if (search_process_audits(pid_audits, TRIGGER_PTRACE, out) < 0)
    {
        ret = -1;
    }
    else if (search_process_audits(inode_audits, TRIGGER_PTRACE, out) < 0)
    {
        ret = -1;
    }

    return ret;
}
SEC("lsm/ptrace_traceme")
int BPF_PROG(lsm_ptraceme, struct task_struct *parent)
{
    int ret = 0;
    int pid = bpf_get_current_pid_tgid() >> 32;
    int parent_pid = BPF_CORE_READ(parent, pid);
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    int exe_inode = get_exe_inode();
    struct process_audit_events *pid_audits = bpf_map_lookup_elem(&process_pid_map, &pid);
    struct process_audit_events *inode_audits = bpf_map_lookup_elem(&process_inode_map, &exe_inode);
    if (!((u64)pid_audits + (u64)inode_audits))
        return 0;
    char *out = get_buffer();
    if (!out)
        return 0;
    char process_path[PATH_LEN];
    char process_path_[PATH_LEN];
    get_now_task_path(process_path, PATH_LEN);
    get_task_path(parent, process_path_, PATH_LEN);
    int parent_exe_inode = BPF_CORE_READ(parent, mm, exe_file, f_inode, i_ino);
    SNPRINTF(out, MSG_DATA_LEN, "process:%s pid:%d user:[uid:%d] ptraced by process:%s pid:%d", (u64)process_path, pid, uid, (u64)process_path_, parent_pid);
    if (search_process_audits(pid_audits, TRIGGER_PTRACEME, out) < 0)
    {
        ret = -1;
    }
    else if (search_process_audits(inode_audits, TRIGGER_PTRACEME, out) < 0)
    {
        ret = -1;
    }

    return ret;
}
/*
LSM_HOOK(int, 0, task_kill, struct task_struct *p, struct kernel_siginfo *info,
     int sig, const struct cred *cred)
*/
SEC("lsm/task_kill")
int BPF_PROG(lsm_task_kill, struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred)
{
    // bpf_printk("test");
    int ret = 0;
    int pid = bpf_get_current_pid_tgid() >> 32;
    int pid_ = BPF_CORE_READ(p, pid);
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    int exe_inode = get_exe_inode();
    int exe_inode_ = BPF_CORE_READ(p, mm, exe_file, f_inode, i_ino);
    struct process_audit_events *pid_audits = bpf_map_lookup_elem(&process_pid_map, &pid);
    struct process_audit_events *inode_audits = bpf_map_lookup_elem(&process_inode_map, &exe_inode);
    //   if(!((u64)pid_audits+(u64)inode_audits))return 0;
    // char *out = get_buffer();
    char *out = get_buffer();
    if (!out)
    {
        return 0;
    }
    char process_path[PATH_LEN];
    char *process_path_ = get_buffer_(3);
    if (!process_path_)
        return 0;
    get_now_task_path(process_path, PATH_LEN);
    get_task_path(p, process_path_, PATH_LEN);
    // bpf_printk("%s\n%d\n%s",process_path,sig,process_path_);
    SNPRINTF(out, MSG_DATA_LEN, "process:%s pid:%d user:[uid:%d] kill sig:%d process:%s pid:%d", (u64)process_path, pid, uid, sig, (u64)process_path_, pid_);
    if (search_process_audits(pid_audits, TRIGGER_KILL, out) < 0)
    {
        ret = -1;
    }
    else if (search_process_audits(inode_audits, TRIGGER_KILL, out) < 0)
    {
        ret = -1;
    }

    return ret;
};
/*
LSM_HOOK(int, 0, task_fix_setuid, struct cred *new, const struct cred *old,
     int flags)
LSM_HOOK(int, 0, task_fix_setgid, struct cred *new, const struct cred * old,
     int flags)
*/
SEC("lsm/task_fix_setuid")
int BPF_PROG(lsm_setuid, struct cred *new, const struct cred *old, int flags)
{
    int ret = 0;
    int pid = bpf_get_current_pid_tgid() >> 32;
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    int exe_inode = get_exe_inode();
    struct process_audit_events *pid_audits = bpf_map_lookup_elem(&process_pid_map, &pid);
    struct process_audit_events *inode_audits = bpf_map_lookup_elem(&process_inode_map, &exe_inode);

    // if (!((u64)pid_audits + (u64)inode_audits))
    //     return 0;
    char *out = get_buffer();
    if (!out)
        return 0;
    char process_path[PATH_LEN];
    get_now_task_path(process_path, PATH_LEN);
    int old_uid, new_uid;
    bpf_probe_read_kernel(&old_uid, sizeof(int), &old->uid);
    bpf_probe_read_kernel(&new_uid, sizeof(int), &new->uid);
    //  bpf_printk("setuid %s",process_path);
    SNPRINTF(out, MSG_DATA_LEN, "process:%s pid:%d user:[uid:%d] setuid %d -> %d [uid:%d] -> [uid:%d]", (u64)process_path, pid, uid, old_uid, new_uid, old_uid, new_uid);
    if (search_process_audits(pid_audits, TRIGGER_SETUID, out) < 0)
    {
        ret = -1;
    }
    else if (search_process_audits(inode_audits, TRIGGER_SETUID, out) < 0)
    {
        ret = -1;
    }

    return ret;
};

SEC("lsm/task_fix_setgid")
int BPF_PROG(lsm_setgid, struct cred *new, const struct cred *old, int flags)
{
    int ret = 0;
    int pid = bpf_get_current_pid_tgid() >> 32;
    int exe_inode = get_exe_inode();
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    struct process_audit_events *pid_audits = bpf_map_lookup_elem(&process_pid_map, &pid);
    struct process_audit_events *inode_audits = bpf_map_lookup_elem(&process_inode_map, &exe_inode);
    if (!((u64)pid_audits + (u64)inode_audits))
        return 0;
    char *out = get_buffer();
    if (!out)
        return 0;
    char process_path[PATH_LEN];
    get_now_task_path(process_path, PATH_LEN);
    int old_gid, new_gid;
    bpf_probe_read_kernel(&old_gid, sizeof(int), &old->gid);
    bpf_probe_read_kernel(&new_gid, sizeof(int), &new->gid);
    SNPRINTF(out, MSG_DATA_LEN, "process:%s pid:%d user:[uid:%d] setgid %d -> %d [gid:%d] -> [gid:%d]", (u64)process_path, pid, uid, old_gid, new_gid, old_gid, new_gid);
    if (search_process_audits(pid_audits, TRIGGER_SETGID, out) < 0)
    {
        ret = -1;
    }
    else if (search_process_audits(inode_audits, TRIGGER_SETGID, out) < 0)
    {
        ret = -1;
    }

    return ret;
};
/*LSM_HOOK(void, LSM_RET_VOID, task_free, struct task_struct *task)*/
SEC("lsm/task_free")
int BPF_PROG(lsm_task_free, struct task_struct *task)
{
    int pid = BPF_CORE_READ(task, pid);
    int exe_inode = BPF_CORE_READ(task, mm, exe_file, f_inode, i_ino);
    int uid = BPF_CORE_READ(task, cred, uid).val;
    struct process_audit_events *pid_audits = bpf_map_lookup_elem(&process_pid_map, &pid);
    struct process_audit_events *inode_audits = bpf_map_lookup_elem(&process_inode_map, &exe_inode);
    if (!((u64)pid_audits + (u64)inode_audits))
        return 0;
    char *out = get_buffer();
    if (!out)
        return 0;
    char process_path[PATH_LEN];
    get_now_task_path(process_path, PATH_LEN);
    SNPRINTF(out, MSG_DATA_LEN, "process:%s pid:%d uid:[uid:%d] free", (u64)process_path, pid, uid);
    search_process_audits(pid_audits, TRIGGER_TASK_FREE, out);
    search_process_audits(inode_audits, TRIGGER_TASK_FREE, out);
    return 0;
}
/*LSM_HOOK(int, -ENOSYS, task_prctl, int option, unsigned long arg2,
     unsigned long arg3, unsigned long arg4, unsigned long arg5)*/
SEC("lsm/task_prctl")
int BPF_PROG(lsm_task_prctl, int option, unsigned long arg2,
             unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
    int ret = 0;
    int pid = bpf_get_current_pid_tgid() >> 32;
    int exe_inode = get_exe_inode();
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    struct process_audit_events *pid_audits = bpf_map_lookup_elem(&process_pid_map, &pid);
    struct process_audit_events *inode_audits = bpf_map_lookup_elem(&process_inode_map, &exe_inode);
    if (!((u64)pid_audits + (u64)inode_audits))
        return 0;
    char *out = get_buffer();
    if (!out)
        return 0;
    char process_path[PATH_LEN];
    get_now_task_path(process_path, PATH_LEN);
     SNPRINTF(out, MSG_DATA_LEN, "process:%s pid:%d uid:[uid:%d] prctl opt:%d", (u64)process_path, pid, uid,option);
    if (search_process_audits(pid_audits, TRIGGER_PRCTL, out) < 0)
    {
        ret = -1;
    }
    else if (search_process_audits(inode_audits, TRIGGER_PRCTL, out) < 0)
    {
        ret = -1;
    }

    return ret;
}