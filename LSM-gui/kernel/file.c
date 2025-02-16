#define __TARGET_ARCH_x86 1
#include "vmlinux.h"
#include <linux/module.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <string.h>
#include "header.h"
// extern struct
// {
//     __uint(type, BPF_MAP_TYPE_RINGBUF);
//     __uint(max_entries, 24 * 1024);
// } RING;
// extern struct {
//     __uint(type, BPF_MAP_TYPE_RINGBUF);
//     __uint(max_entries, 48 * 1024);
// } BUFFER;
char LICENSE[] SEC("license") = "GPL";
struct limited_task
{
    int flag_exclude_or_include;
    u32 uids[LIMIT_MAX];
    int uid_nb;
    u32 gids[LIMIT_MAX];
    int gid_nb;
    u32 pids[LIMIT_MAX];
    int pid_nb;
    u32 exe_inodes[LIMIT_MAX];
    int exe_inode_nb;
};
struct file_audit
{
    int trigger;
    int action;
    struct limited_task index;
};
struct file_audit_event
{

    int inode;
    int audits_nb;
    struct file_audit audit[MAX_AUDIT];
};
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048);
    __type(key, int);
    __type(value, struct file_audit_event);
} file_map SEC(".maps");
static bool is_limited_task(struct limited_task *index)
{
    int ret = 1;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    u32 gid = bpf_get_current_uid_gid() >> 32;
    u32 exe_inode = get_exe_inode();

    if (index->uid_nb)
    {
        ret = 0;
        for (u32 i = 0; i < LIMIT_MAX; i++)
        {
            if (uid == index->uids[i])
            {
                ret = 1;
                break;
            }
        }
    }

    if (ret && index->gid_nb)
    {
        ret = 0;
        for (u32 i = 0; i < LIMIT_MAX; i++)
        {
            if (gid == index->gids[i])
            {
                ret = 1;
                break;
            }
        }
    }

    if (ret && (index->pid_nb || index->exe_inode_nb))
    {
        ret = 0;
        for (int i = 0; i < LIMIT_MAX; i++)
        {
            if (pid == index->pids[i])
            {
                ret=1;
                break;
            }
        }

        if (!ret)
        {

            for (int i = 0;  i < LIMIT_MAX; i++)
            {
                if (exe_inode == index->exe_inodes[i])
                {
                    ret=1;
                    break;
                }
            }
        }
    }

    // 反转 ret 结果
    if (index->flag_exclude_or_include)
    {
        ret = !ret;
    }

    return ret;
}

static int search_file_audits(struct file_audit_event *events, int trigger, char *out)
{
    struct file_audit *audit = events->audit;
    //  u64 time = bpf_ktime_get_ns();
      // #pragma unroll
    for (int i = 0;  i < MAX_AUDIT; i++, audit++)
    {
      //  bpf_printk("%d %d",trigger,audit->trigger);
        if (trigger == audit->trigger)
        {
           //  bpf_printk("search\n");
            //   bpf_printk("%d\n",audit->action);
            if (!is_limited_task(&audit->index))
            continue;
             //     bpf_printk("search_\n");
            if (audit->action == ACTION_DENY)
            {
                BPF_RING_OUTPUT("[time:]\nDeny %s\n", (__u64)out);
                return -1;
            }
            else if (audit->action == ACTION_RECORD)
            {

                BPF_RING_OUTPUT("[time:]\nRecord %s\n", (__u64)out);
            }
        }
    }
    return 0;
}
/*int file_open(struct file *file, const struct cred *cred);*/
static int search_file_audits__(struct file_audit_event *events, int mode)
{
    struct file_audit *audit = events->audit;
    int ret = 0;
    for (int i = 0;  i < MAX_AUDIT; i++, audit++)
    {
        if(!audit->trigger)continue;
        if (!is_limited_task(&audit->index))
            continue;

        switch (audit->trigger)
        {
        case TRIGGER_DIR_RESTRICT:
            if (audit->action == ACTION_DENY)
                return -1;
            else if (audit->action == ACTION_RECORD)
                ret = 1;
            break;

        case TRIGGER_DIR_RESTRICT_R:
            if (mode & MODE_READ)
            {
                if (audit->action == ACTION_DENY)
                    return -1;
                else if (audit->action == ACTION_RECORD)
                    ret = 1;
            }
            break;

        case TRIGGER_DIR_RESTRICT_W:
            if (mode & MODE_WRITE)
            {
                if (audit->action == ACTION_DENY)
                    return -1;
                else if (audit->action == ACTION_RECORD)
                    ret = 1;
            }
            break;

        case TRIGGER_DIR_RESTRICT_RW:
            if ((mode & MODE_READ) && (mode & MODE_WRITE))
            {
             //   bpf_printk("test");
                if (audit->action == ACTION_DENY)
                    return -1;
                else if (audit->action == ACTION_RECORD)
                    ret = 1;
            }
            break;

        default:
            break;
        }
    }

    return ret;
}
SEC("lsm/file_open")
int BPF_PROG(lsm_dir_restrict, struct file *file, const struct cred *cred)
{
    //  struct qstr q;
    int ret = 0;
    u32 mode = BPF_CORE_READ(file, f_mode);
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    for (u32 i = 0; i < 8&&ret>=0; i++)
    {
        struct dentry *p_dentry = BPF_CORE_READ(dentry, d_parent);
        if (!p_dentry||p_dentry == dentry)
            break;
        dentry = p_dentry;
        //   q = BPF_CORE_READ(dentry, d_name);
        int inode = BPF_CORE_READ(dentry, d_inode, i_ino);
        struct file_audit_event *event = bpf_map_lookup_elem(&file_map, &inode);
        if (!event)
            continue;
        ret = search_file_audits__(event, mode);
     //   if (ret < 0)
      //      break;
    }
    if (ret == 0)
        return 0;
    char *out = get_buffer();
    if (!out)
        return 0;
    int pid = bpf_get_current_pid_tgid() >> 32;
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    char process_path[PATH_LEN];
    char buf[PATH_LEN];
    bpf_d_path(&file->f_path, buf, PATH_LEN);
    get_now_task_path(process_path, sizeof(process_path));
    const char *format = "process:%s pid:%d user:[uid:%d] open file: %s mode:0x%x";
    SNPRINTF(out, MSG_DATA_LEN, format, (u64)process_path, pid, uid, (u64)buf, mode);
    if (ret == 1)
    {
        BPF_RING_OUTPUT("[time:]\nRecord %s\n", (__u64)out);
    }
    else if (ret == -1)
    {
        BPF_RING_OUTPUT("[time:]\nDeny %s\n", (__u64)out);
    }
    return ret;
}
SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file, const struct cred *cred)
{
   // return 0;
    int ret = 0;
   
    int inode = BPF_CORE_READ(file, f_inode, i_ino);
    struct file_audit_event *event = bpf_map_lookup_elem(&file_map, &inode);
    if (!event)
    {
        return 0;
    }
 //   bpf_printk("test");
    int pid = bpf_get_current_pid_tgid() >> 32;
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    u32 mode = BPF_CORE_READ(file, f_mode);
    char buf[PATH_LEN];
    bpf_d_path(&file->f_path, buf, sizeof(buf));
    char *out = get_buffer();
    if (!out)
        return 0;

    char process_path[PATH_LEN];
    get_now_task_path(process_path, sizeof(process_path));
    const char *format = "process:%s pid:%d user:[uid:%d] open file: %s mode:0x%x";
    SNPRINTF(out, MSG_DATA_LEN, format, (u64)process_path, pid, uid, (u64)buf, mode);
  // bpf_printk("%s",buf);
    if (search_file_audits(event, TRIGGER_OPEN, out) < 0)
    {
        return -1;
    }
    if (mode & MODE_READ)
    {
        if (search_file_audits(event, TRIGGER_OPEN_READ, out) < 0)
        {
            return -1;
        }
    }
    if (mode & MODE_WRITE)
    {
        // bpf_printk("xx\n");
        if (search_file_audits(event, TRIGGER_OPEN_WRITE, out) < 0)
        {
            return -1;
        }
    }
    if ((mode & MODE_WRITE) && (mode & MODE_READ))
    {
        if (search_file_audits(event, TRIGGER_OPEN_RW, out) < 0)
        {
            return -1;
        }
    }
    /*

    */
   //bpf_printk("ret 0\n");
    return ret;
};
SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_file_exe, struct linux_binprm *bprm)
{
    int ret = 0;
    struct file *file = BPF_CORE_READ(bprm, file);
    int inode = BPF_CORE_READ(file, f_inode, i_ino);
    struct qstr q;

    // bpf_printk("%d",inode);
    struct file_audit_event *event = bpf_map_lookup_elem(&file_map, &inode);
    if (!event)
    {
        return ret;
    }
    //   bpf_printk("test\n");
    int pid = bpf_get_current_pid_tgid() >> 32;
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    // char tmp[PATH_LEN];
    // bpf_d_path(&file->f_path, tmp, PATH_LEN);
    char *out = get_buffer();
    if (!out)
        return 0;
    char process_path[PATH_LEN];
    get_now_task_path(process_path, sizeof(process_path));
    const char *format = "process:%s pid:%d user:[uid:%d] execve: %s ";
    SNPRINTF(out, MSG_DATA_LEN, format, (u64)process_path, pid, uid, (u64)bprm->filename);
    if (search_file_audits(event, TRIGGER_EXE, out) < 0)
        ret = -1;

    return ret;
}
// static char link_out[MSG_DATA_LEN]; // stack is not enough in link
SEC("lsm/path_link")
int BPF_PROG(lsm_link, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry)
{

    int ret = 0;
    // bpf_printk("link");
    int old_inode = BPF_CORE_READ(old_dentry, d_inode, i_ino);
    struct file_audit_event *event = bpf_map_lookup_elem(&file_map, &old_inode);
    if (!event)
    {
        return 0;
    }
    int pid = bpf_get_current_pid_tgid() >> 32;
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    char *out = get_buffer();
    if (!out)
        return 0;
    char *process_path = get_buffer_(3);
    if (!process_path)
    {
        return 0;
    }
    char buf[PATH_LEN];
    char *buf_ = get_buffer_(4);
    if (!buf_)
        return 0;
    get_now_task_path(process_path, PATH_LEN);
    get_dentry_path(old_dentry, buf, sizeof(buf));
    get_dentry_path(new_dentry, buf_, PATH_LEN);
    SNPRINTF(out, MSG_DATA_LEN, "process:%s pid:%d user:[uid:%d] link %s -> %s", (u64)process_path, pid, uid, (u64)buf, (u64)buf_);
    // get_dentry_path(new_dentry, buf, sizeof(buf));
    // u32 index = bpf_strlen(link_out, MSG_DATA_LEN);
    // if (index < MSG_DATA_LEN)
    // {
    //     SNPRINTF((char *)link_out + index, MSG_DATA_LEN - index, "%s", (u64)buf);
    // }
    if (search_file_audits(event, TRIGGER_LINK, out) < 0)
        ret = -1;
exit:
    return ret;
};
/*LSM_HOOK(int, 0, path_unlink, const struct path *dir, struct dentry *dentry)
LSM_HOOK(int, 0, path_symlink, const struct path *dir, struct dentry *dentry,
     const char *old_name)
    LSM_HOOK(int, 0, path_link, struct dentry *old_dentry,
     const struct path *new_dir, struct dentry *new_dentry)
*/
SEC("lsm/path_unlink")
int BPF_PROG(lsm_unlink, struct path *p, struct dentry *dentry_)
{
    int ret = 0;
    int inode = BPF_CORE_READ(dentry_, d_inode, i_ino);
    struct file_audit_event *event = bpf_map_lookup_elem(&file_map, &inode);
    if (!event)
    {
        return 0;
    }
    char *out = get_buffer();
    if (!out)
        return 0;

    char buf[PATH_LEN];
    int pid = bpf_get_current_pid_tgid() >> 32;
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    get_dentry_path(dentry_, buf, sizeof(buf));
    char process_path[PATH_LEN];
    get_now_task_path(process_path, sizeof(process_path));
    //     bpf_printk("unlink %s",buf);
    SNPRINTF(out, MSG_DATA_LEN, "process:%s pid:%d user:[uid:%d] unlink path:%s", (u64)process_path, pid, uid, (u64)buf);
    if (search_file_audits(event, TRIGGER_UNLINK, out) < 0)
        ret = -1;
exit:

    //   bpf_printk("ret %d",ret);
    return ret;
};
SEC("lsm/file_truncate")
int BPF_PROG(lsm_truncate, struct file *file)
{
    int ret = 0;
    u32 inode = BPF_CORE_READ(file, f_inode, i_ino);
    struct file_audit_event *event = bpf_map_lookup_elem(&file_map, &inode);
    if (!event)
    {
        return 0;
    }
    int pid = bpf_get_current_pid_tgid() >> 32;
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    char *out = get_buffer();
    if (!out)
        return 0;
    char buf[PATH_LEN];
    char process_path[PATH_LEN];
    struct path p = BPF_CORE_READ(file, f_path);
    get_dentry_path(p.dentry, buf, sizeof(buf));
    get_now_task_path(process_path, PATH_LEN);
    const char *format = "process:%s pid:%d user:[uid:%d] truncate  path:%s";
    SNPRINTF(out, MSG_DATA_LEN, format, (u64)process_path, pid, uid, (u64)buf);
    //  u32 sz=bpf_strlen(out);
    //  if(sz<MSG_DATA_LEN)
    // bpf_d_path(&file->f_path,(char*)out,MSG_DATA_LEN);
    if (search_file_audits(event, TRIGGER_TRUNCATE, out) < 0)
        ret = -1;
exit:

    return ret;
};
/*LSM_HOOK(int, 0, inode_create, struct inode *dir, struct dentry *dentry,
     umode_t mode)*/
SEC("lsm/inode_create")
int BPF_PROG(lsm_create_file, struct inode *dir, struct dentry *dentry,
             umode_t mode)
{
    int ret = 0;
    u32 inode = BPF_CORE_READ(dir, i_ino);
    struct file_audit_event *event = bpf_map_lookup_elem(&file_map, &inode);
    if (!event)
    {
        return 0;
    }
    char *out = get_buffer();
    if (!out)
        return 0;
    char buf[PATH_LEN];
    char process_path[PATH_LEN];
    int pid = bpf_get_current_pid_tgid() >> 32;
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    struct qstr q = BPF_CORE_READ(dentry, d_name);
    get_dentry_path(dentry, buf, PATH_LEN);
    get_now_task_path(process_path, PATH_LEN);
    SNPRINTF(out, MSG_DATA_LEN, "process:%s pid:%d user:[uid:%d] create_file: %s", (u64)process_path, pid, uid, (__u64)buf);
    if (search_file_audits(event, TRIGGER_CREATE_FILE, out) < 0)
        ret = -1;
exit:

    return ret;
}
/*LSM_HOOK(int, 0, inode_mkdir, struct inode *dir, struct dentry *dentry,
     umode_t mode)
LSM_HOOK(int, 0, inode_rmdir, struct inode *dir, struct dentry *dentry)*/
SEC("lsm/inode_mkdir")
int BPF_PROG(lsm_mkdir, struct inode *dir, struct dentry *dentry, umode_t mode)
{
    int ret = 0;
    u32 inode = BPF_CORE_READ(dir, i_ino);
    struct file_audit_event *event = bpf_map_lookup_elem(&file_map, &inode);
    if (!event)
    {
        return 0;
    }
    //    bpf_printk("mkdir");
    char *out = get_buffer();
    if (!out)
        return 0;
    int pid = bpf_get_current_pid_tgid() >> 32;
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    char buf[PATH_LEN];
    char process_path[PATH_LEN];
    get_now_task_path(process_path, sizeof(process_path));
    get_dentry_path(dentry, buf, PATH_LEN);
    SNPRINTF(out, MSG_DATA_LEN, "process:%s pid:%d user:[uid:%d] mkdir %s", (u64)process_path, pid, uid, (u64)buf);
    if (search_file_audits(event, TRIGGER_MKDIR, out) < 0)
        ret = -1;
exit:

    return ret;
}
SEC("lsm/inode_rmdir")
int BPF_PROG(lsm_rmdir, struct inode *dir, struct dentry *dentry)
{

    int ret = 0;
    u32 inode = BPF_CORE_READ(dir, i_ino);
    struct file_audit_event *event = bpf_map_lookup_elem(&file_map, &inode);
    if (!event)
    {
        return 0;
    }
    //    bpf_printk("rmdir");
    char *out = get_buffer();
    if (!out)
        return 0;
    int pid = bpf_get_current_pid_tgid() >> 32;
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    char buf[PATH_LEN];
    char process_path[PATH_LEN];
    get_dentry_path(dentry, buf, sizeof(buf));
    get_now_task_path(process_path, sizeof(process_path));
    SNPRINTF(out, MSG_DATA_LEN, "process:%s pid:%d user:[uid:%d] rmdir %s", (u64)process_path, pid, uid, (u64)buf);
    if (search_file_audits(event, TRIGGER_RMDIR, out) < 0)
        ret = -1;
exit:

    return ret;
}
/*LSM_HOOK(int, 0, mmap_file, struct file *file, unsigned long reqprot,
     unsigned long prot, unsigned long flags)*/

SEC("lsm/mmap_file")
int BPF_PROG(lsm_file_mmap, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags)
{
    int ret = 0;
    u32 inode = BPF_CORE_READ(file, f_inode, i_ino);
    struct file_audit_event *event = bpf_map_lookup_elem(&file_map, &inode);
    if (!event)
    {
        return 0;
    }
    //    bpf_printk("rmdir");
    char *out = get_buffer();
    if (!out)
        return 0;
    int pid = bpf_get_current_pid_tgid() >> 32;
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    char buf[PATH_LEN];
    char process_path[PATH_LEN];
    bpf_d_path(&file->f_path, buf, PATH_LEN);
    get_now_task_path(process_path, sizeof(process_path));
    SNPRINTF(out, MSG_DATA_LEN, "process:%s pid:%d user:[uid:%d] mmap file:%s", (u64)process_path, pid, uid, (u64)buf);
    if (search_file_audits(event, TRIGGER_FILE_MMAP, out) < 0)
        ret = -1;

    return ret;
}
