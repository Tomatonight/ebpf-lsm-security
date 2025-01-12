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
#define OPERATOR_MAX 16
struct operator_index
{
    int flag_exclude_or_include;
    u32 uids[OPERATOR_MAX];
    int uid_nb;
    u32 gids[OPERATOR_MAX];
    int gid_nb;
    u32 pids[OPERATOR_MAX];
    int pid_nb;
    u32 exe_inodes[OPERATOR_MAX];
    int exe_inode_nb;
};
struct file_audit
{
    int trigger;
    int action;
    struct operator_index index;
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
static int judge_operator(struct operator_index *index)
{
    int ret = 1;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    u32 gid = bpf_get_current_uid_gid() >> 32;
    u32 exe_inode = get_exe_inode();
    // reject
    if (index->uid_nb)
    {
        int i = 0;
        //  bpf_printk("uid nb %d,", index->uid_nb);
        for (; i < index->uid_nb && i < OPERATOR_MAX; i++)
        {
            if (uid == index->uids[i])
                break;
        }
        if (i == index->uid_nb)
        {
            ret = 0;
            goto exit;
        }
    }
    if (index->gid_nb)
    {
        //   bpf_printk("gid nb %d,", index->gid_nb);
        int i = 0;
        for (; i < index->gid_nb && i < OPERATOR_MAX; i++)
        {
            if (gid == index->gids[i])
                break;
        }
        if (i == index->gid_nb)
        {
            ret = 0;
            goto exit;
        }
    }
    if (index->pid_nb || index->exe_inode_nb)
    {
        // bpf_printk("pid nb %d,", index->pid_nb);
        bool flag = false;
        for (int i = 0; i < index->pid_nb && i < OPERATOR_MAX; i++)
        {
            if (pid == index->pids[i])
            {
                flag = true;
                break;
            }
        }
        for (int i = 0; i < index->exe_inode_nb && i < OPERATOR_MAX && !flag; i++)
        {
            if (exe_inode == index->exe_inodes[i])
            {
                flag = true;
                break;
            }
        }
        if (!flag)
        {
            ret = 0;
            goto exit;
        }
    }
exit:
    if (index->flag_exclude_or_include)
    {
        return !ret;
    };
    return ret;
}

static int search_file_audits(struct file_audit_event *events, int trigger, char *out)
{
    int ret = 0;
    if (!events)
        return ret;
    struct file_audit *audit = events->audit;
    for (int i = 0; i < events->audits_nb && i < MAX_AUDIT; i++, audit++)
    {

        if (trigger == audit->trigger && (judge_operator(&audit->index)))
        {
            if (audit->action == ACTION_DENY)
            {
                BPF_RING_OUTPUT("Deny %s\n", (__u64)out);
                ret = -1;
                continue;
            }
            else if (audit->action == ACTION_RECORD)
            {

                BPF_RING_OUTPUT("Record %s\n", (__u64)out);
                continue;
            }
            else
            {
                bpf_printk("file audit action err");
            }
        }
    }
    return ret;
}
/*int file_open(struct file *file, const struct cred *cred);*/
SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file, const char *fmt)
{

    int ret = 0;
    int inode = BPF_CORE_READ(file, f_inode, i_ino);
    struct file_audit_event *event = bpf_map_lookup_elem(&file_map, &inode);
    if (!event)
    {
        return ret;
    }

    int pid = bpf_get_current_pid_tgid() >> 32;
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    int mode = BPF_CORE_READ(file, f_mode);
    char tmp[PATH_LEN];
    bpf_d_path(&file->f_path, tmp, PATH_LEN);
    char out[MSG_DATA_LEN] = {0};
    const char *format = "process:[pid:%d] pid:%d user:[uid:%d] open file: %s mode:0x%x";
    SNPRINTF(out, MSG_DATA_LEN, format, pid, uid, inode, (u64)tmp, mode);
    if (search_file_audits(event, TRIGGER_OPEN, out) < 0)
    {
        ret = -1;
    }
    if (mode & MODE_READ)
    {
        if (search_file_audits(event, TRIGGER_OPEN_READ, out) < 0)
            ret = -1;
    }
    if (mode & MODE_WRITE)
    {
        if (search_file_audits(event, TRIGGER_OPEN_WRITE, out) < 0)
            ret = -1;
    }
    if ((mode & MODE_WRITE) && (mode & MODE_READ))
    {
        if (search_file_audits(event, TRIGGER_OPEN_RW, out) < 0)
            ret = -1;
    }

    return ret;
};
//static char link_out[MSG_DATA_LEN]; // stack is not enough in link
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
        goto exit;
    }
    int pid = bpf_get_current_pid_tgid() >> 32;
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
     char link_out[MSG_DATA_LEN] = {0};
    char buf[PATH_LEN / 2];
    //  char buf_[PATH_LEN / 2];
    // char buf_new[PATH_LEN / 2];
    get_dentry_path(old_dentry, buf, sizeof(buf));
    //   get_dentry_path(old_dentry, buf_, PATH_LEN / 2);
    //  bpf_printk("%s",buf);
    // struct qstr old = BPF_CORE_READ(old_dentry, d_name);
    // struct qstr new = BPF_CORE_READ(new_dentry, d_name);
    SNPRINTF(link_out, MSG_DATA_LEN, "process:[pid:%d] pid:%d user:[uid:%d] link %s -> ", MSG_DATA_LEN, pid, pid, uid, (u64)buf);
    // get_dentry_path(new_dentry, buf, sizeof(buf));
    // u32 index = bpf_strlen(link_out, MSG_DATA_LEN);
    // if (index < MSG_DATA_LEN)
    // {
    //     SNPRINTF((char *)link_out + index, MSG_DATA_LEN - index, "%s", (u64)buf);
    // }
    if (search_file_audits(event, TRIGGER_LINK, link_out) < 0)
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
    //  bpf_printk("unlink 1");
    struct file_audit_event *event = bpf_map_lookup_elem(&file_map, &inode);
    if (!event)
    {
        goto exit;
    }
    char out[MSG_DATA_LEN];
    char buf[PATH_LEN/2];
    // struct qstr name=BPF_CORE_READ(dentry_,d_name);
    int pid = bpf_get_current_pid_tgid() >> 32;
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    get_dentry_path(dentry_, buf, sizeof(buf));
    SNPRINTF(out, MSG_DATA_LEN, "process:[pid:%d] pid:%d user:[uid:%d] unlink path:%s", pid, pid, uid, (u64)buf);
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
        goto exit;
    }
    int pid = bpf_get_current_pid_tgid() >> 32;
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    char out[MSG_DATA_LEN];
    char buf[PATH_LEN/2];
    struct path p=BPF_CORE_READ(file,f_path);
    get_dentry_path(p.dentry,buf,sizeof(buf));
    const char *format = "process[pid:%d] pid:%d user:[uid:%d] truncate  path:%s";
    SNPRINTF(out, MSG_DATA_LEN, format, pid, pid, uid, (u64)buf);
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
        goto exit;
    }
    char out[MSG_DATA_LEN];
    char buf[PATH_LEN];
    int pid = bpf_get_current_pid_tgid() >> 32;
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    struct qstr q = BPF_CORE_READ(dentry, d_name);
    get_dentry_path(dentry, buf, PATH_LEN);
    SNPRINTF(out, MSG_DATA_LEN, "process[pid:%d] pid:%d user:[uid:%d] create_file: %s  ", pid, pid, uid, (__u64)buf);
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
        goto exit;
    }
    // bpf_printk("mkdir");
    char out[MSG_DATA_LEN];
    int pid = bpf_get_current_pid_tgid() >> 32;
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    char buf[PATH_LEN];
    get_dentry_path(dentry, buf, PATH_LEN);
    SNPRINTF(out, MSG_DATA_LEN, "process:[pid:%d] pid:%d user:[uid:%d] mkdir %s", pid, pid, uid, (u64)buf);
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
        goto exit;
    }
    // bpf_printk("rmdir");
    char out[MSG_DATA_LEN];
    int pid = bpf_get_current_pid_tgid() >> 32;
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    char buf[PATH_LEN];
    get_dentry_path(dentry, buf, PATH_LEN);
    SNPRINTF(out, MSG_DATA_LEN, "process:[pid:%d] pid:%d user:[uid:%d] rmdir %s", pid, pid, uid, (u64)buf);
    if (search_file_audits(event, TRIGGER_RMDIR, out) < 0)
        ret = -1;
exit:
    return ret;
}
