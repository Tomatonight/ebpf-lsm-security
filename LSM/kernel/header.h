#ifndef HEADER_H
#define HEADER_H
#include <linux/module.h>
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/unistd.h>

#define PATH_LEN 128
//#define FILENAME_LEN 256
#define MSG_DATA_LEN 128

// #define TO_CONSOLE
#ifdef TO_CONSOLE
#define BPF_RING_OUTPUT(fmt, ...) \
    bpf_printk(fmt, ##__VA_ARGS__);
#else

#define BPF_RING_OUTPUT(fmt, ...)                                                    \
    {                                                                                \
        char *__buf = bpf_ringbuf_reserve(&RING, MSG_DATA_LEN, 0);                   \
        if (__buf)                                                                   \
        {                                                                            \
            __u64 data[] = {__VA_ARGS__};                                            \
            const char *format = fmt;                                                \
            int __n = bpf_snprintf(__buf, MSG_DATA_LEN, format, data, sizeof(data)); \
            bpf_ringbuf_submit(__buf, 0);                                            \
        }                                                                            \
    }

#endif
static __u32 bpf_strlen(char *str, u32 sz)
{
    __u32 len = 0;
#pragma unroll
    for (__u32 i = 0; i < sz; i++)
    {
        u8 t;
        bpf_probe_read_kernel(&t, sizeof(char), &str[i]);
        if (t == 0)
        {
            break;
        }
        len++;
    }
    return len;
}
#define SNPRINTF(__buf, __sz, fmt, ...)                              \
    {                                                                \
        __u64 __data[] = {__VA_ARGS__};                              \
        const char *__format = fmt;                                  \
        bpf_snprintf(__buf, __sz, __format, __data, sizeof(__data)); \
    }
/////////////////
// bool is_suid_file(const struct file *file);
// int get_dentry_inode(struct dentry *dentry);

static inline int get_exe_inode(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    return BPF_CORE_READ(task, mm, exe_file, f_inode, i_ino);
};
////////////////////////////////////

#define MAX_PATH_LEN 255
#define MAX_AUDIT 10

#define ACTION_RECORD 0x1
#define ACTION_DENY 0x2

#define CHARACTER_ALL -1
#define PROCESS_ALL -1

#define TRIGGER_OPEN 1
#define TRIGGER_OPEN_WRITE 2
#define TRIGGER_OPEN_READ 3
#define TRIGGER_OPEN_RW 4
// #define TRIGGER_WRITE 0x5
// #define TRIGGER_READ 0x6
#define TRIGGER_LINK 7
#define TRIGGER_UNLINK 8
#define TRIGGER_TRUNCATE 9
#define TRIGGER_CREATE_FILE 10
#define TRIGGER_MKDIR 11
#define TRIGGER_RMDIR 12

#define TRIGGER_CREATE_THREAD 1 + 100
#define TRIGGER_FORK 2 + 100
#define TRIGGER_EXECVE 3 + 100
#define TRIGGER_KILL 4 + 100
#define TRIGGER_PTRACE 5 + 100
#define TRIGGER_PTRACEME 6 + 100
#define TRIGGER_SETUID 7 + 100
#define TRIGGER_SETGID 8 + 100

#define TRIGGER_CREATE_SOCKET 1 + 1000
#define TRIGGER_LISTEN 2 + 1000
#define TRIGGER_SEND_MSG 3 + 1000
#define TRIGGER_RECV_MSG 4 + 1000
#define TRIGGER_BIND 5 + 1000
#define TRIGGER_CONNECT 6 + 1000
#define TRIGGER_ACCEPT 7 + 1000
#define TRIGGER_SHUTDOWN 8 + 1000

/*------------------------*/
#define CLONE_VM 0x00000100
#define CLONE_PTRACE 0x00002000
#define MODE_READ 0x1
#define MODE_WRITE 0x2

///////////////////
#define S_IFMT 00170000
#define S_IFREG 0100000
#define S_ISUID 0004000

#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#define S_ISSUID(m) (((m) & S_ISUID) != 0)

#define AF_INET 2
#define AF_INET6 10
// #define IPPROTO_TCP 6
// #define IPPROTO_UDP 17
// #define IPPROTO_ICMP 1
// #define IPPROTO_ICMPV6 58
// #define IPPROTO_RAW 255
///////////////////

// extern struct {
//     __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
//     __uint(max_entries, 128);
// } events;
// 从 struct dentry 获取路径
// extern struct {
//     __uint(type, BPF_MAP_TYPE_RINGBUF);
//     __uint(max_entries, 48 * 1024);
// } BUFFER;
extern struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 24 * 1024);
} RING;
extern struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 48 * 1024);
} BUFFER;

static void get_dentry_path(struct dentry *dentry, char *buf, u32 sz)
{
    char *buffer = bpf_ringbuf_reserve(&BUFFER, PATH_LEN, 0);
    if (!buffer)
        return;
    __builtin_memset(buffer, 0, PATH_LEN);
    char *t = bpf_ringbuf_reserve(&BUFFER, PATH_LEN, 0);
    if (!t)
    {
        bpf_ringbuf_discard(buffer, 0);
        return;
    }
    // char buffer[PATH_LEN];
    buffer[PATH_LEN - 1] = '\0';
    u32 now_index = PATH_LEN - 1;
    struct qstr q;
#pragma unroll
    for (int k = 0; k < 10; k++)
    {
        q = BPF_CORE_READ(dentry, d_name);
        u32 len = q.len;
        if (len > now_index)
            break;

        __builtin_memset(t, 0, PATH_LEN);
        t[0] = '/';
        bpf_probe_read_kernel_str(&t[1], PATH_LEN - 1, q.name);

        if (len == 1 && t[1] == '/')
            break;
        // bpf_printk("t:%s", t);
        now_index -= (len + 1);

#pragma unroll
        for (u32 i = 0; i < PATH_LEN && t[i] != '\0'; i++)
        {
            u32 x = now_index + i;
            if (x >= PATH_LEN)
                x = PATH_LEN - 1;
            if (PATH_LEN > x)
            {
                buffer[x] = t[i];
                // bpf_probe_read(&buffer[now_index + i],1,&t[i]);
            }
        }
        struct dentry *parent_dentry = BPF_CORE_READ(dentry, d_parent);
        if (parent_dentry == NULL)
            break;
        if (parent_dentry == dentry)
            break;
        dentry = parent_dentry;
        if (now_index == 0)
            break;
        //   if(now_index<PATH_LEN)  bpf_printk("xx %c", &buffer[now_index]);
    }
#pragma unroll
    for (u32 i = 0; i < sz; i++)
    {
        if (now_index + i < PATH_LEN)
        {
            buf[i] = buffer[now_index + i];
            //  bpf_printk("%d %c",i, buffer[now_index + i]);
        }
    }
    buf[sz - 1] = '\0';
    //  bpf_printk("%s",buf);
    bpf_ringbuf_discard(buffer, 0);
    bpf_ringbuf_discard(t, 0);
}
static void get_path_path(struct path *p, char *buffer, u32 sz)
{
    struct dentry *dentry = BPF_CORE_READ(p, dentry);
    if (!dentry)
        return;
    get_dentry_path(dentry, buffer, sz);
}
#endif