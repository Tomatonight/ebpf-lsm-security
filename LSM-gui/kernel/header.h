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
#define NAME_LEN 48
// #define FILENAME_LEN 256
#define MSG_DATA_LEN 150

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
#define MAX_AUDIT 15
#define LIMIT_MAX 10
#define SCALE_INCLUDE 0
#define SCALE_EXCLUDE 1
#define ACTION_RECORD 0x1
#define ACTION_DENY 0x2

#define CHARACTER_ALL -1
#define PROCESS_ALL -1

#define TRIGGER_OPEN 1
#define TRIGGER_OPEN_WRITE 2
#define TRIGGER_OPEN_READ 3
#define TRIGGER_OPEN_RW 4
#define TRIGGER_EXE 5
// #define TRIGGER_READ 0x6
#define TRIGGER_LINK 7
#define TRIGGER_UNLINK 8
#define TRIGGER_TRUNCATE 9
#define TRIGGER_CREATE_FILE 10
#define TRIGGER_MKDIR 11
#define TRIGGER_RMDIR 12
#define TRIGGER_DIR_RESTRICT 13
#define TRIGGER_DIR_RESTRICT_R 14
#define TRIGGER_DIR_RESTRICT_W 15
#define TRIGGER_DIR_RESTRICT_RW 16
#define TRIGGER_FILE_MMAP 17

#define TRIGGER_CREATE_THREAD 1 + 100
#define TRIGGER_FORK 2 + 100
#define TRIGGER_EXECVE 3 + 100
#define TRIGGER_KILL 4 + 100
#define TRIGGER_PTRACE 5 + 100
#define TRIGGER_PTRACEME 6 + 100
#define TRIGGER_SETUID 7 + 100
#define TRIGGER_SETGID 8 + 100
#define TRIGGER_TASK_FREE 9+100
#define TRIGGER_PRCTL 10+100

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
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); // 定义类型
    __type(key, u32);                        // 键类型
    __type(value, char[1024]);               // 值类型
    __uint(max_entries, 10);                 // 数组的最大大小
} ARRAY;
static char *get_buffer()
{
    int key = 0;
    return (char *)bpf_map_lookup_elem(&ARRAY, &key);
}
static char *get_buffer_(int key)
{
    return (char *)bpf_map_lookup_elem(&ARRAY, &key);
}
static void get_dentry_path(struct dentry *dentry, char *buf, u32 sz)
{
    char tmp;
    char *buffer = get_buffer_(1);
    if (!buffer)
        return;
    char *t = get_buffer_(2);
    if (!t)
        return;
    buffer[PATH_LEN - 1] = '\0';
    u32 now_index = PATH_LEN - 1;
    
    struct qstr q;
#pragma unroll
    for (int k = 0; k < 10; k++)
    {
        q = BPF_CORE_READ(dentry, d_name);
        u32 len = q.len;
        if (len > NAME_LEN - 1)
            len = NAME_LEN - 1;
        t[0] = '/';
        bpf_probe_read_kernel_str(&t[1], NAME_LEN - 1, q.name);
        if (len == 1 && t[1] == '/')
            break;
        now_index -= (len + 1);
        if(now_index>PATH_LEN)break;
#pragma unroll
        for (u32 i = 0; i < NAME_LEN; i++)
        {
            u32 j = now_index + i;
            if (j > PATH_LEN)
                break;
            if (t[i] == '\0')
                break;
            buffer[j] = t[i];
        }

        struct dentry *parent_dentry = BPF_CORE_READ(dentry, d_parent);
        if (parent_dentry == NULL)
            break;
        dentry = parent_dentry;
        //   if(now_index<PATH_LEN)
    }
    // #pragma unroll
    for (u32 i = 0; i < sz; i++, now_index++)
    {
        if (now_index < PATH_LEN)
        {
            bpf_probe_read_kernel(&tmp, 1, &buffer[now_index]);
            buf[i] = tmp;
            //  bpf_printk("%d %c",i, buffer[now_index + i]);
        }
    }
    buf[sz - 1] = '\0';
}
static void get_path_path(struct path *p, char *buffer, u32 sz)
{
    struct dentry *dentry = BPF_CORE_READ(p, dentry);
    if (!dentry)
        return;
    get_dentry_path(dentry, buffer, sz);
}
static void get_task_path(struct task_struct *task, char *buffer, u32 sz)
{
    // struct path* p=BPF_CORE_READ(task,mm,exe_file,f_path);
    struct path p = BPF_CORE_READ(task, mm, exe_file, f_path);
    get_path_path(&p, buffer, sz);
}
static void get_now_task_path(char *buffer, u32 sz)
{

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct path p = BPF_CORE_READ(task, mm, exe_file, f_path);
    get_path_path(&p, buffer, sz);
}
static u16 get_sock_protocol(struct socket *sock)
{
    return BPF_CORE_READ(sock, sk, sk_protocol);
}
static u16 get_sock_family(struct socket *sock)
{
    struct sock_common *skc = (struct sock_common *)BPF_CORE_READ(sock, sk);
    return BPF_CORE_READ(skc, skc_family);
}
static u32 get_sock_sip(struct socket *sock)
{
  
    struct inet_sock *inet = (struct inet_sock *)BPF_CORE_READ(sock, sk);
    return BPF_CORE_READ(inet, inet_saddr);
}
static u32 get_sock_dip(struct socket *sock)
{
    struct sock_common *skc = (struct sock_common *)BPF_CORE_READ(sock, sk);
    return BPF_CORE_READ(skc, skc_daddr);
}
static u16 get_sock_sport(struct socket *sock)
{
     struct inet_sock *inet = (struct inet_sock *)BPF_CORE_READ(sock, sk);
    return BPF_CORE_READ(inet, inet_sport);
}
static u16 get_sock_dport(struct socket *sock)
{
    struct sock_common *skc = (struct sock_common *)BPF_CORE_READ(sock, sk);
    return BPF_CORE_READ(skc, skc_dport);
}
#endif