#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 24 * 1024);
} RING SEC(".maps");
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 5* 1024);
} BUFFER SEC(".maps");
// int is_suid_file(const struct file *file)
// {
//     umode_t mode = BPF_CORE_READ(file, f_inode, i_mode);
//     return S_ISREG(mode) && S_ISSUID(mode);
// }

// int get_dentry_inode(struct dentry *dentry)
// {
//     return BPF_CORE_READ(dentry, d_inode, i_ino);
// }
// void get_full_path(struct path *path, char *buffer, unsigned int size)
// {
//     u32 len;
//     if (size <= MAX_PATH_LEN)
//         len = bpf_d_path(path, buffer, size);
//     char t = 0;
//     for (int i = MAX_PATH_LEN - 1; i >= 0 && i > len; i--)
//     {
//         if (buffer[i] == 0)
//             break;
//         bpf_probe_read(&buffer[i], 1, &t);
//     }
// };


// struct
// {
//     __uint(type, BPF_MAP_TYPE_RINGBUF);
//     __uint(max_entries, 48 * 1024);
// } BUFFER SEC(".maps");

// int get_dentry_path(struct dentry *dentry, char *buf, u32 sz)
// {

//     //   char* buffer=bpf_ringbuf_reserve(&BUFFER,PATH_LEN,0);
//     char buffer[PATH_LEN];
//     buffer[PATH_LEN - 1] = '\0';
//     u32 now_index = PATH_LEN - 1;
//     struct qstr q;
// #pragma unroll
//     for (int k = 0; k < 10; k++)
//     {
//         q = BPF_CORE_READ(dentry, d_name);
//         u32 len = q.len;
//         if (len > now_index)
//             break;

//         char t[FILENAME_LEN] = {0};
//         t[0] = '/';
//         bpf_probe_read_kernel(&t[1], sizeof(t) - 1, q.name);
//         if (len == 1 && t[1] == '/')
//             break;
//         now_index -= (len + 1);

// #pragma unroll
//         for (u32 i = 0; i < sizeof(t) && t[i] != '\0'; i++)
//         {
//             u32 x = now_index + i;
//             if (x < PATH_LEN)
//                 buffer[x] = t[i];
//         }
//         struct dentry *parent_dentry = BPF_CORE_READ(dentry, d_parent);
//         if (parent_dentry == NULL)
//             break;
//         if (parent_dentry == dentry)
//             break;
//         dentry = parent_dentry;
//         if (now_index == 0)
//             break;
//         //   if(now_index<PATH_LEN)  bpf_printk("xx %c", &buffer[now_index]);
//     }
// #pragma unroll
//     for (u32 i = 0; i < sz; i++)
//     {
//         if (now_index + i < PATH_LEN)
//         {
//             buf[i] = buffer[now_index + i];
//         }
//     }
//     buf[sz - 1] = '\0';
//     //  bpf_ringbuf_discard(buffer,0);
//     return 0;
// }