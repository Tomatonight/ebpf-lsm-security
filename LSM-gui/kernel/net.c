#include "vmlinux.h"
#include <linux/module.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/unistd.h>
#include "header.h"
// extern struct {
//     __uint(type, BPF_MAP_TYPE_RINGBUF);
//     __uint(max_entries, 24 * 1024);
// } RING;
// extern struct {
//     __uint(type, BPF_MAP_TYPE_RINGBUF);
//     __uint(max_entries, 48 * 1024);
// } BUFFER;
struct ipv4_data
{
    u32 sip;
    u32 dip;
    u32 sip_mask;
    u32 dip_mask;
};
struct transport_data
{
    u16 sport_l;
    u16 sport_r;
    u16 dport_l;
    u16 dport_r;
};
struct pkt_limit_v4
{
    bool ignore;
    bool exclude_or_include;
    int protocol;
    struct ipv4_data ipv4;
    struct transport_data transport;
};
struct network_audit
{
    int trigger;
    int action;
    struct pkt_limit_v4 limit;
};

// struct create_socket_data
// {
//     int nb;
//     int ban_protocol[10];
// };
// struct shutdown_data
// {
//     int close_action;
// };
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048);
    __type(key, int);
    __type(value, struct network_audit_events);
} net_pid_map SEC(".maps");
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048);
    __type(key, int);
    __type(value, struct network_audit_events);
} net_inode_map SEC(".maps");

struct network_audit_events
{
    union
    {
        int pid;
        int exe_inode;
    };
    int audit_nb;
    struct network_audit audits[MAX_AUDIT];
};

/*
LSM_HOOK(int, 0, socket_bind, struct socket *sock, struct sockaddr *address,
     int addrlen)
LSM_HOOK(int, 0, socket_connect, struct socket *sock, struct sockaddr *address,
     int addrlen)
LSM_HOOK(int, 0, socket_listen, struct socket *sock, int backlog)
LSM_HOOK(int, 0, socket_accept, struct socket *sock, struct socket *newsock)
LSM_HOOK(int, 0, socket_sendmsg, struct socket *sock, struct msghdr *msg,
     int size)
LSM_HOOK(int, 0, socket_recvmsg, struct socket *sock, struct msghdr *msg,
     int size, int flags)
LSM_HOOK(int, 0, socket_create, int family, int type, int protocol, int kern)
LSM_HOOK(int, 0, socket_shutdown, struct socket *sock, int how)
LSM_HOOK(int, 0, socket_sock_rcv_skb, struct sock *sk, struct sk_buff *skb)
*/
bool is_limit(struct network_audit *audit, int protocol, struct sockaddr_in *saddr, struct sockaddr_in *daddr)
{
    if (!audit)
        return 0;
    struct pkt_limit_v4 *limit = &audit->limit;
    if (limit->ignore)
        return 1;
    bool ret = 1;
    __u32 sip, dip;
    __u16 sport, dport;
    if (!limit)
        return 0;
    if (protocol != limit->protocol && limit->protocol != IPPROTO_IP)
        ret = 0;

    if (saddr)
    {
        sip = saddr->sin_addr.s_addr;
        sport = bpf_ntohs(saddr->sin_port);
    }
    if (daddr)
    {
        dip = daddr->sin_addr.s_addr;
        dport = bpf_ntohs(daddr->sin_port);
    }
    if (saddr)
    {
        if ((sip & limit->ipv4.sip_mask) != (limit->ipv4.sip_mask & limit->ipv4.sip))
        {
            ret = 0;
        }
        else if (sport < limit->transport.sport_l || sport > limit->transport.sport_r)
        {
            ret = 0;
        }
    }
    if (daddr)
    {
        if ((dip & limit->ipv4.dip_mask) != (limit->ipv4.dip_mask & limit->ipv4.dip))
        {
            ret = 0;
        }
        else if (dport < limit->transport.dport_l || dport > limit->transport.dport_r)
        {
            ret = 0;
        }
    }
    if (limit->exclude_or_include)
        ret = !ret;

    return ret;
};
struct var_tmp
{
    struct sockaddr_in *saddr;
    struct sockaddr_in *daddr;
    char *out;
};
int search_net_audits__(struct network_audit_events *events, int trigger, int protocol, struct var_tmp *var)
{
    if (!var)
        return 0;
    struct sockaddr_in saddr;
    bpf_probe_read(&saddr, sizeof(struct sockaddr), var->saddr);
    struct sockaddr_in daddr;
    bpf_probe_read(&daddr, sizeof(struct sockaddr), var->daddr);
    char *out = var->out;
    if (!events)
        return 0;
    int ret = 0;
    struct network_audit *audit = events->audits;

    // bpf_printk("search\n");
    for (int i = 0; i < events->audit_nb && i < MAX_AUDIT; i++, audit++)
    {
        if (audit->trigger == trigger)
        {
            //    bpf_printk("test");
            //   struct pkt_limit_v4 *limit= &audit->limit;
            if (!is_limit(audit, protocol, &saddr, &daddr))
            {
                continue;
            }
            if (audit->action == ACTION_DENY)
            {
                BPF_RING_OUTPUT("[time:]\nDeny %s\n", (__u64)out);
                ret = -1;
            }
            else if (audit->action == ACTION_RECORD)
            {
                BPF_RING_OUTPUT("[time:]\nRecord %s\n", (__u64)out);
                // to do
            }
            break;
        }
    }
    return ret;
}
int search_net_audits(struct network_audit_events *events, int trigger, char *out)
{
    if (!events)
        return 0;
    int ret = 0;
    struct network_audit *audit = events->audits;
    //  bpf_printk("search\n");
    for (int i = 0; i < events->audit_nb && i < MAX_AUDIT; i++, audit++)
    {
        if (audit->trigger == trigger)
        {
            //   struct pkt_limit_v4 *limit= &audit->limit;
            if (audit->action == ACTION_DENY)
            {
                BPF_RING_OUTPUT("[time:]\nDeny %s\n", (__u64)out);
                ret = -1;
            }
            else if (audit->action == ACTION_RECORD)
            {
                BPF_RING_OUTPUT("[time:]\nRecord %s\n", (__u64)out);
                // to do
            }
            break;
        }
    }
    return ret;
}
SEC("lsm/socket_bind")
int BPF_PROG(lsm_socket_bind, struct socket *sock, struct sockaddr *address, int addrlen)
{
    int ret = 0;
    int pid = bpf_get_current_pid_tgid() >> 32;
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    struct task_struct *now_task = (struct task_struct *)bpf_get_current_task();
    int exe_inode = BPF_CORE_READ(now_task, mm, exe_file, f_inode, i_ino);
    struct network_audit_events *pid_audits = bpf_map_lookup_elem(&net_pid_map, &pid);
    struct network_audit_events *inode_audits = bpf_map_lookup_elem(&net_inode_map, &exe_inode);
    if (((u64)pid_audits + (u64)inode_audits) == 0)
        return 0;
    char *out = get_buffer();
    if (!out)
        return 0;
    char process_path[PATH_LEN];
    get_now_task_path(process_path, PATH_LEN);
    //  bpf_printk("test %s",process_path);
    struct sockaddr_in saddr;
    int protocol = get_sock_protocol(sock);
    bpf_probe_read_kernel(&saddr, sizeof(struct sockaddr), address);
    SNPRINTF(out, MSG_DATA_LEN, "process:%s pid:%d uid:[uid:%d] bind [ip:%u]:%d", (u64)process_path, pid, uid, saddr.sin_addr.s_addr, bpf_ntohs(saddr.sin_port));
    struct var_tmp var = {.saddr = &saddr, .daddr = NULL, .out = out};
    if (search_net_audits__(pid_audits, TRIGGER_BIND, protocol, &var) < 0)
    {
        ret = -1;
    }
    else if (search_net_audits__(inode_audits, TRIGGER_BIND, protocol, &var) < 0)
    {
        ret = -1;
    }
    return ret;
};
SEC("lsm/socket_connect")
int BPF_PROG(lsm_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    int ret = 0;
    int pid = bpf_get_current_pid_tgid() >> 32;
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    struct task_struct *now_task = (struct task_struct *)bpf_get_current_task();
    int exe_inode = BPF_CORE_READ(now_task, mm, exe_file, f_inode, i_ino);
    struct network_audit_events *pid_audits = bpf_map_lookup_elem(&net_pid_map, &pid);
    struct network_audit_events *inode_audits = bpf_map_lookup_elem(&net_inode_map, &exe_inode);
    if (((u64)pid_audits + (u64)inode_audits) == 0)
        return 0;
    // bpf_printk("connect");
    int protocol = get_sock_protocol(sock);
    struct sockaddr_in daddr;
    bpf_probe_read(&daddr, sizeof(struct sockaddr), address);
    if (daddr.sin_family != AF_INET)
        return 0;
    char *out = get_buffer();
    if (!out)
        return 0;
    char process_path[PATH_LEN];
    get_now_task_path(process_path, PATH_LEN);
    SNPRINTF(out, MSG_DATA_LEN, "process:%s pid:%d user:[uid:%d] connect [ip:%u] port:%d", (u64)process_path, pid, uid, daddr.sin_addr.s_addr, bpf_ntohs(daddr.sin_port));
    struct var_tmp var = {.saddr = NULL, .daddr = &daddr, .out = out};
    if (search_net_audits__(pid_audits, TRIGGER_CONNECT, protocol, &var) < 0)
    {
        ret = -1;
    }
    else if (search_net_audits__(inode_audits, TRIGGER_CONNECT, protocol, &var) < 0)
    {
        ret = -1;
    }
    return ret;
};
SEC("lsm/socket_listen")
int BPF_PROG(lsm_socket_listen, struct socket *sock, int backlog)
{
    int ret = 0;
    int pid = bpf_get_current_pid_tgid() >> 32;
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    struct task_struct *now_task = (struct task_struct *)bpf_get_current_task();
    int exe_inode = BPF_CORE_READ(now_task, mm, exe_file, f_inode, i_ino);
    struct network_audit_events *pid_audits = bpf_map_lookup_elem(&net_pid_map, &pid);
    struct network_audit_events *inode_audits = bpf_map_lookup_elem(&net_inode_map, &exe_inode);
    if (((u64)pid_audits + (u64)inode_audits) == 0)
        return 0;
    int protocol = get_sock_protocol(sock);
    u16 sk_family = get_sock_family(sock);
    if (sk_family != AF_INET)
        return 0;
    char *out = get_buffer();
    if (!out)
        return 0;
    char process_path[PATH_LEN];
    get_now_task_path(process_path, PATH_LEN);
    u32 sip = get_sock_sip(sock);
    u16 sport = get_sock_sport(sock);
    SNPRINTF(out, MSG_DATA_LEN, "process:%s pid:%d user:[uid:%d] listen [ip:%u]:%d", (u64)process_path, pid, uid, sip, bpf_ntohs(sport));
    if (search_net_audits(pid_audits, TRIGGER_LISTEN, out) < 0)
    {
        ret = -1;
    }
    else if (search_net_audits(inode_audits, TRIGGER_LISTEN, out) < 0)
    {
        ret = -1;
    }
    return ret;
};
SEC("lsm/socket_accept")
int BPF_PROG(lsm_socket_accept, struct socket *sock, struct socket *newsock)
{
    int ret = 0;
    int pid = bpf_get_current_pid_tgid() >> 32;
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    struct task_struct *now_task = (struct task_struct *)bpf_get_current_task();
    int exe_inode = BPF_CORE_READ(now_task, mm, exe_file, f_inode, i_ino);
    struct network_audit_events *pid_audits = bpf_map_lookup_elem(&net_pid_map, &pid);
    struct network_audit_events *inode_audits = bpf_map_lookup_elem(&net_inode_map, &exe_inode);
    if (((u64)pid_audits + (u64)inode_audits) == 0)
        return 0;
    int protocol = BPF_CORE_READ(newsock, sk, sk_protocol);
    struct sock_common *skc = (struct sock_common *)BPF_CORE_READ(newsock, sk);
    int sk_family = BPF_CORE_READ(skc, skc_family);
    if (sk_family != AF_INET)
        return 0;
    u32 dip = BPF_CORE_READ(skc, skc_daddr);
    u16 dport = BPF_CORE_READ(skc, skc_dport);
    struct sockaddr_in daddr = {.sin_addr.s_addr = dip, .sin_port = dport};
    char *out = get_buffer();
    if (!out)
        return 0;
    char process_path[PATH_LEN];
    get_now_task_path(process_path, PATH_LEN);
    SNPRINTF(out, MSG_DATA_LEN, "process:%s pid:%d user:[uid:%d] accept [ip:%u] %d", (u64)process_path, pid, uid, daddr.sin_addr.s_addr, bpf_ntohs(daddr.sin_port));
    struct var_tmp var = {.saddr = NULL, .daddr = &daddr, .out = out};
    if (search_net_audits__(pid_audits, TRIGGER_ACCEPT, protocol, &var) < 0)
    {
        ret = -1;
    }
    else if (search_net_audits__(inode_audits, TRIGGER_ACCEPT, protocol, &var) < 0)
    {
        ret = -1;
    }
    return ret;
};
SEC("lsm/socket_sendmsg")
int BPF_PROG(lsm_socket_sendmsg, struct socket *sock, struct msghdr *msg, int size)
{
    int ret = 0;
    int pid = bpf_get_current_pid_tgid() >> 32;
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    struct task_struct *now_task = (struct task_struct *)bpf_get_current_task();
    int exe_inode = BPF_CORE_READ(now_task, mm, exe_file, f_inode, i_ino);
    struct network_audit_events *pid_audits = bpf_map_lookup_elem(&net_pid_map, &pid);
    struct network_audit_events *inode_audits = bpf_map_lookup_elem(&net_inode_map, &exe_inode);
    if (((u64)pid_audits + (u64)inode_audits) == 0)
        return 0;
    // bpf_printk("send a\n");
    char *out = get_buffer();
    if (!out)
        return 0;
    char process_path[PATH_LEN];
    get_now_task_path(process_path, PATH_LEN);
    struct sockaddr_in daddr;
    u16 protocol = get_sock_protocol(sock);
    u16 family = get_sock_family(sock);
    if (family != AF_INET)
        return 0;
    //     bpf_printk("send b\n");
    struct msg_name *msg_name = BPF_CORE_READ(msg, msg_name);
    switch (protocol)
    {
    case IPPROTO_TCP:
    {
        daddr.sin_addr.s_addr = get_sock_dip(sock);
        daddr.sin_port = get_sock_dport(sock);
        daddr.sin_family = AF_INET;
        u32 sip = get_sock_sip(sock);
        u16 sport = get_sock_sport(sock);
        SNPRINTF(out, MSG_DATA_LEN, "process:%s pid:%d user:[uid:%d] sendmsg %d (tcp) [ip:%u]:%d->[ip:%u]:%d",
                 (u64)process_path, pid, uid, size, sip, bpf_ntohs(sport), daddr.sin_addr.s_addr, bpf_ntohs(daddr.sin_port));
        break;
    }
    case IPPROTO_UDP:
    {
        struct msg_name *msg_name = BPF_CORE_READ(msg, msg_name);
        if (msg_name)
        {
            bpf_probe_read(&daddr, sizeof(struct sockaddr_in), msg_name);
        }
        else
        {
            daddr.sin_addr.s_addr = get_sock_dip(sock);
            daddr.sin_port = get_sock_dport(sock);
            daddr.sin_family = AF_INET;
        }
        u32 sip = get_sock_sip(sock);
        u16 sport = get_sock_sport(sock);
        SNPRINTF(out, MSG_DATA_LEN, "process:%s pid:%d user:[uid:%d] sendmsg %d (udp) [ip:%u]:%d->[ip:%u]:%d",
                 (u64)process_path, pid, uid, size, sip, bpf_ntohs(sport), daddr.sin_addr.s_addr, bpf_ntohs(daddr.sin_port));
        break;
    }
    case IPPROTO_ICMP:
    {
        struct msg_name *msg_name = BPF_CORE_READ(msg, msg_name);
        u32 dip;
        u16 sip = get_sock_sip(sock);
        if (msg_name)
        {
            bpf_probe_read(&daddr, sizeof(struct sockaddr_in), msg_name);
            dip = daddr.sin_addr.s_addr;
        }
        else
        {
            dip = get_sock_dip(sock);
        }
        SNPRINTF(out, MSG_DATA_LEN, "process:%s pid:%d user:[uid:%d] sendmsg %d (icmp) [ip:%u]->[ip:%u]",
                 (u64)process_path, pid, uid, size, sip, daddr.sin_addr.s_addr);
        break;
    }
    default:
    {
        SNPRINTF(out, MSG_DATA_LEN, "process:%s pid:%d user:[uid:%d] sendmsg %d (protocol unsupport)",
                 (u64)process_path, pid, uid, size);
    }
    }
    //  bpf_printk("send c\n");
    struct var_tmp var = {.saddr = NULL, .daddr = &daddr, .out = out};
    if (search_net_audits__(pid_audits, TRIGGER_SEND_MSG, protocol, &var) < 0)
    {
        ret = -1;
    }
    else if (search_net_audits__(inode_audits, TRIGGER_SEND_MSG, protocol, &var) < 0)
    {
        ret = -1;
    }
    //     bpf_printk("send d %d\n",ret);
    return ret;
};
SEC("lsm/socket_recvmsg")
int BPF_PROG(lsm_socket_recvmsg, struct socket *sock, struct msghdr *msg, int size, int flags)
{
    int ret = 0;
    int pid = bpf_get_current_pid_tgid() >> 32;
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    struct task_struct *now_task = (struct task_struct *)bpf_get_current_task();
    int exe_inode = BPF_CORE_READ(now_task, mm, exe_file, f_inode, i_ino);
    struct network_audit_events *pid_audits = bpf_map_lookup_elem(&net_pid_map, &pid);
    struct network_audit_events *inode_audits = bpf_map_lookup_elem(&net_inode_map, &exe_inode);
    if (((u64)pid_audits + (u64)inode_audits) == 0)
        return 0;
    // u32 sz=BPF_CORE_READ(msg,msg_iter.count);
    char *out = get_buffer();
    if (!out)
        return 0;
    char process_path[PATH_LEN];
    get_now_task_path(process_path, PATH_LEN);
    struct sockaddr_in daddr;
    u16 protocol = get_sock_protocol(sock);
    u16 family = get_sock_family(sock);
    if (family != AF_INET)
        return 0;

    struct msg_name *msg_name = BPF_CORE_READ(msg, msg_name);
    switch (protocol)
    {
    case IPPROTO_TCP:
    {
        daddr.sin_addr.s_addr = get_sock_dip(sock);
        daddr.sin_port = get_sock_dport(sock);
        daddr.sin_family = AF_INET;
        u32 sip = get_sock_sip(sock);
        u16 sport = get_sock_sport(sock);
        SNPRINTF(out, MSG_DATA_LEN, "process:%s pid:%d user:[uid:%d] recvmsg (tcp) [ip:%u]:%d<-[ip:%u]:%d",
                 (u64)process_path, pid, uid,  sip, bpf_ntohs(sport), daddr.sin_addr.s_addr, bpf_ntohs(daddr.sin_port));
        break;
    }
    case IPPROTO_UDP:
    {
        struct msg_name *msg_name = BPF_CORE_READ(msg, msg_name);
        if (msg_name)
        {
            bpf_probe_read(&daddr, sizeof(struct sockaddr_in), msg_name);
        }
        else
        {
            daddr.sin_addr.s_addr = get_sock_dip(sock);
            daddr.sin_port = get_sock_dport(sock);
            daddr.sin_family = AF_INET;
        }
        u32 sip = get_sock_sip(sock);
        u16 sport = get_sock_sport(sock);
        SNPRINTF(out, MSG_DATA_LEN, "process:%s pid:%d user:[uid:%d] recvmsg (udp) [ip:%u]:%d<-[ip:%u]:%d",
                 (u64)process_path, pid, uid,  sip, bpf_ntohs(sport), daddr.sin_addr.s_addr, bpf_ntohs(daddr.sin_port));
        break;
    }
    case IPPROTO_ICMP:
    {
        struct msg_name *msg_name = BPF_CORE_READ(msg, msg_name);
        u32 dip;
        u16 sip = get_sock_sip(sock);
        if (msg_name)
        {
            bpf_probe_read(&daddr, sizeof(struct sockaddr_in), msg_name);
            dip = daddr.sin_addr.s_addr;
        }
        else
        {
            dip = get_sock_dip(sock);
        }
        SNPRINTF(out, MSG_DATA_LEN, "process:%s pid:%d user:[uid:%d] recvmsg (icmp) [ip:%u]<-[ip:%u]",
                 (u64)process_path, pid, uid,  sip, daddr.sin_addr.s_addr);
        break;
    }
    default:
    {
        SNPRINTF(out, MSG_DATA_LEN, "process:%s pid:%d user:[uid:%d] recvmsg (protocol unsupport)",
                 (u64)process_path, pid, uid);
    }
    }
    struct var_tmp var = {.saddr = NULL, .daddr = &daddr, .out = out};
    if (search_net_audits__(pid_audits, TRIGGER_RECV_MSG, protocol, &var) < 0)
    {
        ret = -1;
    }
    else if (search_net_audits__(inode_audits, TRIGGER_RECV_MSG, protocol, &var) < 0)
    {
        ret = -1;
    }
    return ret;
};
SEC("lsm/socket_create")
int BPF_PROG(lsm_socket_create, int family, int type, int protocol, int kern)
{
    int ret = 0;
    int pid = bpf_get_current_pid_tgid() >> 32;
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    struct task_struct *now_task = (struct task_struct *)bpf_get_current_task();
    int exe_inode = BPF_CORE_READ(now_task, mm, exe_file, f_inode, i_ino);
    struct network_audit_events *pid_audits = bpf_map_lookup_elem(&net_pid_map, &pid);
    struct network_audit_events *inode_audits = bpf_map_lookup_elem(&net_inode_map, &exe_inode);
    if (((u64)pid_audits + (u64)inode_audits) == 0)
        return 0;
    char *out = get_buffer();
    if (!out)
        return 0;
    char process_path[PATH_LEN];
    get_now_task_path(process_path, PATH_LEN);
    SNPRINTF(out, MSG_DATA_LEN, "process:%s pid:%d user:[uid:%d] create socket family:%d type:%d protocol:%d", (u64)process_path, pid, uid, family, type, protocol);
    if (search_net_audits(pid_audits, TRIGGER_CREATE_SOCKET, out) < 0)
    {
        ret = -1;
    }
    else if (search_net_audits(inode_audits, TRIGGER_CREATE_SOCKET, out) < 0)
    {
        ret = -1;
    }
    return ret;
};
#define SHUTDOWN_R 0
#define SHUTDOWN_W 1
#define SHUTDOWN_RW 2
SEC("lsm/socket_shutdown")
int BPF_PROG(lsm_socket_shutdown, struct socket *sock, int how)
{
    int ret = 0;
    int pid = bpf_get_current_pid_tgid() >> 32;
    int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    struct task_struct *now_task = (struct task_struct *)bpf_get_current_task();
    int exe_inode = BPF_CORE_READ(now_task, mm, exe_file, f_inode, i_ino);
    struct network_audit_events *pid_audits = bpf_map_lookup_elem(&net_pid_map, &pid);
    struct network_audit_events *inode_audits = bpf_map_lookup_elem(&net_inode_map, &exe_inode);
 //   bpf_printk("test\n");
    if (((u64)pid_audits + (u64)inode_audits) == 0)
        return 0;
    
    char *out = get_buffer();
    if (!out)
        return 0;
    char process_path[PATH_LEN];
    get_now_task_path(process_path, PATH_LEN);
    if (how == SHUTDOWN_R)
    {
        SNPRINTF(out, MSG_DATA_LEN, "process:%s pid:%d user:[uid:%d] shutdown sock R", (u64)process_path, pid, uid);
    }
    else if (how == SHUTDOWN_W)
    {
        SNPRINTF(out, MSG_DATA_LEN, "process:%s pid:%d user:[uid:%d] shutdown sock W", (u64)process_path, pid, uid);
    }
    else if (how == SHUTDOWN_RW)
    {
        SNPRINTF(out, MSG_DATA_LEN, "process:%s pid:%d user:[uid:%d] shutdown sock RW", (u64)process_path, pid, uid);
    }
    else
        bpf_printk("shutdown how err");
    if (search_net_audits(pid_audits, TRIGGER_SHUTDOWN, out) < 0)
    {
        ret = -1;
    }
    else if (search_net_audits(inode_audits, TRIGGER_SHUTDOWN, out) < 0)
    {
        ret = -1;
    }
    return ret;
};
