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
    //   struct network_audit *audit;
    if (!daddr)
        return 0;
    struct pkt_limit_v4 *limit = &audit->limit;
    bool ret = 1;
    __u32 sip = saddr->sin_addr.s_addr;
    __u16 sport = bpf_ntohs(saddr->sin_port);
    __u32 dip = daddr->sin_addr.s_addr;
    __u16 dport = bpf_ntohs(daddr->sin_port);
    if (limit->exclude_or_include)
        ret = 1;
    if (protocol != limit->protocol)
        ret = 0;
    else if ((sip & limit->ipv4.sip_mask) != (limit->ipv4.sip_mask & limit->ipv4.sip) || (dip & limit->ipv4.dip_mask) != (limit->ipv4.dip_mask & limit->ipv4.dip))
        ret = 0;
    else if (sport < limit->transport.sport_l || sport > limit->transport.sport_r)
        ret = 0;
    else if (dport < limit->transport.dport_l || dport > limit->transport.dport_r)
        ret = 0;

    if (limit->exclude_or_include)
        return !ret;
    return ret;
};
int search_net_audits(struct network_audit_events *events, int trigger, int protocol, struct sockaddr_in *addr,char* out)
{
    if (!events)
        return 0;
    int ret = 0;
    struct network_audit *audit = events->audits;
    struct sockaddr_in saddr = {.sin_addr = 0, .sin_family = 0, .sin_port = 0};
  //  bpf_printk("search\n");
    for (int i = 0; i < events->audit_nb && i < MAX_AUDIT; i++, audit++)
    {
        if (audit->trigger == trigger)
        {

            switch (trigger)
            {
            case TRIGGER_CONNECT:
            case TRIGGER_ACCEPT:
            {
                //   struct pkt_limit_v4 *limit= &audit->limit;

                if (!is_limit(audit, protocol, &saddr, addr))
                {
                    
                    continue;
                }
            }

            default:

                if (audit->action == ACTION_DENY)
                {
                    // to do
                    BPF_RING_OUTPUT("Deny %s\n",(__u64)out);
                    ret = -1;
                }
                else if (audit->action == ACTION_RECORD)
                {
                    BPF_RING_OUTPUT("Record %s\n",(__u64)out);
                    // to do
                }

                break;
            }
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
    char out[MSG_DATA_LEN];
    struct sockaddr_in addr;
    bpf_probe_read_kernel(&addr,sizeof(struct sockaddr),address);
    SNPRINTF(out,MSG_DATA_LEN,"process:[pid:%d] pid:%d bind [ip:%u] %d",pid,pid,addr.sin_addr.s_addr,bpf_ntohs(addr.sin_port));
    if (search_net_audits(pid_audits, TRIGGER_BIND, 0, 0,out) < 0)
    {
        ret = -1;
    }
    if (search_net_audits(inode_audits, TRIGGER_BIND, 0, 0,out) < 0)
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
    int protocol = BPF_CORE_READ(sock, sk, sk_protocol);
    struct sockaddr_in addr;
    bpf_probe_read(&addr, sizeof(struct sockaddr), address);
    char out[MSG_DATA_LEN];
    SNPRINTF(out,MSG_DATA_LEN,"process:[pid:%d] pid:%d user:[uid:%d] connect [ip:%u] port:%d",pid,pid,uid,addr.sin_addr.s_addr,bpf_ntohs(addr.sin_port));
    if (search_net_audits(pid_audits, TRIGGER_CONNECT, protocol, &addr,out) < 0)
    {
        ret = -1;
    }
    if (search_net_audits(inode_audits, TRIGGER_CONNECT, protocol, &addr,out) < 0)
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
    char out[MSG_DATA_LEN];
    SNPRINTF(out,MSG_DATA_LEN,"process:[pid:%d] pid:%d user:[uid:%d] listen",pid,pid,uid);
    if (search_net_audits(pid_audits, TRIGGER_LISTEN, 0, 0,out) < 0)
    {
        ret = -1;
    }
    if (search_net_audits(inode_audits, TRIGGER_LISTEN, 0, 0,out) < 0)
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
    int protocol = BPF_CORE_READ(newsock, sk, sk_protocol);
    struct sock_common *skc = (struct sock_common *)BPF_CORE_READ(newsock, sk);
    int sk_family=BPF_CORE_READ(skc,skc_family);
    if(sk_family!=AF_INET)return 0;
    u32 dip = BPF_CORE_READ(skc, skc_daddr);
    u16 dport = BPF_CORE_READ(skc, skc_dport);
    struct sockaddr_in addr = {.sin_addr.s_addr = dip, .sin_port = dport};
    char out[MSG_DATA_LEN];
    SNPRINTF(out,MSG_DATA_LEN,"process:[pid:%d] pid:%d user:[uid:%d] accept [ip:%u] %d",pid,pid,uid,addr.sin_addr.s_addr,bpf_ntohs(addr.sin_port));
    if (search_net_audits(pid_audits, TRIGGER_ACCEPT, protocol, &addr,out) < 0)
    {
        ret = -1;
    }
    if (search_net_audits(inode_audits, TRIGGER_ACCEPT, protocol, &addr,out) < 0)
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
    struct msg_name *msg_name = BPF_CORE_READ(msg, msg_name);
    if (!msg_name)
        return 0;
    struct sockaddr_in addr;
    bpf_probe_read(&addr, sizeof(struct sockaddr_in), msg_name);
    if (addr.sin_family != AF_INET)
        return 0;
    int protocol = BPF_CORE_READ(sock, sk, sk_protocol);
    u32 dip = addr.sin_addr.s_addr;
    u16 dport = addr.sin_port;
    struct sockaddr_in address = {.sin_addr.s_addr = dip, .sin_port = dport};
    char out[MSG_DATA_LEN];
    SNPRINTF(out,MSG_DATA_LEN,"process:[pid:%d] pid:%d user:[uid%d] sendmsg %d to [ip:%u] %d",pid,pid,uid,size,dip,bpf_ntohs(address.sin_port));
    if (search_net_audits(pid_audits, TRIGGER_ACCEPT, protocol, &address,out) < 0)
    {
        ret = -1;
    }
    if (search_net_audits(inode_audits, TRIGGER_ACCEPT, protocol, &address,out) < 0)
    {
        ret = -1;
    }
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
    struct msg_name *msg_name = BPF_CORE_READ(msg, msg_name);
    if (!msg_name)
        return 0;
    struct sockaddr_in addr;
    bpf_probe_read(&addr,sizeof(struct  sockaddr_in),msg_name);
    if(addr.sin_family!=AF_INET)return 0;
    int protocol = BPF_CORE_READ(sock, sk, sk_protocol);
    u32 dip = addr.sin_addr.s_addr;
    u16 dport = addr.sin_port;
    struct sockaddr_in address = {.sin_addr.s_addr = dip, .sin_port = dport};
    char out[MSG_DATA_LEN];
    SNPRINTF(out,MSG_DATA_LEN,"process:[pid:%d] pid:%d user:[uid%d] recvmsg %d to [ip:%u] %d",pid,pid,uid,size,dip,bpf_ntohs(address.sin_port));
    if (search_net_audits(pid_audits, TRIGGER_ACCEPT, protocol, &address,out) < 0)
    {
        ret = -1;
    }
    if (search_net_audits(inode_audits, TRIGGER_ACCEPT, protocol, &address,out) < 0)
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
    char out[MSG_DATA_LEN];
    SNPRINTF(out,MSG_DATA_LEN,"process[pid:%d] pid:%d user:[uid:%d] create socket family:%d type:%d protocol:%d",pid,pid,uid,family,type,protocol);
    if (search_net_audits(pid_audits, TRIGGER_SHUTDOWN, 0, 0,out) < 0)
    {
        ret = -1;
    }
    if (search_net_audits(inode_audits, TRIGGER_SHUTDOWN, 0, 0,out) < 0)
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
    char out[MSG_DATA_LEN];
    if(how==SHUTDOWN_R)
    {
    SNPRINTF(out,MSG_DATA_LEN,"process:[pid:%d] pid: %d user:[uid:%d] shutdown sock R",pid,pid,uid);
    }
    else if(how==SHUTDOWN_W)
    {
    SNPRINTF(out,MSG_DATA_LEN,"process:[pid:%d] pid: %d user:[uid:%d] shutdown sock W",pid,pid,uid);
    }
    else if(how==SHUTDOWN_RW)
    {
    SNPRINTF(out,MSG_DATA_LEN,"process:[pid:%d] pid: %d user:[uid:%d] shutdown sock RW",pid,pid,uid);
    }
    else bpf_printk("shutdown how err");
    if (search_net_audits(pid_audits, TRIGGER_SHUTDOWN, 0, 0,out) < 0)
    {
        ret = -1;
    }
    if (search_net_audits(inode_audits, TRIGGER_SHUTDOWN, 0, 0,out) < 0)
    {
        ret = -1;
    }
    return ret;
};
