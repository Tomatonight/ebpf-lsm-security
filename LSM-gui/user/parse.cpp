#include "parse.h"
#include <unistd.h>
#include <iostream>
#include <sys/stat.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <vector>
#include <bpf/bpf.h>
#include <fstream>
using json = nlohmann::json;
/*-----------------*/
/*-----------------*/
extern int file_map;
#define MAX_PATH_LEN 256
#define MAX_AUDIT 15
#define LIMIT_MAX 10
#define PRIVATE_DATA_SIZE 128
#define ACTION_RECORD 0x1
#define ACTION_DENY 0x2
static std::vector<std::pair<std::string, int>> Actions =
    {{"record", ACTION_RECORD}, {"deny", ACTION_DENY}};
//
#define TRIGGER_OPEN 1
#define TRIGGER_OPEN_WRITE 2
#define TRIGGER_OPEN_READ 3
#define TRIGGER_OPEN_RW 4
#define TRIGGER_EXE 5
// #define TRIGGER_WRITE 0x5
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
#define TRIGGER_TASK_FREE 9 + 100
#define TRIGGER_PRCTL 10 + 100

#define TRIGGER_CREATE_SOCKET 1 + 1000
#define TRIGGER_LISTEN 2 + 1000
#define TRIGGER_SEND_MSG 3 + 1000
#define TRIGGER_RECV_MSG 4 + 1000
#define TRIGGER_BIND 5 + 1000
#define TRIGGER_CONNECT 6 + 1000
#define TRIGGER_ACCEPT 7 + 1000
#define TRIGGER_SHUTDOWN 8 + 1000

static std::vector<std::pair<std::string, int>> Triggers =
    {{"open", TRIGGER_OPEN}, {"file_mmap", TRIGGER_FILE_MMAP}, {"dir_restrict", TRIGGER_DIR_RESTRICT}, {"dir_restrict_r", TRIGGER_DIR_RESTRICT_R}, {"dir_restrict_w", TRIGGER_DIR_RESTRICT_W}, {"dir_restrict_rw", TRIGGER_DIR_RESTRICT_RW}, {"open_w", TRIGGER_OPEN_WRITE}, {"open_r", TRIGGER_OPEN_READ}, {"open_rw", TRIGGER_OPEN_RW}, {"exe", TRIGGER_EXE}, {"link", TRIGGER_LINK}, {"unlink", TRIGGER_UNLINK}, {"truncate", TRIGGER_TRUNCATE}, {"create_file", TRIGGER_CREATE_FILE}, {"mkdir", TRIGGER_MKDIR}, {"rmdir", TRIGGER_RMDIR}, {"create_thread", TRIGGER_CREATE_THREAD}, {"fork", TRIGGER_FORK}, {"execve", TRIGGER_EXECVE}, {"ptrace", TRIGGER_PTRACE}, {"ptraceme", TRIGGER_PTRACEME}, {"kill", TRIGGER_KILL}, {"setuid", TRIGGER_SETUID}, {"setgid", TRIGGER_SETGID}, {"task_free", TRIGGER_TASK_FREE}, {"prctl", TRIGGER_PRCTL}, {"socket_create", TRIGGER_CREATE_SOCKET}, {"listen", TRIGGER_LISTEN}, {"sendmsg", TRIGGER_SEND_MSG}, {"recvmsg", TRIGGER_RECV_MSG}, {"bind", TRIGGER_BIND}, {"connect", TRIGGER_CONNECT}, {"accept", TRIGGER_ACCEPT}, {"shutdown", TRIGGER_SHUTDOWN}};
//
#define CHARACTER_ALL -1
#define PROCESS_ALL -1
/*------------------*/
/*------------------*/
#define OPERATOR_MAX 16
struct operator_index
{
  int flag_exclude_or_include;
  __u32 uids[LIMIT_MAX];
  int uid_nb;
  __u32 gids[LIMIT_MAX];
  int gid_nb;
  __u32 pids[LIMIT_MAX];
  int pid_nb;
  __u32 exe_inodes[LIMIT_MAX];
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
struct process_audit
{
  int trigger;
  // int uid;
  int action;
  //   char private_data[PRIVATE_DATA_SIZE];
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
struct ipv4_data
{
  __u32 sip;
  __u32 dip;
  __u32 sip_mask;
  __u32 dip_mask;
};
struct transport_data
{
  __u16 sport_l;
  __u16 sport_r;
  __u16 dport_l;
  __u16 dport_r;
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
void json_parse::read_json()
{
  char buffer[4096 * 5] = {0};
  int file_fd = open("configure/configure.json", O_RDONLY);
  if (file_fd < 0)
  {
    perror("open configure");
    exit(-1);
  }
  read(file_fd, buffer, sizeof(buffer));
  close(file_fd);
  data = json::parse(buffer);
}
void json_parse::init(struct bpf_object *obj)
{
  // std::ifstream f(JSON_PATH);
  //  json data = json::parse(f);

  file_map = bpf_object__find_map_fd_by_name(obj, "file_map");
  process_pid_map = bpf_object__find_map_fd_by_name(obj, "process_pid_map");
  process_inode_map = bpf_object__find_map_fd_by_name(obj, "process_inode_map");
  net_pid_map = bpf_object__find_map_fd_by_name(obj, "net_pid_map");
  net_inode_map = bpf_object__find_map_fd_by_name(obj, "net_inode_map");
  if (file_map < 0 || process_pid_map < 0 || process_inode_map < 0 || net_pid_map < 0 || net_inode_map < 0)
  {
    perror("Failed to find map");
    return;
  }
  read_json();
}
void json_parse::parse()
{
  if (data.contains("file") && data["file"].is_array())
  {
    for (const auto &fileEntry : data["file"])
    {
      std::string action = fileEntry["action"];
      auto limited_task = fileEntry["limited_task"];
      int is_exclude_or_include = set_scale(limited_task);
      if (is_exclude_or_include < 0)
        continue;
      std::vector<int> uids, gids, pids;
      std::vector<std::string> exe_paths;
      set_uids(limited_task["uid"], uids);
      set_gids(limited_task["gid"], gids);
      set_process(limited_task["limited_task"], pids, exe_paths);
      for (const std::string path : fileEntry["path"])
      {

        for (const std::string trigger : fileEntry["trigger"])
        {
          if (add_file_audit(path, trigger, action, is_exclude_or_include, exe_paths, pids, gids, uids) < 0)
            printf("add file audit err\n");
        }
      }
    }
  }
 // printf("file done\n");
  if (data.contains("process") && data["process"].is_array())
  {
    for (const auto &process : data["process"])
    {
      //  std::string trigger = process["trigger"];
      std::string action = process["action"];
      std::vector<int> pids;
      std::vector<std::string> exe_paths;
      set_process(process["limited_process"], pids, exe_paths);
      for (const std::string &trigger : process["trigger"])
      {
        for (int pid : pids)
        {
          add_process_audit(pid, trigger, action);
        }
        for (std::string exe_path : exe_paths)
        {
          add_process_audit(exe_path, trigger, action);
        }
      }
      // printf("pid done\n");
    }
  }
 // printf("process done\n");
  if (data.contains("network") && data["network"].is_array())
  {

    for (const auto &net : data["network"])
    {
      //   std::vector<int> pids;
      //  std::vector<std::string> paths;

      //   std::string trigger = net["trigger"];
      std::string action = net["action"];
      struct pkt_limit_v4 limit;
      memset(&limit, 0, sizeof(pkt_limit_v4));
      if (net.contains("limit"))
      {

        const auto &visit = net["limit"];
        int is_exclude_include = set_scale(visit);
        if (is_exclude_include < 0)
          continue;
        std::string protocol;
        std::string sip;
        std::string sip_mask;
        std::string dip;
        std::string dip_mask;

        if (visit.contains("protocol"))
        {

          if (visit["protocol"] == "tcp")
          {
            limit.protocol = IPPROTO_TCP;
          }
          else if (visit["protocol"] == "udp")
          {
            limit.protocol = IPPROTO_UDP;
          }
          else if (visit["protocol"] == "icmp")
          {
            limit.protocol = IPPROTO_ICMP;
          }
          else if (visit["protocol"] == "all")
          {
            limit.protocol = IPPROTO_IP;
          }
        }
        else
        {
          limit.protocol = IPPROTO_IP;
        }
        if (visit.contains("sip"))
        {
          std::string sip = visit["sip"];
          limit.ipv4.sip = inet_addr(sip.data());
        }
        if (visit.contains("sip_mask"))
        {
          std::string sip_mask = visit["sip_mask"];
          limit.ipv4.sip_mask = htonl((uint32_t)strtoul(sip_mask.data(), NULL, 16));
        }
        if (visit.contains("dip"))
        {
          std::string dip = visit["dip"];
          limit.ipv4.dip = inet_addr(dip.data());
        }
        if (visit.contains("dip_mask"))
        {
          std::string dip_mask = visit["dip_mask"];
          limit.ipv4.dip_mask = htonl((uint32_t)strtoul(dip_mask.data(), NULL, 16));
        }
        limit.transport.dport_l = 0;
        limit.transport.dport_r = 0XFFFF;
        limit.transport.sport_l = 0;
        limit.transport.sport_r = 0XFFFF;
        if (visit.contains("sport_scale") && visit["sport_scale"].is_array() && visit["sport_scale"].size() == 2)
        {
          limit.transport.sport_l = visit["sport_scale"][0];
          limit.transport.sport_r = visit["sport_scale"][1];
        }
        if (visit.contains("dport_scale") && visit["dport_scale"].is_array() && visit["dport_scale"].size() == 2)
        {
          limit.transport.dport_l = visit["dport_scale"][0];
          limit.transport.dport_r = visit["dport_scale"][1];
        }
      }
      else
      {
        limit.ignore = true;
      }
      std::vector<int> pids;
      std::vector<std::string> exe_paths;
      set_process(net["limited_process"], pids, exe_paths);
      for (const std::string &trigger : net["trigger"])
      {
        for (int pid : pids)
        {
          add_net_aduit(pid, trigger, action, &limit);
        }
        for (std::string path : exe_paths)
        {
          add_net_aduit(path, trigger, action, &limit);
        }
      }
    }
  }
  //printf("net done\n");
}
int json_parse::add_file_audit(std::string path_name, std::string trigger, std::string action, bool exclude_or_include, std::vector<std::string> &exe_paths, std::vector<int> &pids, std::vector<int> &gids, std::vector<int> &uids)
{
 // printf("add\n");
  if (!exist_file(path_name))
  {
    printf("path err %s\n", path_name.data());
    return -1;
  }

  struct file_audit new_file_audit;
  memset(&new_file_audit, 0, sizeof(new_file_audit));
  if (set_trigger(&new_file_audit.trigger, trigger) < 0)
  {
    return -1;
  }
  if (set_action(&new_file_audit.action, action) < 0)
  {
    return -1;
  }
  new_file_audit.index.flag_exclude_or_include = exclude_or_include;
  new_file_audit.index.uid_nb = uids.size();
  for (int i = 0; i < uids.size(); i++)
  {
    new_file_audit.index.uids[i] = uids[i];
  }
  new_file_audit.index.gid_nb = gids.size();
  for (int i = 0; i < gids.size(); i++)
  {
    new_file_audit.index.gids[i] = gids[i];
  }
  new_file_audit.index.pid_nb = pids.size();
  for (int i = 0; i < pids.size(); i++)
  {
    new_file_audit.index.pids[i] = pids[i];
  }
  std::vector<int> exe_inodes;
  for (std::string path : exe_paths)
  {
    if (exist_file(path))
    {
      int exe_inode = get_file_inode(path);
      exe_inodes.push_back(exe_inode);
    }
  }
  new_file_audit.index.exe_inode_nb = exe_inodes.size();
  for (int i = 0; i < exe_inodes.size(); i++)
  {
    new_file_audit.index.exe_inodes[i] = exe_inodes[i];
  }

  struct file_audit_event audits;
  memset(&audits, 0, sizeof(file_audit_event));
  audits.inode = get_file_inode(path_name);
  if (audits.inode < 0)
  {
    printf("inode err");
    return -1;
  }

  if (bpf_map_lookup_elem(file_map, &audits.inode, &audits) < 0)
  {
   // printf("no\n");
    memcpy(&audits.audit[0], &new_file_audit, sizeof(new_file_audit));
    audits.audits_nb = 1;
  }
  else
  {
    if (audits.audits_nb >= MAX_AUDIT)
    {
      printf("file audit nb >=%d\n", MAX_AUDIT);
      return -1;
    }
    for (int i = 0; i < MAX_AUDIT; i++)
    {
      if (audits.audit[i].trigger == 0)
      {

        memcpy(&audits.audit[i], &new_file_audit, sizeof(new_file_audit));
        audits.audits_nb++;
        break;
      }
    }
  }
  // printf("add %d\n", new_file_audit.action);
  if (bpf_map_update_elem(file_map, &audits.inode, &audits, BPF_ANY) != 0)
  {
    printf("updata elem err\n");
    return -1;
  }
  return 0;
}
int json_parse::add_process_audit(std::string exe_path, std::string trigger, std::string action)
{

  if (!exist_file(exe_path))
  {
    printf("path err %s\n", exe_path.data());
    return -1;
  }
  // printf("add %s",exe_path.data());
  struct process_audit new_audit;
  struct process_audit_events events;
  memset(&new_audit, 0, sizeof(struct process_audit));
  memset(&events, 0, sizeof(struct process_audit_events));
  int exe_inode = get_file_inode(exe_path);
  if (exe_inode < 0)
  {
    printf("exe path:%s err\n", exe_path.data());
    return -1;
  }
  if (set_trigger(&new_audit.trigger, trigger) < 0)
  {
    printf("trigger %s err\n", trigger.data());
    return -1;
  }
  if (set_action(&new_audit.action, action) < 0)
  {
    printf("action %s err\n", action.data());
    return -1;
  }
  // new_audit.uid = uid;
  if (bpf_map_lookup_elem(process_inode_map, &exe_inode, &events) != 0)
  {
    events.exe_file_inode = exe_inode;
    memcpy(&events.audits[0], &new_audit, sizeof(process_audit));
    events.audit_nb = 1;
  }
  else
  {
    if (events.audit_nb > MAX_AUDIT)
    {
      printf("process audit nb >%d", MAX_AUDIT);
      return -1;
    }
    events.audit_nb++;
    for (int i = 0; i < MAX_AUDIT; i++)
    {
      if (!events.audits[i].trigger)
      {
        memcpy(&events.audits[i], &new_audit, sizeof(process_audit));
        break;
      }
    }
  }

  if (bpf_map_update_elem(process_inode_map, &events.exe_file_inode, &events, BPF_ANY) != 0)
  {
    printf("updata elem err\n");
    return -1;
  }
  return 0;
}
int json_parse::add_process_audit(int pid, std::string trigger, std::string action)
{

  struct process_audit new_audit;
  struct process_audit_events events;
  memset(&new_audit, 0, sizeof(struct process_audit));
  memset(&events, 0, sizeof(struct process_audit_events));

  if (set_trigger(&new_audit.trigger, trigger) < 0)
  {
    printf("trigger %s err\n", trigger.data());
    return -1;
  }
  if (set_action(&new_audit.action, action) < 0)
  {
    printf("action %s err\n", action.data());
    return -1;
  }

  // new_audit.uid = uid;
  if (bpf_map_lookup_elem(process_pid_map, &pid, &events) != 0)
  {
    events.pid = pid;
    memcpy(&events.audits[0], &new_audit, sizeof(process_audit));
    events.audit_nb = 1;
  }
  else
  {
    if (events.audit_nb > MAX_AUDIT)
    {
      printf("process audit nb >%d", MAX_AUDIT);
      return -1;
    }
    events.audit_nb++;
    for (int i = 0; i < MAX_AUDIT; i++)
    {
      if (!events.audits[i].trigger)
      {
        memcpy(&events.audits[i], &new_audit, sizeof(process_audit));
        break;
      }
    }
  }

  if (bpf_map_update_elem(process_pid_map, &events.exe_file_inode, &events, BPF_ANY) != 0)
  {
    printf("updata elem err\n");
    return -1;
  }
  return 0;
}

int json_parse::get_uid(char *username, int *uid)
{

  struct passwd *pw = getpwnam(username);
  if (pw == NULL)
  {
    perror("getpwnam");
    printf("User '%s' not found.\n", username);
    return -1;
  }
  else
  {
    *uid = pw->pw_uid;
    // Log::uid_username[pw->pw_uid]=std::string(username);
    return 0;
  }
}
int json_parse::get_gid(char *groupname, int *gid)
{
  struct group *gr = getgrnam(groupname);
  if (gr == NULL)
  {
    perror("getgrnam");
    printf("Group '%s' not found.\n", groupname);
    return -1;
  }
  else
  {
    *gid = gr->gr_gid;
    // Log::gid_groupname[gr->gr_gid]=std::string(groupname);
    return 0;
  }
}
int json_parse::add_net_aduit(std::string exe_path, std::string trigger, std::string action, pkt_limit_v4 *limit)
{
  if (!exist_file(exe_path))
  {
    printf("path %s err\n", exe_path.data());
    return -1;
  }
  int exe_inode = get_file_inode(exe_path);
  if (exe_inode < 0)
    return -1;
  struct network_audit_events events;
  memset(&events, 0, sizeof(network_audit_events));
  struct network_audit new_audit;
  memset(&new_audit, 0, sizeof(network_audit));
  events.exe_inode = exe_inode;
  if (set_trigger(&new_audit.trigger, trigger) < 0)
  {
    printf("trigger %s err\n", trigger.data());
    return -1;
  }
  if (set_action(&new_audit.action, action) < 0)
  {
    printf("action %s err\n", action.data());
    return -1;
  }
  memcpy(&new_audit.limit, limit, sizeof(pkt_limit_v4));
  if (bpf_map_lookup_elem(net_inode_map, &events.exe_inode, &events) < 0)
  {
    memcpy(&events.audits[0], &new_audit, sizeof(network_audit));
    events.audit_nb = 1;
  }
  else
  {
    if (events.audit_nb > MAX_AUDIT)
    {
      printf("net audit nb >%d\n", MAX_AUDIT);
      return -1;
    }
    events.audit_nb++;
    for (int i = 0; i < MAX_AUDIT; i++)
    {
      if (!events.audits[i].trigger)
      {
        memcpy(&events.audits[i], &new_audit, sizeof(network_audit));
        break;
      }
    }
  }
  if (bpf_map_update_elem(net_inode_map, &events.exe_inode, &events, BPF_ANY) != 0)
  {
    printf("map updata err\n");
    return -1;
  }
  return 0;
}
int json_parse::add_net_aduit(int pid, std::string trigger, std::string action, pkt_limit_v4 *limit)
{
  struct network_audit_events events;
  memset(&events, 0, sizeof(network_audit_events));
  struct network_audit new_audit;
  memset(&new_audit, 0, sizeof(network_audit));
  events.pid = pid;
  if (set_trigger(&new_audit.trigger, trigger) < 0)
  {
    printf("trigger %s err\n", trigger.data());
    return -1;
  }
  if (set_action(&new_audit.action, action) < 0)
  {
    printf("action %s err\n", action.data());
    return -1;
  }
  memcpy(&new_audit.limit, limit, sizeof(pkt_limit_v4));
  if (bpf_map_lookup_elem(net_pid_map, &events.pid, &events) < 0)
  {
    memcpy(&events.audits[0], &new_audit, sizeof(network_audit));
    events.audit_nb = 1;
  }
  else
  {
    if (events.audit_nb > MAX_AUDIT)
    {
      printf("net audit nb >%d\n", MAX_AUDIT);
      return -1;
    }
    events.audit_nb++;
    for (int i = 0; i < MAX_AUDIT; i++)
    {
      if (!events.audits[i].trigger)
      {
        memcpy(&events.audits[i], &new_audit, sizeof(network_audit));
        break;
      }
    }
  }
  if (bpf_map_update_elem(net_pid_map, &events.pid, &events, BPF_ANY) < 0)
  {
    printf("map updata err\n");
    return -1;
  }
  return 0;
}
int json_parse::set_trigger(int *dst, std::string trigger)
{
  for (auto &it : Triggers)
  {
    if (it.first == trigger)
    {
      *dst = it.second;
      return 0;
    }
  }
  printf("trigger %s err\n", trigger.data());
  return -1;
}
int json_parse::set_action(int *dst, std::string action)
{
  for (auto &it : Actions)
  {
    if (it.first == action)
    {
      *dst = it.second;
      return 0;
    }
  }
  printf("action %s err\n", action.data());
  return -1;
}
void json_parse::set_process(const nlohmann::json &json, std::vector<int> &pids, std::vector<std::string> &exe_paths)
{
  for (const auto &item : json)
  {
    if (item.is_number_integer())
    {
      int pid = item;
      pids.push_back(pid);
    }
    else if (item.is_string())
    {
      std::string path = item;
      if (exist_file(path))
      {
        exe_paths.push_back(path);
      }
      else{
        printf("path %s err\n",path.data());
      }
    }
  }
}
void json_parse::set_uids(const nlohmann::json &json, std::vector<int> &uids)
{
  for (const auto &item : json)
  {
    if (item.is_number_integer())
    {
      int uid = item;
      uids.push_back(uid);
    }
    else if (item.is_string())
    {
      int uid;
      std::string username = item;
      if (get_uid(username.data(), &uid) < 0)
      {
        printf("username:%s err\n", username.data());
        continue;
      }
      uids.push_back(uid);
    }
  }
}
void json_parse::set_gids(const nlohmann::json &json, std::vector<int> &gids)
{
  for (const auto &item : json)
  {
    if (item.is_number_integer())
    {
      int gid = item;
      gids.push_back(gid);
    }
    else if (item.is_string())
    {
      int gid;
      std::string groupname = item;
      if (get_gid(groupname.data(), &gid) < 0)
      {
        printf("groupname:%s err\n", groupname.data());
        continue;
      }
      gids.push_back(gid);
    }
  }
}
bool json_parse::exist_file(std::string &path)
{
  struct stat statbuf;
  if (stat(path.data(), &statbuf) == -1)
  {
    return 0;
  }
  return 1;
}
int json_parse::get_file_inode(std::string path)
{
  struct stat statbuf;
  if (stat(path.data(), &statbuf) == -1)
  {
    perror("stat");
    return -1;
  }
  return statbuf.st_ino;
}
int json_parse::set_scale(const nlohmann::json &json) // include 0 exclude 1 err -1
{
  if (json.contains("include"))
  {
    return 0;
  }
  else if (json.contains("exclude"))
  {
    return 1;
  }
  printf("set scale err\n");
  return -1;
}
int json_parse::set_protocol(const nlohmann::json &json)
{
  if (!json.contains("protocol"))
  {
    return -1;
  }
  else if (json.contains("exclude"))
  {
    return 1;
  }
  else if (json.contains("exclude"))
  {
    return 1;
  }
  else if (json.contains("exclude"))
  {
    return 1;
  }
  return -1;
}
void json_parse::clear_rules()
{
  clear_map(file_map);
  clear_map(process_pid_map);
  clear_map(process_inode_map);
  clear_map(net_pid_map);
  clear_map(net_inode_map);
}
void json_parse::updata_rules()
{

  clear_rules();
  read_json();
  parse();
}
void json_parse::clear_map(int map_fd)
{
  int key, next_key;
  int result;
  key = 0;                                           
  result = bpf_map_get_next_key(map_fd, NULL, &key); 
  if (result < 0)
  {

    return;
  }

  // 迭代删除所有元素
  do
  {
    // 删除当前键的元素
    result = bpf_map_delete_elem(map_fd, &key);
    if (result < 0)
    {
      return;
    }

    // 获取下一个键
    result = bpf_map_get_next_key(map_fd, &key, &next_key);
    if (result == 0)
    {
      key = next_key;
    }
  } while (result == 0);
}
void json_parse::wait_command(std::string command)
{
  if (command == std::string("updata\n"))
  {
    updata_rules();
    printf("command done\n");
  }
  else if (command == std::string("clear\n"))
  {
    clear_rules();
    printf("command done\n");
  }
  else
  {
    printf("unknown command %s\n", command.data());
  }
}
