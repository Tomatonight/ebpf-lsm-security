#pragma once
#include <iostream>
#include <pwd.h>
#include <grp.h>
#include<linux/socket.h>
#include<arpa/inet.h>
#include <nlohmann/json.hpp>
#include"log.h"
using json = nlohmann::json;
struct pkt_limit_v4;
class json_parse
{
private:
    int file_map;
    int process_pid_map;
    int process_inode_map;
    int net_pid_map;
    int net_inode_map;
    json data;
    int add_file_audit(std::string path_name, std::string trigger, std::string action, bool exclude_or_include, std::vector<std::string> &exe_paths, std::vector<int> &pids, std::vector<int> &gids, std::vector<int> &uids);
    int add_process_audit(std::string exe_path,std::string trigger,std::string action);
    int add_process_audit(int pid,std::string trigger,std::string action);
    int add_net_aduit(int exe_inode,std::string trigger,std::string action,pkt_limit_v4 *limit);
    int add_net_aduit(int pid,std::string trigger,std::string action,pkt_limit_v4 *limit);
    int set_trigger(int* dst,std::string trigger);
    int set_action(int* dst,std::string action);
    void set_process(const nlohmann::json &json,std::vector<int> &pids,std::vector<int> &exe_inodes);
    void set_uids(const nlohmann::json &json,std::vector<int> &uids);
    void set_gids(const nlohmann::json &json,std::vector<int> &gids);
    
    int get_uid(char* username,int *uid);
    int get_gid(char* groupname,int* gid);
    bool exist_file(std::string &path);
    int get_file_inode(std::string path);
public:
    void init(struct bpf_object *obj);
    void parse();
};