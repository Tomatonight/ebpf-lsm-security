#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <ctime>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include<map>
#include <thread>
#include<mutex>
#include<arpa/inet.h>
#include <time.h>
#include <errno.h>
#define MSG_DATA_LEN 128
class Log
{
private:
    int ring_fd;
    ring_buffer *rb;
    std::thread thread;

public:
    static int file_fd;
    // static std::map<int,std::string> inode_path;
    // static std::map<int,std::string> uid_username;
    // static std::map<int,std::string> gid_groupname;
   // static void search_inode(std::string &str);
    static void search_uid(std::string &str);
    static void search_gid(std::string &str);
    static void search_ip(std::string &str);
    static void search_time(std::string &str);
 //   static std::string search_exe(int pid);
    static std::string get_username(int uid);
    static std::string get_groupname(int gid);
    void init(struct bpf_object *obj);
    void read_loop();
 
};
