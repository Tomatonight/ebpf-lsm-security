#include "log.h"
#include <sys/stat.h>
#include <regex>
#include <pwd.h>
#include <grp.h>

int Log::file_fd = 0;
// std::map<int, std::string> Log::inode_path = {};
// std::map<int, std::string> Log::uid_username = {};
// std::map<int, std::string> Log::gid_groupname = {};
static void get_current_date(char *buffer, size_t buffer_size)
{
    time_t now = time(NULL);              // 获取当前时间
    struct tm *tm_info = localtime(&now); // 转换为本地时间结构

    // 格式化时间为字符串，例如 "2024-12-12"
    strftime(buffer, buffer_size, "log/%Y-%m-%d", tm_info);
}
void Log::init(struct bpf_object *obj)
{
    char buffer[50] = {0};
    get_current_date(buffer, sizeof(buffer));
    file_fd = open(buffer, O_RDWR | O_CREAT | O_APPEND);
    if (file_fd < 0)
    {
        perror("open log");
        printf("%s\n", buffer);
        exit(-1);
    }
    fchmod(file_fd, 0x777);
    ring_fd = bpf_object__find_map_fd_by_name(obj, "RING");
    if (ring_fd < 0)
    {
        printf("find events err\n");
        exit(-1);
    }

    thread = std::move(std::thread([=]()
                                   { read_loop(); }));
    thread.detach();
};
// void Log::search_inode(std::string &str)
// {
//     //[inode:int]->path
//     std::regex inode_pattern("(\[inode:(\d+)\])");
//     std::smatch match;
//     std::vector<int> inodes;
//     std::string::const_iterator search_start(str.cbegin());
//     while (std::regex_search(search_start, str.cend(), match, inode_pattern))
//     {
//         // 将捕获的整数部分转换为 int 并存入结果
//         inodes.push_back(std::stoi(match[1].str()));
//         // 更新搜索起点
//         search_start = match.suffix().first;
//     }
//     for (int i : inodes)
//     {
//         std::string replaced = "[inode:" + std::to_string(i) + "]";
//         if (Log::inode_path.find(i) == Log::inode_path.end())
//             continue;
//         std::string replace = Log::inode_path[i];
//         std::regex replaced_pattern(replaced);
//         std::regex_replace(str, replaced_pattern, replace);
//     }
// }
void Log::search_uid(std::string &str)
{

    std::regex uid_pattern("(\\[uid:(\\d+)\\])");
    std::smatch match;
    std::vector<int> uids;
    std::string::const_iterator search_start(str.cbegin());
    while (std::regex_search(search_start, str.cend(), match, uid_pattern))
    {
        // 将捕获的整数部分转换为 int 并存入结果
        uids.push_back(std::stoi(match[1].str()));
        // 更新搜索起点
        search_start = match.suffix().first;
    }
    for (int i : uids)
    {
        std::string replaced = "[uid:" + std::to_string(i) + "]";
        std::string replace = get_username(i);
        std::regex replaced_pattern(replaced);
        std::regex_replace(str, replaced_pattern, replace);
    }
}
void Log::search_gid(std::string &str)
{
    std::regex gid_pattern("(\\[gid:(\\d+)\\])");
    std::smatch match;
    std::vector<int> gids;
    std::string::const_iterator search_start(str.cbegin());
    while (std::regex_search(search_start, str.cend(), match, gid_pattern))
    {
        // 将捕获的整数部分转换为 int 并存入结果
        gids.push_back(std::stoi(match[1].str()));
        // 更新搜索起点
        search_start = match.suffix().first;
    }
    for (int i : gids)
    {
        std::string replaced = "[gid:" + std::to_string(i) + "]";
        std::string replace = get_groupname(i);
        std::regex replaced_pattern(replaced);
        //   std::regex replaced_pattern(replaced);
        std::regex_replace(str, replaced_pattern, replace);
    }
}
void Log::search_ip(std::string &str)
{
    std::regex ip_pattern("(\\[ip:(\\d+)\\])");
    std::smatch match;
    std::vector<uint32_t> ips;
    std::string::const_iterator search_start(str.cbegin());
    while (std::regex_search(search_start, str.cend(), match, ip_pattern))
    {
        // 将捕获的整数部分转换为 int 并存入结果
        ips.push_back(std::stoul(match[1].str()));
        // 更新搜索起点
        search_start = match.suffix().first;
    }
    for (uint32_t i : ips)
    {
        std::string replaced = "[ip:" + std::to_string(i) + "]";
        in_addr addr = {.s_addr = i};
        std::string replace = std::string(inet_ntoa(addr));
        std::regex replaced_pattern(replaced);
        std::regex_replace(str, replaced_pattern, replace);
    }
}
void Log::search_pid(std::string &str)
{
    std::regex ip_pattern("(\\[pid:(\\d+)\\])");
    std::smatch match;
    std::vector<int> ips;
    std::string::const_iterator search_start(str.cbegin());
    while (std::regex_search(search_start, str.cend(), match, ip_pattern))
    {
        // 将捕获的整数部分转换为 int 并存入结果
        ips.push_back(std::stoi(match[1].str()));
        // 更新搜索起点
        search_start = match.suffix().first;
    }
    for (int i : ips)
    {
        std::string replaced = "[ip:" + std::to_string(i) + "]";
        in_addr addr = {.s_addr = (uint32_t)i};
        std::string replace = std::string(inet_ntoa(addr));
        std::regex replaced_pattern(replaced);
        std::regex_replace(str, replaced_pattern, replace);
    }
}
std::string Log::search_exe(int pid)
{
    char buf[PATH_MAX];
    char proc[PATH_MAX];
    snprintf(buf, sizeof(buf), "/proc/%d/exe", pid);
    if (readlink(buf, proc, sizeof(proc) - 1) < 0)
    {
        return NULL;
    }
    return std::string(proc);
}
int handle_read(void *ctx, void *data, size_t size)
{
    char *buf = (char *)data;
    std::string str(buf);
    // Log::search_inode(str);
    //  Log::search_gid(str);
    //  Log::search_uid(str);
    //  Log::search_ip(str);
    //   Log::search_pid(str);
    if (write(Log::file_fd, str.data(), strlen(str.data())) < 0)
    {
        perror("write file err");
    }
    return 0;
};
std::string Log::get_username(int uid)
{
    struct passwd *pw = getpwuid(uid);
    if (!pw)
        return NULL;
    return std::string(pw->pw_name);
}
std::string Log::get_groupname(int gid)
{
    struct group *grp = getgrgid(gid);
    if (!grp)
        return NULL;
    return std::string(grp->gr_name);
}
void Log::read_loop()
{

    rb = ring_buffer__new(ring_fd, handle_read, NULL, NULL);
    if (!rb)
    {
        printf("ring buffer err\n");
        exit(-1);
    }

    while (true)
    {
        ring_buffer__poll(rb, 100);
    }
    return;
}
