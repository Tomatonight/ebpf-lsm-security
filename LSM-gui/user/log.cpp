#include "log.h"
#include <sys/stat.h>
#include <regex>
#include <pwd.h>
#include <grp.h>
extern bool to_view;
int Log::file_fd = 0;
std::string log_path;
bool log_path_updata=false;
// std::map<int, std::string> Log::inode_path = {};
// std::map<int, std::string> Log::uid_username = {};
// std::map<int, std::string> Log::gid_groupname = {};
void get_current_date(char *buffer, size_t buffer_size)
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
    log_path=buffer;
    file_fd = open(buffer, O_RDWR | O_CREAT | O_APPEND);
    if (file_fd < 0)
    {
        perror("open log");
        printf("%s\n", buffer);
        exit(-1);
    }
    fchmod(file_fd, 0x777);
    ring_fd = bpf_object__find_map_fd_by_name(obj, "RING");

    if (ring_fd < 0 )
    {
        printf("find events err\n");
        exit(-1);
    }

    thread = std::move(std::thread([=]()
                                   { read_loop(); }));

   thread.detach();
};
void Log::search_uid(std::string &str)
{

    std::regex uid_pattern("(\\[uid:(\\d+)\\])");
    std::smatch match;
    std::vector<uint32_t> uids;
    std::string::const_iterator search_start(str.cbegin());

    while (std::regex_search(search_start, str.cend(), match, uid_pattern))
    {
        // 将捕获的整数部分转换为 int 并存入结果
        std::string t = match[2].str();
        uids.push_back(std::atoi(t.data()));
        search_start = match.suffix().first;
    }
    for (uint32_t i : uids)
    {

        std::string replaced = "(\\[uid:" + std::to_string(i) + "\\])";
        std::string replace = get_username(i);
        std::regex replaced_pattern(replaced);
     //   printf("pre %s\n",str.data());
        str = std::regex_replace(str, replaced_pattern, replace);
    //    printf("last %s\n",str.data());
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
        std::string t = match[2].str();
        gids.push_back(atoi(t.data()));
        search_start = match.suffix().first;
        // 更新搜索起点
    }
    for (int i : gids)
    {
        std::string replaced = "\\[gid:" + std::to_string(i) + "\\]";
        std::string replace = get_groupname(i);
        std::regex replaced_pattern(replaced);
        //   std::regex replaced_pattern(replaced);
        str = std::regex_replace(str, replaced_pattern, replace);
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
        std::string t = match[2].str();
        ips.push_back(atoi(t.data()));
        search_start = match.suffix().first;
    }
    for (uint32_t i : ips)
    {
        std::string replaced = "\\[ip:" + std::to_string(i) + "\\]";
        in_addr addr = {.s_addr = i};
        std::string replace = std::string(inet_ntoa(addr));
        std::regex replaced_pattern(replaced);
        str = std::regex_replace(str, replaced_pattern, replace);
    }
}
void Log::search_time(std::string &str)
{

    std::string replaced = "\\[time:\\]";
    std::ostringstream oss;
    struct timespec t;
    if (clock_gettime(CLOCK_REALTIME, &t) == 0)
    {
        std::time_t time = t.tv_sec;
        std::tm *tm_info = std::localtime(&time);
        oss << std::put_time(tm_info, "%Y-%m-%d %H:%M:%S");
    }
    else
    {
        return;
    }
    std::string replace = oss.str();
    std::regex replaced_pattern(replaced);
    str = std::regex_replace(str, replaced_pattern, replace);
}
int handle_read(void *ctx, void *data, size_t size)
{
    char *buf = (char *)data;
    std::string str(buf);
    Log::search_gid(str);
    Log::search_uid(str);
    Log::search_ip(str);
    Log::search_time(str);
    if(log_path_updata)
    {
        close(Log::file_fd);
        Log::file_fd=open(log_path.data(),O_WRONLY|O_CREAT);
        if(Log::file_fd<0)
        {
            printf("open %s err\n",log_path.data());
            return 0;
        }
        log_path_updata=false;
    }
    if (write(Log::file_fd, str.data(),str.size()) < 0)
    {
        perror("write file err");
    }
    if(to_view)
    {
        printf("%s",str.data());
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
