#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <pthread.h>
#include <errno.h>
#include "parse.h"
#include "log.h"
// int file_map;
static class json_parse Json;
static class Log log_;
const char *hooks[] = {"lsm_file_open", "lsm_link", "lsm_unlink",
                       "lsm_truncate", "lsm_rmdir", "lsm_mkdir", "lsm_create_file",
                       "lsm_task_create", "lsm_execve", "lsm_ptrace", "lsm_ptraceme",
                       "lsm_socket_bind","lsm_socket_listen","lsm_socket_accept","lsm_socket_create",
                       "lsm_socket_shutdown","lsm_socket_recvmsg","lsm_socket_sendmsg",
                       "lsm_socket_connect"};
void print()
{
    FILE *fp = fopen("/sys/kernel/debug/tracing/trace_pipe", "r");
    if (!fp)
    {
        perror("Failed to open trace_pipe");
        return;
    }
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), fp))
    {
        printf("%s", buffer);
        //  memset(buffer,0,sizeof(buffer));
    }

    fclose(fp);
}
void add_hook(const char *path, struct bpf_object *obj)
{
    struct bpf_program *prog;
    struct bpf_link *link;
    prog = bpf_object__find_program_by_name(obj, path);
    if (!prog)
    {
        fprintf(stderr, "Error finding BPF program by name %s\n",path);
        return;
    }
    link = bpf_program__attach(prog);
    if (!link)
    {
        fprintf(stderr, "Error attaching BPF program to tracepoint\n");
        return;
    }
}
int main()
{

    struct bpf_object *obj = NULL;
    int ret;
    // 加载 BPF 对象
    obj = bpf_object__open_file("build/test.o", NULL);
    if (!obj)
    {
        fprintf(stderr, "Error opening BPF object file\n");
        return 1;
    }

    // 加载和附加 BPF 程序
    ret = bpf_object__load(obj);
    if (ret)
    {
        fprintf(stderr, "Error loading BPF object\n");
        return 1;
    }

    for (int i = 0; i < sizeof(hooks) / sizeof(hooks[0]); i++)
    {
        // printf("add %s\n",hooks[i]);
        add_hook(hooks[i], obj);
    }
    log_.init(obj);
    printf("log init done\n");
    Json.init(obj);
    printf("josn init done\n");
    Json.parse();
    printf("parse done\n");
    printf("start\n");
    print();
    bpf_object__close(obj);
    return 0;
}
