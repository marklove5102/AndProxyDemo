#ifndef SECCOMP_HOOK_H
#define SECCOMP_HOOK_H

#include <stddef.h>
#include <sys/types.h>
#include <linux/filter.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ARM64 寄存器上下文 */
typedef struct {
    unsigned long long x[31];
    unsigned long long sp;
    unsigned long long pc;
    unsigned long long pstate;
} hook_regs_t;

/* 请求结构 */
typedef struct {
    unsigned long long id;
    int syscall_nr;
    pid_t pid;
    unsigned long long args[6];
    hook_regs_t regs;
} hook_request_t;

/* 动作枚举 */
typedef enum {
    HOOK_ACTION_ALLOW = 0,
    HOOK_ACTION_DENY,
    HOOK_ACTION_MODIFY,
} hook_action_t;

/* 响应结构 */
typedef struct {
    unsigned long long id;
    hook_action_t action;
    long long val;
    int error;
} hook_response_t;

/* 回调函数原型 */
typedef void (*hook_callback_t)(const hook_request_t *req, hook_response_t *resp, void *userdata);

/* 初始钩子条目 */
typedef struct {
    int nr;                     // 系统调用号
    hook_callback_t callback;   // 回调函数
    void *userdata;             // 用户数据
} hook_entry_t;

/**
 * 初始化库
 * @param syscall_list  以 -1 结尾的系统调用号数组，当 custom_filter 为 NULL 时使用此列表构建默认过滤器。
 * @param custom_filter 用户自定义的 BPF 过滤器。若不为 NULL，则忽略 syscall_list。
 * @param entries       初始钩子条目数组（可为 NULL）
 * @param num_entries   entries 数组长度
 * @param use_signal    是否启用信号机制获取寄存器上下文（若为 0，则 req->regs 全为 0）。
 * @return 0 成功，-1 失败
 */
int seccomp_hook_init(const int *syscall_list,
                      const struct sock_fprog *custom_filter,
                      const hook_entry_t *entries,
                      int num_entries,
                      int use_signal);

/**
 * 远程注册钩子（父进程调用）
 * 注意：callback 和 userdata 指针在子进程地址空间中必须有效。
 *      通常全局函数和静态数据可以安全传递，堆分配的数据若在 fork 后未被释放也可用。
 * @param syscall_list  以 -1 结尾的系统调用号数组，当 custom_filter 为 NULL 时使用此列表构建默认过滤器。
 * @param custom_filter 用户自定义的 BPF 过滤器。若不为 NULL，其所处理的 syscall 必须在 syscall_list 中注册。
 * @param callback  回调函数
 * @param userdata  用户数据指针
 * @return 0 成功，-1 失败
 */
int seccomp_hook_register_remote(const int *syscall_list,
                                 const struct sock_fprog *custom_filter, hook_callback_t callback, void *userdata);

/**
 * 远程注销钩子（父进程调用）
 */
int seccomp_hook_unregister_remote(const int *syscall_list, hook_callback_t callback, void *userdata);

/**
 * 内存读写辅助函数（可在回调中安全使用）
 */
ssize_t seccomp_hook_read_mem(pid_t pid, const void *remote_addr, void *local_buf, size_t len);
ssize_t seccomp_hook_write_mem(pid_t pid, void *remote_addr, const void *local_buf, size_t len);

/**
 * 在 supervisor 中为目标进程添加文件描述符（模拟打开文件/创建 socket 等）
 * 该函数只能在回调函数中调用，且 req 必须为当前回调收到的请求指针。
 */
int seccomp_hook_add_fd(const hook_request_t *req, int srcfd, __u32 newfd_flags);

#ifdef __cplusplus
}
#endif

#endif // SECCOMP_HOOK_H