#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <cerrno>
#include <csignal>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <pthread.h>

#include "seccomp_hook.h"
#include "log.h"

/* 全局状态（父进程使用）*/
static int g_initialized = 0;
static pid_t g_parent_pid;
static int g_cmd_pipe_wr = -1;      // 命令管道写端（父进程）
static int g_cmd_pipe_rd = -1;      // 命令管道读端（子进程）
static int g_notify_fd = -1;

/* 共享内存（信号处理与 supervisor 通信）*/
struct shared_regs {
    volatile int ready;
    hook_regs_t regs;
};
static struct shared_regs *g_shared = nullptr;

/* 回调链表（子进程使用）*/
typedef struct hook_node {
    int nr;
    hook_callback_t callback;
    void *userdata;
    struct hook_node *next;
} hook_node_t;
static hook_node_t *g_hook_list = nullptr;
static pthread_mutex_t g_hook_lock = PTHREAD_MUTEX_INITIALIZER;

/* 命令类型 */
typedef enum {
    CMD_REGISTER,
    CMD_UNREGISTER
} cmd_type_t;

typedef struct {
    cmd_type_t type;
    int nr;
    uintptr_t callback;   // 函数指针
    uintptr_t userdata;
} cmd_t;

/* -------------------------------------------------------------------------
 * 辅助系统调用
 * ------------------------------------------------------------------------- */
static inline long syscall_long(long number, ...) {
    va_list ap;
    va_start(ap, number);
    long ret = syscall(number,
                       va_arg(ap, long), va_arg(ap, long),
                       va_arg(ap, long), va_arg(ap, long),
                       va_arg(ap, long), va_arg(ap, long));
    va_end(ap);
    return ret;
}

static inline int seccomp(int op, int fd, void *arg) {
    return (int) syscall_long(__NR_seccomp, op, fd, arg);
}

/* -------------------------------------------------------------------------
 * SVC 指令检查（照抄原 module.c）
 * ------------------------------------------------------------------------- */
static inline int is_svc_instruction(void *pc) {
    uint32_t instr = *(volatile uint32_t *)pc;
    if ((instr & 0xFF00001F) == 0xD4000001)
        return 1;
    return 0;
}

/* -------------------------------------------------------------------------
 * 信号处理函数（异步信号安全）
 * ------------------------------------------------------------------------- */
static void signal_handler(int sig, siginfo_t *info, void *ucontext) {
    (void)sig; (void)info;
    auto *ctx = (ucontext_t *)ucontext;
    mcontext_t *mctx = &ctx->uc_mcontext;
    void *pc = (void *)mctx->pc;

    if (!is_svc_instruction(pc))
        return;

    hook_regs_t *regs = &g_shared->regs;
    for (int i = 0; i < 31; i++)
        regs->x[i] = mctx->regs[i];
    regs->sp = mctx->sp;
    regs->pc = mctx->pc;
    regs->pstate = mctx->pstate;
    
    g_shared->ready = 1;
}

/* -------------------------------------------------------------------------
 * BPF 过滤器构建（默认）
 * ------------------------------------------------------------------------- */
static struct sock_fprog build_filter(const int *syscall_list) {
    static struct sock_filter filter[4096];
    int idx = 0;

    filter[idx++] = (struct sock_filter) BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                             offsetof(struct seccomp_data, nr));

    if (syscall_list) {
        for (const int *p = syscall_list; *p != -1; p++) {
            filter[idx++] = (struct sock_filter) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<__u32>(*p), 0, 0);
        }
    }

    int allow_pos = idx;
    filter[idx++] = (struct sock_filter) BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    int notif_pos = idx;
    filter[idx++] = (struct sock_filter) BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF);

    for (int i = 1; i < allow_pos; i++) {
        if (filter[i].code == (BPF_JMP | BPF_JEQ | BPF_K)) {
            filter[i].jt = notif_pos - (i + 1);
            filter[i].jf = 0;
        }
    }

    struct sock_fprog prog = { .len = static_cast<unsigned short>(idx), .filter = filter };
    return prog;
}

/* -------------------------------------------------------------------------
 * 辅助函数：通过 Unix 域套接字传递文件描述符
 * ------------------------------------------------------------------------- */
static int sendfd(int sock_fd, int fd) {
    struct msghdr msgh{};
    struct iovec iov{};
    char buf[CMSG_SPACE(sizeof(int))];
    int data = 0;

    memset(&msgh, 0, sizeof(msgh));
    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    iov.iov_base = &data;
    iov.iov_len = sizeof(int);
    msgh.msg_control = buf;
    msgh.msg_controllen = sizeof(buf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msgh);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

    if (sendmsg(sock_fd, &msgh, 0) < 0) return -1;
    return 0;
}

static int recvfd(int sock_fd) {
    struct msghdr msgh{};
    struct iovec iov{};
    char buf[CMSG_SPACE(sizeof(int))];
    int data, fd;

    memset(&msgh, 0, sizeof(msgh));
    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    iov.iov_base = &data;
    iov.iov_len = sizeof(int);
    msgh.msg_control = buf;
    msgh.msg_controllen = sizeof(buf);

    if (recvmsg(sock_fd, &msgh, 0) < 0) return -1;

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msgh);
    if (!cmsg || cmsg->cmsg_len != CMSG_LEN(sizeof(int)) ||
        cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
        return -1;
    }
    memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
    return fd;
}

/* -------------------------------------------------------------------------
 * 内存读写辅助函数
 * ------------------------------------------------------------------------- */
ssize_t seccomp_hook_read_mem(pid_t pid, const void *remote_addr, void *local_buf, size_t len) {
    struct iovec local = { .iov_base = local_buf, .iov_len = len };
    struct iovec remote = { .iov_base = (void*)remote_addr, .iov_len = len };
    return syscall(__NR_process_vm_readv, pid, &local, 1, &remote, 1, 0);
}

ssize_t seccomp_hook_write_mem(pid_t pid, void *remote_addr, const void *local_buf, size_t len) {
    struct iovec local = { .iov_base = (void*)local_buf, .iov_len = len };
    struct iovec remote = { .iov_base = remote_addr, .iov_len = len };
    return syscall(__NR_process_vm_writev, pid, &local, 1, &remote, 1, 0);
}

/* -------------------------------------------------------------------------
 * 子进程内部注册/注销（由命令处理调用）
 * ------------------------------------------------------------------------- */
int seccomp_hook_register(int nr, hook_callback_t callback, void *userdata) {
    auto *node = static_cast<hook_node_t *>(malloc(sizeof(hook_node_t)));
    if (!node) return -1;
    node->nr = nr;
    node->callback = callback;
    node->userdata = userdata;

    pthread_mutex_lock(&g_hook_lock);
    node->next = g_hook_list;
    g_hook_list = node;
    pthread_mutex_unlock(&g_hook_lock);
    return 0;
}

int seccomp_hook_unregister(int nr, hook_callback_t callback, void *userdata) {
    pthread_mutex_lock(&g_hook_lock);
    hook_node_t **pp = &g_hook_list;
    int found = 0;
    while (*pp) {
        hook_node_t *cur = *pp;
        if (cur->nr == nr && cur->callback == callback && cur->userdata == userdata) {
            *pp = cur->next;
            free(cur);
            found = 1;
            break;
        }
        pp = &cur->next;
    }
    pthread_mutex_unlock(&g_hook_lock);
    return found ? 0 : -1;
}

/* -------------------------------------------------------------------------
 * supervisor 子进程主循环（带命令处理）
 * ------------------------------------------------------------------------- */
static void supervisor_loop(int lfd, int cmd_fd, int use_signal) {
    LOGD("supervisor_loop started, lfd=%d", lfd);
    g_notify_fd = lfd;
    struct seccomp_notif_sizes sizes{};
    if (seccomp(SECCOMP_GET_NOTIF_SIZES, 0, &sizes) != 0) {
        LOGE("GET_NOTIF_SIZES failed\n");
        _exit(-1);
    }

    auto *req = static_cast<struct seccomp_notif *>(malloc(sizes.seccomp_notif));
    auto *resp = static_cast<struct seccomp_notif_resp *>(malloc(sizes.seccomp_notif_resp));
    if (!req || !resp) {
        LOGE("malloc failed\n");
        _exit(-1);
    }

    struct pollfd fds[2];
    fds[0].fd = lfd;
    fds[0].events = POLLIN;
    fds[1].fd = cmd_fd;
    fds[1].events = POLLIN;

    int is_first_enter = 1;

    while (true) {
        int ret = poll(fds, 2, -1);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }

        // 处理 seccomp 通知
        if (fds[0].revents & POLLIN) {
            memset(req, 0, sizes.seccomp_notif);
            if (ioctl(lfd, SECCOMP_IOCTL_NOTIF_RECV, req) < 0) {
                if (errno == EINTR) continue;
                LOGE("NOTIF_RECV failed: %d\n", errno);
                break;
            }
            LOGD("supervisor: received notification id=%llu, nr=%d, pid=%d",
                 req->id, req->data.nr, req->pid);

            hook_regs_t regs = {0};
            if (use_signal && is_first_enter) {
                if (tgkill(g_parent_pid, static_cast<pid_t>(req->pid), SIGUSR2) == 0) {
                    LOGD("supervisor: tgkill sent to pid=%d", req->pid);
                    int timeout = 100;
                    while (timeout-- > 0 && g_shared->ready == 0) {
                        usleep(1000);
                    }
                    if (g_shared->ready) {
                        regs = g_shared->regs;
                        g_shared->ready = 0;
                        LOGD("supervisor: pc %llx from reg_pipe", regs.pc);
                    }
                    is_first_enter = 0;
                    continue;
                } else {
                    LOGE("tgkill failed: %d\n", errno);
                }
            } else if (use_signal) {
                is_first_enter = 1;
            }

            hook_request_t hook_req;
            hook_req.id = req->id;
            hook_req.syscall_nr = req->data.nr;
            hook_req.pid = static_cast<pid_t>(req->pid);
            memcpy(hook_req.args, req->data.args, sizeof(req->data.args));
            hook_req.regs = regs;

            hook_response_t hook_resp;
            memset(&hook_resp, 0, sizeof(hook_resp));
            hook_resp.id = req->id;
            hook_resp.action = HOOK_ACTION_ALLOW;

            // 执行回调
            LOGD("supervisor: before callbacks");
            // pthread_mutex_lock(&g_hook_lock);
            hook_node_t *node = g_hook_list;
            while (node) {
                if (node->nr == hook_req.syscall_nr) {
                    node->callback(&hook_req, &hook_resp, node->userdata);
                }
                node = node->next;
            }
            // pthread_mutex_unlock(&g_hook_lock);
            LOGD("supervisor: after callbacks");

            memset(resp, 0, sizes.seccomp_notif_resp);
            resp->id = req->id;
            if (hook_resp.action == HOOK_ACTION_ALLOW) {
                resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
                resp->error = 0;
                resp->val = 0;
            } else if (hook_resp.action == HOOK_ACTION_DENY) {
                resp->flags = 0;
                resp->error = hook_resp.error;
                resp->val = 0;
            } else {
                resp->flags = 0;
                resp->error = 0;
                resp->val = hook_resp.val;
            }

            if (ioctl(lfd, SECCOMP_IOCTL_NOTIF_ID_VALID, &req->id) == 0) {
                if (ioctl(lfd, SECCOMP_IOCTL_NOTIF_SEND, resp) < 0) {
                    LOGE("SEND error: %d\n", errno);
                }
            }
        }

        // 处理父进程命令
        if (fds[1].revents & POLLIN) {
            cmd_t cmd;
            ssize_t n = read(cmd_fd, &cmd, sizeof(cmd));
            if (n == sizeof(cmd)) {
                if (cmd.type == CMD_REGISTER) {
                    seccomp_hook_register(cmd.nr, (hook_callback_t)cmd.callback, (void*)cmd.userdata);
                } else if (cmd.type == CMD_UNREGISTER) {
                    seccomp_hook_unregister(cmd.nr, (hook_callback_t)cmd.callback, (void*)cmd.userdata);
                }
            } else if (n == 0) {
                break;
            } else {
                LOGE("read cmd failed: %zd\n", n);
            }
        }
    }

    free(req);
    free(resp);
    close(lfd);
    close(cmd_fd);
    _exit(0);
}

/* -------------------------------------------------------------------------
 * 父进程远程注册/注销
 * ------------------------------------------------------------------------- */
int seccomp_hook_register_remote(const int *syscall_list,
                                 const struct sock_fprog *custom_filter, hook_callback_t callback, void *userdata) {
    if (!syscall_list || *syscall_list == -1) return -1;
    struct sock_fprog prog{};
    if (custom_filter) {
        prog = *custom_filter;
    } else {
        prog = build_filter(syscall_list);
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
        LOGE("failed to add filter");
    }
    for (const int* nr = syscall_list; *nr != -1; nr++) {
        cmd_t cmd;
        cmd.type = CMD_REGISTER;
        cmd.nr = *nr;
        cmd.callback = (uintptr_t)callback;
        cmd.userdata = (uintptr_t)userdata;
        ssize_t w = write(g_cmd_pipe_wr, &cmd, sizeof(cmd));
        if (w != sizeof(cmd))
            return -1;
    }
    return 0;
}

int seccomp_hook_unregister_remote(const int *syscall_list, hook_callback_t callback, void *userdata) {
    for (const int* nr = syscall_list; *nr != -1; nr++) {
        cmd_t cmd;
        cmd.type = CMD_UNREGISTER;
        cmd.nr = *nr;
        cmd.callback = (uintptr_t)callback;
        cmd.userdata = (uintptr_t)userdata;
        ssize_t w = write(g_cmd_pipe_wr, &cmd, sizeof(cmd));
        if (w != sizeof(cmd))
            return -1;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * 初始化库（父进程调用）
 * ------------------------------------------------------------------------- */
int seccomp_hook_init(const int *syscall_list,
                      const struct sock_fprog *custom_filter,
                      const hook_entry_t *entries,
                      int num_entries,
                      int use_signal) {
    LOGD("seccomp_hook_init: called");
    
    if (g_initialized) return 0;

    if (prctl(PR_SET_DUMPABLE, 1) < 0) {
        LOGE("prctl failed\n");
        return -1;
    }

    g_parent_pid = getpid();

    // 创建共享内存
    g_shared = static_cast<shared_regs *>(mmap(nullptr, sizeof(struct shared_regs),
                    PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    if (g_shared == MAP_FAILED) {
        LOGE("mmap failed\n");
        return -1;
    }
    g_shared->ready = 0;

    // 创建命令管道
    int cmd_pipe[2];
    if (pipe(cmd_pipe) < 0) {
        LOGE("pipe(cmd) failed\n");
        munmap(g_shared, sizeof(struct shared_regs));
        return -1;
    }
    g_cmd_pipe_wr = cmd_pipe[1];
    g_cmd_pipe_rd = cmd_pipe[0];

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        LOGE("prctl failed\n");
        close(cmd_pipe[0]); close(cmd_pipe[1]);
        munmap(g_shared, sizeof(struct shared_regs));
        return -1;
    }

    struct sock_fprog prog{};
    if (custom_filter) {
        prog = *custom_filter;
    } else if (syscall_list) {
        prog = build_filter(syscall_list);
    } else {
        LOGE("no filter provided\n");
        close(cmd_pipe[0]); close(cmd_pipe[1]);
        munmap(g_shared, sizeof(struct shared_regs));
        return -1;
    }

    int lfd = seccomp(SECCOMP_SET_MODE_FILTER,
                      SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    LOGD("seccomp returned lfd = %d", lfd);
    if (lfd < 0) {
        LOGE("seccomp failed: %d\n", errno);
        close(cmd_pipe[0]); close(cmd_pipe[1]);
        munmap(g_shared, sizeof(struct shared_regs));
        return -1;
    }

    struct sigaction sa{};
    sa.sa_sigaction = signal_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR2, &sa, nullptr) < 0) {
        LOGE("sigaction failed\n");
        close(lfd);
        close(cmd_pipe[0]); close(cmd_pipe[1]);
        munmap(g_shared, sizeof(struct shared_regs));
        return -1;
    }
    LOGD("sigaction registered");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        LOGE("socketpair failed\n");
        close(lfd);
        close(cmd_pipe[0]); close(cmd_pipe[1]);
        munmap(g_shared, sizeof(struct shared_regs));
        return -1;
    }
    LOGD("socketpair created: [%d,%d]", sv[0], sv[1]);

    pid_t pid = fork();
    LOGD("fork returned pid = %d", pid);
    if (pid < 0) {
        LOGE("fork failed\n");
        close(lfd); close(sv[0]); close(sv[1]);
        close(cmd_pipe[0]); close(cmd_pipe[1]);
        munmap(g_shared, sizeof(struct shared_regs));
        return -1;
    }

    if (pid == 0) {  // 子进程
        LOGD("supervisor child started");
        close(sv[1]);
        close(cmd_pipe[1]);   // 关闭写端
        int lfd_child = recvfd(sv[0]);
        close(sv[0]);
        close(lfd);           // 父进程的 lfd 已关闭

        // 注册初始钩子列表
        for (int i = 0; i < num_entries; i++) {
            const hook_entry_t *entry = &entries[i];
            seccomp_hook_register(entry->nr, entry->callback, entry->userdata);
        }

        supervisor_loop(lfd_child, cmd_pipe[0], use_signal);
        _exit(0);
    }

    // 父进程
    close(sv[0]);
    LOGD("parent sending fd");
    sendfd(sv[1], lfd);
    close(sv[1]);
    close(lfd);
    close(cmd_pipe[0]);       // 关闭读端

    g_initialized = 1;
    LOGD("handler thread created");
    return 0;
}

int seccomp_hook_add_fd(const hook_request_t *req, int srcfd, __u32 newfd_flags) {
    if (!req || g_notify_fd == -1) {
        errno = EINVAL;
        return -1;
    }

    // 检查 newfd_flags 是否合法（目前只支持 O_CLOEXEC，也可支持其他有效标志）
    if (newfd_flags & ~O_CLOEXEC) {
        errno = EINVAL;
        return -1;
    }

    struct seccomp_notif_addfd addfd = {
            .id = req->id,
            .flags = 0,               // 固定为 0，不使用 SETFD 和 SEND
            .srcfd = static_cast<__u32>(srcfd),
            .newfd = 0,               // 固定为 0，表示由内核自动分配
            .newfd_flags = newfd_flags,
    };
    return ioctl(g_notify_fd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);
}