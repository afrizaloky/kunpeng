#define main tls_host_main
#include "../ca/tls_host.c"
#undef main
#include <assert.h>
#include <sys/wait.h>

static unsigned int calls;
static unsigned int terminal_flag;

TEEC_Result TEEC_InvokeCommand(TEEC_Session *session, uint32_t command,
    TEEC_Operation *operation, uint32_t *origin)
{
    (void)session;
    (void)origin;
    assert(command == TLS_CMD_PROCESS);
    assert(calls < 4);
    if (calls == 0) {
        assert(operation->params[0].tmpref.size == 0);
        operation->params[1].tmpref.size = 0;
        operation->params[2].value.a = 0;
    } else {
        if (calls == 1) {
            assert(operation->params[0].tmpref.size == 4);
            assert(memcmp(operation->params[0].tmpref.buffer, "ping", 4) == 0);
        } else {
            assert(operation->params[0].tmpref.size == 0);
        }
        memset(operation->params[1].tmpref.buffer, (int)calls,
            TLS_PROTOCOL_CAPACITY);
        operation->params[1].tmpref.size = TLS_PROTOCOL_CAPACITY;
        operation->params[2].value.a = calls == 3 ? terminal_flag :
            TLS_PROTOCOL_FLAG_MORE_OUTPUT | terminal_flag;
    }
    ++calls;
    return TEEC_SUCCESS;
}

static void flush_terminal_output(unsigned int flag)
{
    int pair[2];
    int size = 1024;
    int epoll_fd;
    int status;
    pid_t child;
    size_t total = 0;
    unsigned char buffer[4096];
    terminal_flag = flag;
    calls = 0;
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
        0, pair) == 0);
    assert(setsockopt(pair[0], SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) == 0);
    assert(send(pair[1], "ping", 4, MSG_NOSIGNAL) == 4);
    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    assert(epoll_fd >= 0);
    assert(watch_socket(epoll_fd, pair[1]) == 0);
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        TEEC_Session session = {0};
        int child_epoll = epoll_create1(EPOLL_CLOEXEC);
        assert(close(pair[1]) == 0);
        assert(child_epoll >= 0);
        assert(watch_socket(child_epoll, pair[0]) == 0);
        relay(child_epoll, pair[0], &session);
        assert(calls == 4);
        assert(close(pair[0]) == 0);
        assert(close(child_epoll) == 0);
        assert(close(epoll_fd) == 0);
        _exit(0);
    }
    assert(close(pair[0]) == 0);
    for (;;) {
        ssize_t count = recv(pair[1], buffer, sizeof(buffer), 0);
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            assert(wait_ready(epoll_fd, pair[1], EPOLLIN) == 1);
            continue;
        }
        assert(count >= 0);
        if (count == 0)
            break;
        for (ssize_t i = 0; i < count; ++i) {
            assert(total < 3 * TLS_PROTOCOL_CAPACITY);
            assert(buffer[i] == total / TLS_PROTOCOL_CAPACITY + 1);
            ++total;
        }
    }
    assert(total == 3 * TLS_PROTOCOL_CAPACITY);
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(close(pair[1]) == 0);
    assert(close(epoll_fd) == 0);
}

int main(void)
{
    flush_terminal_output(TLS_PROTOCOL_FLAG_FATAL);
    flush_terminal_output(TLS_PROTOCOL_FLAG_CLOSED);
    puts("host socket tests passed");
    return 0;
}
