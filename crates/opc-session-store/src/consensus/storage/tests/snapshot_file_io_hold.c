#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

/* Isolated libtest child only. Hold the actual call on one configured fd,
 * then invoke the real Linux syscall. Control traffic bypasses interposition. */
static int hold_call(int fd, const char *operation) {
    const char *target = getenv("OPC_SNAPSHOT_IO_TARGET");
    const char *socket_path = getenv("OPC_SNAPSHOT_IO_SOCKET");
    if (!target || !socket_path) return -1;
    int marker = syscall(SYS_openat, AT_FDCWD, target, O_RDONLY | O_CLOEXEC, 0);
    if (marker < 0) return -1;
    char text[64] = {0};
    ssize_t count = syscall(SYS_read, marker, text, sizeof(text) - 1);
    syscall(SYS_close, marker);
    int expected = -1;
    char selected[16] = {0};
    if (count <= 0 || sscanf(text, "%d %15s", &expected, selected) != 2 ||
        expected != fd || strcmp(selected, operation) != 0) return -1;

    int channel = syscall(SYS_socket, AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (channel < 0) _exit(90);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    if (strlen(socket_path) >= sizeof(address.sun_path)) _exit(91);
    memcpy(address.sun_path + 1, socket_path, strlen(socket_path));
    socklen_t length = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(socket_path);
    if (syscall(SYS_connect, channel, &address, length) != 0) _exit(92);
    char signal = 'S';
    if (syscall(SYS_write, channel, &signal, 1) != 1) _exit(93);
    ssize_t received;
    do {
        received = syscall(SYS_read, channel, &signal, 1);
    } while (received < 0 && errno == EINTR);
    /* EOF also releases the worker when the Rust observer unwinds. */
    return channel;
}

static void finish_call(int channel, int saved_errno) {
    if (channel >= 0) {
        char signal = 'F';
        syscall(SYS_sendto, channel, &signal, 1, MSG_NOSIGNAL, NULL, 0);
        syscall(SYS_close, channel);
    }
    errno = saved_errno;
}

ssize_t read(int fd, void *buffer, size_t length) {
    int channel = hold_call(fd, "read");
    ssize_t result = syscall(SYS_read, fd, buffer, length);
    int saved_errno = errno;
    finish_call(channel, saved_errno);
    return result;
}

int fsync(int fd) {
    int channel = hold_call(fd, "fsync");
    int result = syscall(SYS_fsync, fd);
    int saved_errno = errno;
    finish_call(channel, saved_errno);
    return result;
}
