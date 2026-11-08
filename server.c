#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define PORT 3000
#define PUBLIC_DIR "public"

#define RATE_LIMIT 100
#define RATE_WINDOW 10
#define RATE_TABLE_SIZE 1024

static char root[PATH_MAX];
static size_t root_len;

struct mime {
    const char *ext;
    const char *type;
};

static const struct mime mimes[] = {
    {".html", "text/html; charset=utf-8"},
    {".css", "text/css"},
    {".js", "text/javascript"},
    {".json", "application/json"},
    {".txt", "text/plain; charset=utf-8"},
    {".png", "image/png"},
    {".jpg", "image/jpeg"},
    {".jpeg", "image/jpeg"},
    {".gif", "image/gif"},
    {".svg", "image/svg+xml"},
    {".ico", "image/x-icon"},
    {".woff2", "font/woff2"},
    {".woff", "font/woff"},
    {".webp", "image/webp"},
    {".pdf", "application/pdf"},
    {".xml", "application/xml"},
    {".mp4", "video/mp4"},
    {".webmanifest", "application/manifest+json"},
};

struct rate_entry {
    char ip[INET6_ADDRSTRLEN];
    time_t window_start;
    int count;
};

struct rate_state {
    atomic_flag lock;
    struct rate_entry table[RATE_TABLE_SIZE];
};

// Shared memory. The parent creates it and every child process uses it.
static struct rate_state *rate;

static time_t now_seconds(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec;
}

// Return 1 if this IP stays within the limit, 0 if not.
static int rate_allow(const char *ip)
{
    time_t now = now_seconds();
    struct rate_entry *match = NULL;
    struct rate_entry *oldest = &rate->table[0];
    int allowed = 1;
    size_t i;

    while (atomic_flag_test_and_set(&rate->lock))
        sched_yield();

    for (i = 0; i < RATE_TABLE_SIZE; i++) {
        struct rate_entry *e = &rate->table[i];

        if (e->count > 0 && strcmp(e->ip, ip) == 0) {
            match = e;
            break;
        }
        if (e->window_start < oldest->window_start)
            oldest = e;
    }

    if (match != NULL) {
        if (now - match->window_start >= RATE_WINDOW) {
            match->window_start = now;
            match->count = 0;
        }
        if (match->count >= RATE_LIMIT)
            allowed = 0;
        else
            match->count++;
    } else {
        // Unknown IP: take over the entry with the oldest window.
        snprintf(oldest->ip, sizeof oldest->ip, "%s", ip);
        oldest->window_start = now;
        oldest->count = 1;
    }

    atomic_flag_clear(&rate->lock);
    return allowed;
}

static const char *mime_type(const char *file)
{
    const char *ext = strrchr(file, '.');
    size_t i;

    if (ext != NULL) {
        for (i = 0; i < sizeof mimes / sizeof mimes[0]; i++) {
            if (strcmp(ext, mimes[i].ext) == 0)
                return mimes[i].type;
        }
    }
    return "application/octet-stream";
}

static int send_all(int fd, const char *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = send(fd, buf, len, 0);
        if (n <= 0)
            return -1;
        buf += n;
        len -= (size_t)n;
    }
    return 0;
}

static int send_error(int fd, int status, const char *text)
{
    char msg[512];
    int n = snprintf(msg, sizeof msg,
                     "HTTP/1.1 %d %s\r\n"
                     "Content-Type: text/plain\r\n"
                     "Content-Length: %zu\r\n"
                     "Connection: close\r\n"
                     "\r\n"
                     "%s\n",
                     status, text, strlen(text) + 1, text);

    if (n > 0 && (size_t)n < sizeof msg)
        send_all(fd, msg, (size_t)n);
    return status;
}

// Read until the headers end. Return 0 on success, -1 on failure.
static int read_request(int fd, char *buf, size_t size)
{
    size_t len = 0;

    while (len < size - 1) {
        ssize_t n = recv(fd, buf + len, size - 1 - len, 0);
        if (n <= 0)
            return -1;
        len += (size_t)n;
        buf[len] = '\0';
        if (strstr(buf, "\r\n\r\n") != NULL)
            return 0;
    }
    return -1;
}

// Copy a header value into out. Return 0 if found, -1 if not.
static int get_header(const char *req, const char *name, char *out,
                      size_t size)
{
    size_t name_len = strlen(name);
    const char *line = strstr(req, "\r\n");

    while (line != NULL) {
        line += 2;
        if (strncmp(line, "\r\n", 2) == 0)
            break;
        if (strncasecmp(line, name, name_len) == 0 && line[name_len] == ':') {
            const char *value = line + name_len + 1;
            size_t len = strcspn(value, "\r\n");

            while (len > 0 && (*value == ' ' || *value == '\t')) {
                value++;
                len--;
            }
            while (len > 0 && (value[len - 1] == ' ' || value[len - 1] == '\t'))
                len--;
            if (len == 0 || len >= size)
                return -1;
            memcpy(out, value, len);
            out[len] = '\0';
            return 0;
        }
        line = strstr(line, "\r\n");
    }
    return -1;
}

// Trust CF-Connecting-IP only from loopback, where the tunnel connects.
static void resolve_ip(const char *req, const char *peer, char *out,
                       size_t size)
{
    char value[INET6_ADDRSTRLEN];
    struct in_addr v4;
    struct in6_addr v6;

    snprintf(out, size, "%s", peer);
    if (strcmp(peer, "127.0.0.1") != 0 && strcmp(peer, "::1") != 0)
        return;
    if (get_header(req, "CF-Connecting-IP", value, sizeof value) < 0)
        return;
    if (inet_pton(AF_INET, value, &v4) == 1 ||
        inet_pton(AF_INET6, value, &v6) == 1)
        snprintf(out, size, "%s", value);
}

// Cut the query string and decode %XX in place. Return -1 on bad input.
static int decode_path(char *path)
{
    char *in = path;
    char *out = path;
    char *cut = strpbrk(path, "?#");

    if (cut != NULL)
        *cut = '\0';

    while (*in != '\0') {
        if (*in != '%') {
            *out++ = *in++;
            continue;
        }
        if (!isxdigit((unsigned char)in[1]) || !isxdigit((unsigned char)in[2]))
            return -1;
        char hex[3] = {in[1], in[2], '\0'};
        long value = strtol(hex, NULL, 16);
        if (value == 0)
            return -1;
        *out++ = (char)value;
        in += 3;
    }
    *out = '\0';
    return 0;
}

// Send the file for a URL path. Return the HTTP status.
static int serve_file(int fd, char *path, int head_only)
{
    char target[PATH_MAX];
    char resolved[PATH_MAX];
    char header[256];
    char chunk[8192];
    struct stat st;
    int file;
    int n;

    if (path[0] != '/')
        return send_error(fd, 400, "Bad Request");

    n = snprintf(target, sizeof target, "%s%s%s", root, path,
                 path[strlen(path) - 1] == '/' ? "index.html" : "");
    if (n < 0 || (size_t)n >= sizeof target)
        return send_error(fd, 404, "Not Found");

    // realpath removes "..", "." and symlinks.
    if (realpath(target, resolved) == NULL)
        return send_error(fd, 404, "Not Found");

    // The resolved path must stay inside the public directory.
    if (strncmp(resolved, root, root_len) != 0 || resolved[root_len] != '/')
        return send_error(fd, 404, "Not Found");

    file = open(resolved, O_RDONLY);
    if (file < 0)
        return send_error(fd, 404, "Not Found");
    if (fstat(file, &st) < 0) {
        close(file);
        return send_error(fd, 404, "Not Found");
    }
    if (S_ISDIR(st.st_mode)) {
        char dir_path[PATH_MAX];

        close(file);
        if (path[strlen(path) - 1] == '/')
            return send_error(fd, 404, "Not Found");
        snprintf(dir_path, sizeof dir_path, "%s/", resolved + root_len);
        return serve_file(fd, dir_path, head_only);
    }
    if (!S_ISREG(st.st_mode)) {
        close(file);
        return send_error(fd, 404, "Not Found");
    }

    n = snprintf(header, sizeof header,
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: %s\r\n"
                 "Content-Length: %lld\r\n"
                 "Connection: close\r\n"
                 "\r\n",
                 mime_type(resolved), (long long)st.st_size);
    if (n > 0 && (size_t)n < sizeof header &&
        send_all(fd, header, (size_t)n) == 0 && !head_only) {
        ssize_t got;
        while ((got = read(file, chunk, sizeof chunk)) > 0) {
            if (send_all(fd, chunk, (size_t)got) < 0)
                break;
        }
    }
    close(file);
    return 200;
}

static void print_clean(const char *s)
{
    for (; *s != '\0'; s++)
        putchar(isprint((unsigned char)*s) ? *s : '?');
}

static void log_request(const char *ip, const char *method, const char *path,
                        int status)
{
    printf("%s ", ip);
    print_clean(method);
    putchar(' ');
    print_clean(path);
    printf(" %d\n", status);
    fflush(stdout);
}

static void handle_client(int fd, const char *peer)
{
    char req[8192];
    char ip[INET6_ADDRSTRLEN];
    char method[8] = "-";
    char path[1024] = "-";
    char version[16] = "";
    struct timeval timeout = {5, 0};
    int status;

    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);

    snprintf(ip, sizeof ip, "%s", peer);
    if (read_request(fd, req, sizeof req) < 0 ||
        sscanf(req, "%7s %1023s %15s", method, path, version) != 3 ||
        strncmp(version, "HTTP/1.", 7) != 0) {
        status = send_error(fd, 400, "Bad Request");
    } else {
        resolve_ip(req, peer, ip, sizeof ip);
        if (!rate_allow(ip))
            status = send_error(fd, 429, "Too Many Requests");
        else if (strcmp(method, "GET") != 0 && strcmp(method, "HEAD") != 0)
            status = send_error(fd, 405, "Method Not Allowed");
        else if (decode_path(path) < 0)
            status = send_error(fd, 400, "Bad Request");
        else
            status = serve_file(fd, path, strcmp(method, "HEAD") == 0);
    }
    log_request(ip, method, path, status);
}

// Write the client address as text. IPv4 clients show as plain IPv4.
static void peer_ip(const struct sockaddr_in6 *addr, char *out, size_t size)
{
    if (IN6_IS_ADDR_V4MAPPED(&addr->sin6_addr))
        inet_ntop(AF_INET, &addr->sin6_addr.s6_addr[12], out, (socklen_t)size);
    else
        inet_ntop(AF_INET6, &addr->sin6_addr, out, (socklen_t)size);
}

int main(void)
{
    struct sockaddr_in6 addr;
    int listener;
    int yes = 1;
    int no = 0;

    if (realpath(PUBLIC_DIR, root) == NULL) {
        perror(PUBLIC_DIR);
        return 1;
    }
    root_len = strlen(root);

    rate = mmap(NULL, sizeof *rate, PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_ANON, -1, 0);
    if (rate == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    atomic_flag_clear(&rate->lock);

    signal(SIGCHLD, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);

    listener = socket(AF_INET6, SOCK_STREAM, 0);
    if (listener < 0) {
        perror("socket");
        return 1;
    }
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
    setsockopt(listener, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof no);

    memset(&addr, 0, sizeof addr);
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(PORT);

    if (bind(listener, (struct sockaddr *)&addr, sizeof addr) < 0) {
        perror("bind");
        return 1;
    }
    if (listen(listener, 64) < 0) {
        perror("listen");
        return 1;
    }
    printf("listening on :%d\n", PORT);
    fflush(stdout);

    for (;;) {
        struct sockaddr_in6 client;
        socklen_t client_len = sizeof client;
        char ip[INET6_ADDRSTRLEN];
        pid_t pid;
        int fd;

        fd = accept(listener, (struct sockaddr *)&client, &client_len);
        if (fd < 0) {
            if (errno != EINTR)
                perror("accept");
            continue;
        }
        peer_ip(&client, ip, sizeof ip);

        pid = fork();
        if (pid == 0) {
            close(listener);
            handle_client(fd, ip);
            close(fd);
            _exit(0);
        }
        if (pid < 0)
            perror("fork");
        close(fd);
    }
}
