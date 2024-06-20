/**
 * LAZY static file server
 * serve conn ONE BY ONE, http1.1, can only GET
 * malloc-allergic
 */

#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define PORT 2048
#define READ_BUF_CAP 1024
#define HEADER_KEY_CAP 128
#define HEADER_VALUE_CAP 512
#define HEADER_CAP 64
#define CR 13
#define LF 10
#define PATH_LEN_MAX 256
#define SP 32
#define LOG_LEVEL 4

#if LOG_LEVEL > 3
#define debug(...)                                                             \
  printf("> debug: ");                                                         \
  printf(__VA_ARGS__);                                                         \
  fflush(stdout)
#else
#define debug(...)
#endif

#if LOG_LEVEL > 2
#define info(...)                                                              \
  printf("> info: ");                                                          \
  printf(__VA_ARGS__)
#else
#define info(...)
#endif

#if LOG_LEVEL > 1
#define warn(...)                                                              \
  printf("> warn: ");                                                          \
  printf(__VA_ARGS__)
#else
#define warn(...)
#endif

#define panic(msg)                                                             \
  perror(msg);                                                                 \
  exit(EXIT_FAILURE)

typedef struct HeaderEntry {
  char key[HEADER_KEY_CAP];
  char value[HEADER_VALUE_CAP];
} HeaderEntry;

// no list no worry
typedef struct HeaderMap {
  HeaderEntry headers[HEADER_CAP];
  size_t len;
} HeaderMap;

typedef enum Method {
  Get,
} Method;

typedef struct HttpReq {
  HeaderMap headers;
  Method method;
  char path[PATH_LEN_MAX];
} HttpReq;

typedef enum ECode {
  EServer = 500,
  EClient = 400,
  ENotFound = 404,
} ECode;

typedef struct MimeType {
  char *ext;
  char *mime;
} MimeType;

// return file size
off_t file_exist(char *path) {
  struct stat s;
  if (stat(path, &s) < 0) {
    return 0;
  }

  if (!S_ISREG(s.st_mode)) {
    return 0;
  }

  return s.st_size;
}

bool is_crlf(char *str) {
  if (str[0] == CR && str[1] == LF) {
    return true;
  } else {
    return false;
  }
}

bool parse_http_method(char *req_buf, size_t end, HttpReq *req) {
  if (strncmp(req_buf, "GET", 3) != 0) {
    warn("support GET only");
    return false;
  }
  req->method = Get;

  size_t i = 3;
  assert(req_buf[i++] == SP);

  while (i < end) {
    if (req_buf[i] == SP) {
      strncpy(req->path, &req_buf[4], i - 4);
      i++;
      break;
    }
    i++;
  }

  debug("parse_http_method: path: %s\n", req->path);
  if (strncmp(&req_buf[i], "HTTP/1.1", 8) != 0) {
    warn("support http1.1 only");
    return false;
  }

  return true;
}

bool parse_http_req(char *req_buf, size_t req_len, HttpReq *req) {
  // debug("parse_http_req full: req buf: \n\n%s\n\n", req_buf);
  size_t line_start = 0;
  for (size_t i = 1; i < req_len; i++) {
    if (is_crlf(&req_buf[i - 1])) {
      if (line_start == 0) {
        // first line
        if (!parse_http_method(req_buf, i, req)) {
          return false;
        }
      } else {
        // TODO: parse header
      }

      line_start = i + 1;
    }
  }

  return true;
}

void send_err(int sockfd, ECode code, char *msg) {
  char pack[255];
  memset(pack, 0, 255);
  sprintf(pack, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\n\r\n", code, msg);
  debug("send_err: %s", pack);
  if (send(sockfd, pack, strlen(pack), 0) < 0) {
    panic("send err");
  }
}

void send_err_404(int sockfd) { send_err(sockfd, ENotFound, "Not Found"); }

char *mime_mapping(char *path) {
  static const MimeType mapping[] = {
      {".html", "text/html"},
      {".js", "application/javascript"},
      {".css", "text/css"},
      {".png", "image/png"},
  };
  char *ext = NULL;
  size_t path_len = strlen(path);
  for (size_t i = 0; i < path_len; i++) {
    if (path[i] == '.') {
      ext = &path[i];
      debug("mime_mapping ext: %s\n", ext);
    }
  }
  if (ext == NULL) {
    // no ext
    return "text/plain";
  }

  size_t map_len = sizeof(mapping) / sizeof(MimeType);
  size_t ext_len = strlen(ext);
  for (size_t j = 0; j < map_len; j++) {
    if (strncmp(ext, mapping[j].ext, ext_len) == 0) {
      return mapping[j].mime;
    }
  }

  // not a supported ext
  return "text/plain";
}

// Connection: Close or KeepAlive
// all in client's favor
bool send_file(int sockfd, char *path) {
  info("query file: %s\n", path);
  if (path[0] == '/') {
    path++;
  }
  int size = file_exist(path);
  if (size == 0) {
    send_err_404(sockfd);
    return false;
  }

  char header[255];
  memset(header, 0, 255);
  char *content_type = mime_mapping(path);
  // Connection: Close\r\n
  sprintf(header,
          "HTTP/1.1 200\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n",
          content_type, size);
  if (send(sockfd, header, strlen(header), 0) < 0) {
    panic("send file header err");
  }

  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    panic("send file open err");
  }

  off_t len;
  if (sendfile(fd, sockfd, 0, &len, NULL, 0) < 0) {
    panic("sendfile err");
  }
  return true;
}

int init_sock() {
  int sock_fd = socket(PF_INET, SOCK_STREAM, 0);
  if (sock_fd < 0) {
    panic("sock err");
  }

  struct sockaddr_in local_addr;
  memset(&local_addr, 0, sizeof(local_addr));
  local_addr.sin_family = PF_INET;
  local_addr.sin_addr.s_addr = INADDR_ANY;
  local_addr.sin_port = htons(PORT);
  if (bind(sock_fd, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0) {
    panic("bind err");
  }

  if (listen(sock_fd, 0) < 0) {
    panic("listen err");
  }

  info("init_sock: listening at %d:%d\n", INADDR_ANY, PORT);
  return sock_fd;
}

void handle_http(int remote_sock) {
  // request packet may require one more recv
  char full_read_buf[READ_BUF_CAP];
  memset(full_read_buf, 0, READ_BUF_CAP);
  HttpReq request;
  memset(&request, 0, sizeof(request));

  while (true) {
    // read (more)
    char read_buf[READ_BUF_CAP];
    memset(read_buf, 0, READ_BUF_CAP);

    info("sock: %d wait on recv\n", remote_sock);
    ssize_t read_len = recv(remote_sock, read_buf, READ_BUF_CAP, 0);
    if (read_len < 0) {
      panic("recv err");
    }

    if (read_len == 0) {
      info("client closed\n");
      break;
    }

    info("sock: %d recv len: %zd\n", remote_sock, read_len);
    strlcat(full_read_buf, read_buf, READ_BUF_CAP);
    size_t full_len = strlen(full_read_buf);
    assert(full_len > 3);
    size_t pack_start = 0;

    for (size_t i = 3; i < full_len; i++) {
      // may have multi reqs in one recv
      if (is_crlf(&full_read_buf[i - 3]) && is_crlf(&full_read_buf[i - 1])) {
        // two-cont-newline = end of header
        if (parse_http_req(&full_read_buf[pack_start], i - pack_start,
                           &request)) {
          bool found = send_file(remote_sock, request.path);
          info("sock: %d resp: %s found: %d\n", remote_sock, request.path,
               found);
          memset(&request, 0, sizeof(request));
        } else {
          info("sock: %d send err\n", remote_sock);
          send_err(remote_sock, EClient, "Bad Req");
        }

        pack_start = i + 1;
      }
    }

    debug("pack_start: %lu\n", pack_start);
    if (pack_start < full_len) {
      debug("pack has leftover\n");
      // some bytes left
      // go shifting
      for (size_t j = 0; j < full_len - pack_start; j++) {
        full_read_buf[j] = full_read_buf[j + pack_start];
      }
      for (size_t k = pack_start + 1; k < full_len; k++) {
        full_read_buf[k] = 0;
      }
    } else {
      // reset
      memset(full_read_buf, 0, READ_BUF_CAP);
    }
  }
}

int local_sock;
pid_t master_pid;

void cleanup(int sig) {
  if (getpid() == master_pid) {
    close(local_sock);
    info("Stop on Ctrl-c\n");
    fflush(stdout);
    exit(EXIT_SUCCESS);
  }
}

int main() {
  info("Ctrl-c to Stop!");
  local_sock = init_sock();
  master_pid = getpid();
  signal(SIGINT, cleanup);

  while (true) {
    struct sockaddr_in remote_addr;
    socklen_t remote_addr_len = sizeof(remote_addr);

    // new conn arrived
    info("master wait on accept\n");
    int remote_sock =
        accept(local_sock, (struct sockaddr *)&remote_addr, &remote_addr_len);
    if (remote_sock < 0) {
      panic("accept err");
    }
    info("accept: %s:%d\n", inet_ntoa(remote_addr.sin_addr),
         remote_addr.sin_port);

    int child = fork();
    if (child < 0) {
      panic("fork err");
    } else if (child != 0) {
      info("fork pid: %d to handle socket: %d\n", child, remote_sock);
      // parent not interested in this sock
      close(remote_sock);
      // clean zombies
      int already_dead;
      do {
        // there are always ONE zombie remaining
        already_dead = waitpid(0, 0, WNOHANG);
        if (already_dead < 0) {
          panic("wait pid err");
        } else if (already_dead > 0) {
          info("bury pid: %d\n", already_dead);
        }
      } while (already_dead != 0);
      // parent continue
    } else {
      // child process
      handle_http(remote_sock);
      close(local_sock);
      close(remote_sock);
      // child process about to exit
      warn("child %d become ZOMBIE\n", getpid());
      // child break to exit
      break;
    }
  }

  info("pid: %d exit\n", getpid());
  return EXIT_SUCCESS;
}
