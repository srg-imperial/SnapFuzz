/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "real_syscall.h"
#include "sbr_api_defs.h"

#define __STDC_WANT_LIB_EXT2__ 1
#define _GNU_SOURCE

#include <libgen.h>
#undef basename

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <linux/unistd.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <sqlfs.h>

#define SBR_FILES_MAX 10400

static sqlfs_t *sqlfs = NULL;
static char sfile_map[SBR_FILES_MAX][PATH_MAX] = {0};
static ssize_t sfile_map_seek[SBR_FILES_MAX] = {0};
static int sfile_map_size = -1;

// We skip some fair amount of numbers to avoid collisions.
static const int fd_offset = 400;

static pthread_mutex_t lock;

static int target_log_sock = -1;

static bool starts_with(const char *str, const char *pre) {
  if (!str || !pre)
    return false;
  size_t lenstr = strlen(str);
  size_t lenprefix = strlen(pre);
  if (lenprefix > lenstr)
    return false;
  return strncmp(pre, str, lenprefix) == 0;
}

int iopenat(int dirfd, const char *pathname, int flags, mode_t mode) {
  // TODO: What if we read the file multiple times?
  // TODO: User writes once, closes the file, then readonly.
  if (!(flags & O_WRONLY) && !(flags & O_RDWR)) {
    return real_syscall(SYS_openat, dirfd, (long)pathname, flags, mode, 0, 0);
  } else if (starts_with(pathname, "/dev/")) {
    return real_syscall(SYS_openat, dirfd, (long)pathname, flags, mode, 0, 0);
  }

  char resolved_pathname[PATH_MAX];
  char *rv = realpath(pathname, resolved_pathname);
  if (rv == NULL && errno != ENOENT) {
    perror("realpath() failed");
    exit(EXIT_FAILURE);
  }

  sfile_map_size++;
  assert(sfile_map_size < SBR_FILES_MAX);
  char *sfilename = sfile_map[sfile_map_size];

  if (sqlfs_proc_access(sqlfs, resolved_pathname, F_OK) == -ENOENT) {
    // If the file doesn't exists create it.
    char *pathname_dup = strdup(resolved_pathname);
    assert(pathname_dup != NULL);

    int rc = sqlfs_proc_mkdir(sqlfs, dirname(pathname_dup), 0777);
    assert(rc == 0 || rc == -EEXIST);
    free(pathname_dup);

    // If file exists in the real FS we need to copy it's content.
    if (access(resolved_pathname, F_OK) != -1) {
      // TODO:
      // https://eklausmeier.wordpress.com/2016/02/03/performance-comparison-mmap-versus-read-versus-fread/
      FILE *real_file = fopen(resolved_pathname, "rb");
      fseek(real_file, 0, SEEK_END);
      long fsize = ftell(real_file);
      rewind(real_file);
      char *buf = (char *)malloc(sizeof(char) * (fsize + 1));
      size_t result = fread(buf, sizeof(char), fsize, real_file);
      assert(result == fsize);
      buf[fsize] = '\0';
      fclose(real_file);

      int rc = sqlfs_proc_write(sqlfs, resolved_pathname, buf, fsize, 0, NULL);
      assert(rc == fsize);

      free(buf);
    }
  }

  assert(sqlfs_proc_access(sqlfs, resolved_pathname, F_OK) != -1);
  // If file exists open the existing file.
  struct fuse_file_info fi = {0};
  fi.flags = flags;
  int rc = sqlfs_proc_open(sqlfs, resolved_pathname, &fi);
  assert(!rc);

  strncpy(sfilename, resolved_pathname, PATH_MAX);
  sfile_map_seek[sfile_map_size + fd_offset] = 0;

  return sfile_map_size + fd_offset;
}

int ilseek(int fd, off_t offset, int whence) {
  if (fd >= fd_offset) {
    key_attr attr = {0};

    switch (whence) {
    case SEEK_SET:
      sfile_map_seek[fd - fd_offset] = offset;
      break;
    case SEEK_CUR:
      sfile_map_seek[fd - fd_offset] = sfile_map_seek[fd - fd_offset] + offset;
      break;
    case SEEK_END:
      sqlfs_get_attr(sqlfs, sfile_map[fd - fd_offset], &attr);
      sfile_map_seek[fd - fd_offset] = attr.size + offset;
      break;
    default:
      assert(false);
      break;
    }
    return sfile_map_seek[fd - fd_offset];
  }
  return real_syscall(SYS_lseek, fd, offset, whence, 0, 0, 0);
}

int ifstat(int fd, struct stat *statbuf) {
  if (fd >= fd_offset) {
    // HINT: Don't use sqlfs_proc_statfs it doesn't support ":memory:".
    key_attr attr = {0};
    sqlfs_get_attr(sqlfs, sfile_map[fd - fd_offset], &attr);

    statbuf->st_dev = makedev(0, 49);
    statbuf->st_nlink = 1;
    statbuf->st_blksize = 4096;
    statbuf->st_blocks = 8;

    statbuf->st_ino = attr.inode;
    statbuf->st_mode = attr.mode;

    statbuf->st_uid = attr.uid;
    statbuf->st_gid = attr.gid;

    statbuf->st_size = attr.size;

    statbuf->st_atime = attr.atime;
    statbuf->st_mtime = attr.mtime;
    statbuf->st_ctime = attr.ctime;
    return 0;
  }
  return real_syscall(SYS_fstat, fd, (long)statbuf, 0, 0, 0, 0);
}

// TODO: Memory only increases. The benchmark-fs is using brk() all the time.
int iunlink(const char *pathname) {
  char resolved_pathname[PATH_MAX];
  char *rv = realpath(pathname, resolved_pathname);
  if (rv == NULL && errno != ENOENT) {
    perror("realpath() failed");
    exit(EXIT_FAILURE);
  }

  int rc = sqlfs_proc_unlink(sqlfs, resolved_pathname);
  assert(rc == 0);

  return rc;
}

// TODO: Support AT_REMOVEDIR
int iunlinkat(int dirfd, const char *pathname, int flags) {
  assert(false);
  assert((flags & AT_REMOVEDIR) == 0);
  return iunlink(pathname);
}

#define AFL_DATA_SOCKET 200
#define AFL_CTL_SOCKET (AFL_DATA_SOCKET + 1)

typedef enum { Accept, Send, Recv, ExitGroup } SbrState;

static int aflsocket = AFL_DATA_SOCKET;
// static int childlistensocket = -1;
static int childacceptsocket = -1;
static int dbgsbrsocket = -1;

#define CHILD_ACCEPT_PORT 2321

// TODO: Should we accept more than 1 socket? How will we handle it?
int isocket(int domain, int type, int protocol) {
  // TODO: SOCK_NONBLOCK, SOCK_CLOEXEC
  assert(domain == AF_INET || domain == AF_INET6);
  assert(type == SOCK_STREAM || type == SOCK_SEQPACKET);
  assert((type & SOCK_NONBLOCK) == 0);

  return aflsocket;
}

// TODO: We should ideally keep track of optval between setsockopt and get.
// int igetsockopt(int sockfd, int level, int optname, void *optval,
//                 socklen_t *optlen) {
//   return 0;
// }

int isetsockopt(int sockfd, int level, int optname, const void *optval,
                socklen_t optlen) {
  return 0;
}

int ibind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  return 0;
}

int ilisten(int sockfd, int backlog) { return 0; }

int iaccept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  // TODO: we only support 1 accept.
  if (childacceptsocket >= 0) {
    errno = ECONNRESET;
    return -1;
  }

  // Initialize a sockaddr_in for the peer
  struct sockaddr_in peer_addr = {0};

  // Set the contents in the peer's sock_addr.
  // Make sure the contents will simulate a real client that connects with the
  // intercepted server, as the server may depend on the contents to make
  // further decisions. The followings set-up should be fine with Nginx.
  peer_addr.sin_family = AF_INET;
  peer_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  peer_addr.sin_port = htons(CHILD_ACCEPT_PORT);

  // copy the initialized peer_addr back to the original sockaddr. Note the
  // space for the original sockaddr, namely addr, has already been allocated
  if (addr && addrlen) {
    memcpy(addr, &peer_addr, sizeof(peer_addr));
    *addrlen = sizeof(peer_addr);
  }

  childacceptsocket = dup(aflsocket);

  // Inform afl that we are ready.
  SbrState st = Accept;
  int rc = send(AFL_CTL_SOCKET, &st, sizeof(SbrState), MSG_NOSIGNAL);
  assert(rc == sizeof(SbrState));

  return childacceptsocket;
}

int iaccept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
  return iaccept(sockfd, addr, addrlen);
}

int igetsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  struct sockaddr_in target;
  socklen_t copylen = sizeof(target);

  if (!addr || !addrlen)
    return -1;

  if (*addrlen < sizeof(target))
    copylen = *addrlen;

  target.sin_family = AF_INET;
  target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  target.sin_port = htons(CHILD_ACCEPT_PORT);

  memcpy(addr, &target, copylen);
  *addrlen = copylen;

  return 0;
}

int igetpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
  struct sockaddr_in target;
  socklen_t copylen = sizeof(target);

  if (!addr || !addrlen)
    return -1;

  if (*addrlen < sizeof(target))
    copylen = *addrlen;

  target.sin_family = AF_INET;
  target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  target.sin_port = htons(CHILD_ACCEPT_PORT + 100);

  memcpy(addr, &target, copylen);
  *addrlen = copylen;

  return 0;
}

int iconnect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  char logpath[] = "/dev/log";
  if ((addr->sa_family == AF_UNIX) &&
      (strncmp(((struct sockaddr_un *)addr)->sun_path, logpath,
               sizeof(logpath)) == 0)) {
    target_log_sock = sockfd;
    return 0;
  }
  // dprintf(2, "Trying to connect. We will refuse\n");
  errno = ECONNREFUSED;
  return -1;
}

ssize_t isendto(int sockfd, const void *buf, size_t len, int flags,
                const struct sockaddr *dest_addr, socklen_t addrlen) {
  assert(sockfd == childacceptsocket);

  pthread_mutex_lock(&lock);

  SbrState st = Send;
  ssize_t rc = send(AFL_CTL_SOCKET, &st, sizeof(SbrState), MSG_NOSIGNAL);
  assert(rc == sizeof(SbrState));

  rc = sendto(sockfd, buf, len, flags, dest_addr, addrlen);

  pthread_mutex_unlock(&lock);

  return rc;
}

ssize_t irecvfrom(int sockfd, void *buf, size_t len, int flags,
                  struct sockaddr *src_addr, socklen_t *addrlen) {
  assert(sockfd == childacceptsocket);

  pthread_mutex_lock(&lock);

  SbrState st = Recv;
  ssize_t rc = send(AFL_CTL_SOCKET, &st, sizeof(SbrState), MSG_NOSIGNAL);
  assert(rc == sizeof(SbrState));

  rc = recvfrom(sockfd, buf, len, flags, src_addr, addrlen);

  pthread_mutex_unlock(&lock);

  return rc;
}

int ishutdown(int sockfd, int how) {
  if (sockfd == AFL_DATA_SOCKET || sockfd == AFL_CTL_SOCKET) {
    return 0;
  }
  return syscall(SYS_shutdown, sockfd, how);
}

// Common to FS and Net

ssize_t iread(int fd, void *buf, size_t count) {
  if (fd >= fd_offset) {
    int rc = sqlfs_proc_read(sqlfs, sfile_map[fd - fd_offset], buf, count,
                             sfile_map_seek[fd - fd_offset], NULL);
    if (rc > 0) {
      sfile_map_seek[fd - fd_offset] += rc;
    }
    return rc;
  }
  return syscall(SYS_read, fd, buf, count);
}

ssize_t iwrite(int fd, const void *buf, size_t count) {
  if (fd >= fd_offset) {
    int rc = sqlfs_proc_write(sqlfs, sfile_map[fd - fd_offset], buf, count,
                              sfile_map_seek[fd - fd_offset], NULL);
    if (rc > 0) {
      sfile_map_seek[fd - fd_offset] += rc;
    }
    return rc;
  } else if (fd == STDOUT_FILENO || fd == STDERR_FILENO ||
             fd == target_log_sock) {
    return count;
  }
  return syscall(SYS_write, fd, buf, count);
}

// Close is used in both networking and files.
int iclose(int fd) {
  if (fd >= fd_offset) {
    // TODO: We need a mechanism to recycle FDs.
    sfile_map_seek[fd - fd_offset] = 0;
    // TODO: Implement a file state and set it to closed.
    return 0;
  }
  if (fd == AFL_DATA_SOCKET || fd == AFL_CTL_SOCKET) {
    return 0;
  }
  return syscall(SYS_close, fd);
}

// Misc

int inanosleep(const struct timespec *req, struct timespec *rem) {
  nanosleep((const struct timespec[]){{0, 1L}}, NULL);
  return 0;
}

static bool i_m_forkserver = true;

long iexit_group(int status) {
  if (i_m_forkserver == false) {
    pthread_mutex_lock(&lock);

    SbrState st = ExitGroup;
    int rc = send(AFL_CTL_SOCKET, &st, sizeof(SbrState), MSG_NOSIGNAL);
    assert(rc == sizeof(SbrState));
  }

  long rc = syscall(SYS_exit_group, status);

  return rc;
}

long handle_syscall(long sc_no, long arg1, long arg2, long arg3, long arg4,
                    long arg5, long arg6, void *wrapper_sp) {
  if (sc_no == SYS_clone) {
    if (arg2 != 0) { // clone for threads
      void *ret_addr = get_syscall_return_address(wrapper_sp);
      return clone_syscall(arg1, (void *)arg2, (void *)arg3, (void *)arg4, arg5,
                           ret_addr);
    } else { // fork -> if (arg2 == 0)
      long rc = real_syscall(sc_no, arg1, arg2, arg3, arg4, arg5, arg6);
      if (rc == 0) { // We are the afl-forkserver's child
        i_m_forkserver = false;
      }
      return rc;
    }
  }

  // TODO: Switch to a switch
  if (sc_no == SYS_openat) {
    return iopenat(arg1, (const char *)arg2, arg3, arg4);
  } else if (sc_no == SYS_lseek) {
    return ilseek(arg1, arg2, arg3);
  } else if (sc_no == SYS_fstat) {
    return ifstat(arg1, (struct stat *)arg2);
  } else if (sc_no == SYS_unlink) {
    return iunlink((const char *)arg1);
  } else if (sc_no == SYS_unlinkat) {
    return iunlinkat(arg1, (const char *)arg2, arg3);
  } else if (sc_no == SYS_statfs) {
    assert(false);
  } else if (sc_no == SYS_fstatfs) {
    assert(false);
  } else if (sc_no == SYS_truncate) {
    assert(false);
  } else if (sc_no == SYS_fsync) {
    assert(false);
  } else if (sc_no == SYS_rename) {
    assert(false);
  } else if (sc_no == SYS_renameat) {
    assert(false);
  } else if (sc_no == SYS_renameat2) {
    assert(false);

    // Networking + FS

  } else if (sc_no == SYS_read) {
    return iread(arg1, (void *)arg2, arg3);
  } else if (sc_no == SYS_write) {
    return iwrite(arg1, (const void *)arg2, arg3);
  } else if (sc_no == SYS_close) {
    return iclose(arg1);

    // Networking

  } else if (sc_no == SYS_socket) {
    return isocket(arg1, arg2, arg3);
  } else if (sc_no == SYS_getsockopt) {
    assert(false);
    // return igetsockopt(arg1, arg2, arg3, (void *)arg4, (socklen_t *)arg5);
  } else if (sc_no == SYS_setsockopt) {
    return isetsockopt(arg1, arg2, arg3, (const void *)arg4, arg5);
  } else if (sc_no == SYS_bind) {
    return ibind(arg1, (const struct sockaddr *)arg2, arg3);
  } else if (sc_no == SYS_listen) {
    return ilisten(arg1, arg2);
  } else if (sc_no == SYS_accept) {
    return iaccept(arg1, (struct sockaddr *)arg2, (socklen_t *)arg3);
  } else if (sc_no == SYS_accept4) {
    return iaccept4(arg1, (struct sockaddr *)arg2, (socklen_t *)arg3, arg4);
  } else if (sc_no == SYS_getsockname) {
    return igetsockname(arg1, (struct sockaddr *)arg2, (socklen_t *)arg3);
  } else if (sc_no == SYS_getpeername) {
    return igetpeername(arg1, (struct sockaddr *)arg2, (socklen_t *)arg3);
  } else if (sc_no == SYS_select) {
    assert(false); // GNU pth requires select
  } else if (sc_no == SYS_fcntl) {
    assert(false);
  } else if (sc_no == SYS_msgsnd) {
    assert(false);
  } else if (sc_no == SYS_msgrcv) {
    assert(false);
  } else if (sc_no == SYS_connect) {
    return iconnect(arg1, (struct sockaddr *)arg2, arg3);
  } else if (sc_no == SYS_sendto) {
    return isendto(arg1, (const void *)arg2, arg3, arg4,
                   (struct sockaddr *)arg5, arg6);
  } else if (sc_no == SYS_recvfrom) {
    return irecvfrom(arg1, (void *)arg2, arg3, arg4, (struct sockaddr *)arg5,
                     (socklen_t *)arg6);

    // Misc

  } else if (sc_no == SYS_nanosleep) {
    return inanosleep((const struct timespec *)arg1, (struct timespec *)arg2);
    // } else if (sc_no == SYS_exit) {
    //   // TODO: Do we need this?
    //   return real_syscall(sc_no, arg1, arg2, arg3, arg4, arg5, arg6);
  } else if (sc_no == SYS_exit_group) {
    return iexit_group(arg1);
  }

  // TODO: No forking and threading? Think of FTP server and LIST op.

  return real_syscall(sc_no, arg1, arg2, arg3, arg4, arg5, arg6);
}

void_void_fn actual_clock_gettime = NULL;
void_void_fn actual_getcpu = NULL;
void_void_fn actual_gettimeofday = NULL;
void_void_fn actual_time = NULL;

typedef int clock_gettime_fn(clockid_t, struct timespec *);
int handle_vdso_clock_gettime(clockid_t arg1, struct timespec *arg2) {
  return ((clock_gettime_fn *)actual_clock_gettime)(arg1, arg2);
}

// arg3 has type: struct getcpu_cache *
typedef int getcpu_fn(unsigned *, unsigned *, void *);
int handle_vdso_getcpu(unsigned *arg1, unsigned *arg2, void *arg3) {
  return ((getcpu_fn *)actual_getcpu)(arg1, arg2, arg3);
}

typedef int gettimeofday_fn(struct timeval *, struct timezone *);
int handle_vdso_gettimeofday(struct timeval *arg1, struct timezone *arg2) {
  return ((gettimeofday_fn *)actual_gettimeofday)(arg1, arg2);
}

#ifdef __x86_64__
typedef int time_fn(time_t *);
int handle_vdso_time(time_t *arg1) { return ((time_fn *)actual_time)(arg1); }
#endif // __x86_64__

void_void_fn handle_vdso(long sc_no, void_void_fn actual_fn) {
  (void)actual_fn;
  switch (sc_no) {
  case SYS_clock_gettime:
    actual_clock_gettime = actual_fn;
    return (void_void_fn)handle_vdso_clock_gettime;
  case SYS_getcpu:
    actual_getcpu = actual_fn;
    return (void_void_fn)handle_vdso_getcpu;
  case SYS_gettimeofday:
    actual_gettimeofday = actual_fn;
    return (void_void_fn)handle_vdso_gettimeofday;
#ifdef __x86_64__
  case SYS_time:
    actual_time = actual_fn;
    return (void_void_fn)handle_vdso_time;
#endif // __x86_64__
  default:
    return (void_void_fn)NULL;
  }
}

#ifdef __NX_INTERCEPT_RDTSC
long handle_rdtsc() {
  long high, low;

  asm volatile("rdtsc;" : "=a"(low), "=d"(high) : :);

  long ret = high;
  ret <<= 32;
  ret |= low;

  return ret;
}
#endif // __NX_INTERCEPT_RDTSC

void sbr_init(int *argc, char **argv[], sbr_icept_reg_fn fn_icept_reg,
              sbr_icept_vdso_callback_fn *vdso_callback,
              sbr_sc_handler_fn *syscall_handler,
#ifdef __NX_INTERCEPT_RDTSC
              sbr_rdtsc_handler_fn *rdtsc_handler,
#endif
              sbr_post_load_fn *post_load) {
  (void)fn_icept_reg; // unused
  (void)post_load;    // unused

  *syscall_handler = handle_syscall;
  *vdso_callback = handle_vdso;

#ifdef __NX_INTERCEPT_RDTSC
  *rdtsc_handler = handle_rdtsc;
#endif

  (*argc)--;
  (*argv)++;

  int rc = pthread_mutex_init(&lock, NULL);
  assert(rc == 0);

  // Libsqlfs
  char *memdb = ":memory:";
  rc = sqlfs_open(memdb, &sqlfs);
  assert(rc);
  assert(sqlfs != 0);

  // TODO: assert(sqlfs_close(sqlfs));

  struct stat sockstatus;
  fstat(AFL_CTL_SOCKET, &sockstatus);
  // If we are under AFL, let's handshake.
  if (S_ISSOCK(sockstatus.st_mode) == 1) {

    char msg[] = "hello from sbr";
    rc = send(AFL_CTL_SOCKET, msg, sizeof(msg), MSG_NOSIGNAL);
    assert(rc == sizeof(msg));

    char rsp[1024] = {0};
    rc = recv(AFL_CTL_SOCKET, rsp, sizeof(rsp), 0);

    char expected[] = "hello from afl";
    assert(strncmp(rsp, expected, sizeof(expected)) == 0 &&
           rc == sizeof(expected));
  } else {
    dprintf(2, "WARN: SaBRe-afl is running headless.\n");
    // TODO: This is broken!
    // Let's local debug.
    int sbr_pair[2];

    if (socketpair(AF_LOCAL, SOCK_STREAM, 0, sbr_pair) != 0) {
      perror("socketpair() failed");
      exit(EXIT_FAILURE);
    }
    if (dup2(sbr_pair[1], AFL_CTL_SOCKET) != AFL_CTL_SOCKET) {
      perror("dup2() failed");
      exit(EXIT_FAILURE);
    }
    close(sbr_pair[1]);

    dbgsbrsocket = sbr_pair[0];

    fstat(AFL_CTL_SOCKET, &sockstatus);
    assert(S_ISSOCK(sockstatus.st_mode) == 1);
  }
}
