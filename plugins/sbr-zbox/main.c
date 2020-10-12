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
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <zbox.h>

static zbox_repo repo;
static zbox_file zfile_map[400] = {NULL};
static int zfile_map_size = -1;
static int fd_offset = 400;

// We can have 2 strategies here:
// 1) The user can declare a list of files. Whitelist vs Blacklist?
// 2) We can be lazy, load something in memory only if we try to write once.
// 2a) What if we read the file multiple times? We can speed it up if we go with
// (1)
int iopenat(int dirfd, const char *pathname, int flags, mode_t mode) {
  // TODO: check flags and mode!

  // Blacklist
  char ftp_logs[] = "fftplog";
  char ftp_dir[] = "ftpshare";

  if (strstr(pathname, ftp_logs) == NULL && strstr(pathname, ftp_dir) == NULL) {
    return real_syscall(SYS_openat, dirfd, (long)pathname, flags, mode, 0, 0);
  }

  char resolved_pathname[PATH_MAX];
  char *rv = realpath(pathname, resolved_pathname);
  if (rv == NULL && errno != ENOENT) {
    perror("realpath() failed");
    exit(EXIT_FAILURE);
  }

  zfile_map_size++;
  assert(zfile_map_size < 400);
  zbox_file *file = &zfile_map[zfile_map_size];

  if (zbox_repo_path_exists(repo, resolved_pathname)) {
    // Open the existing file.
    int ret = zbox_repo_open_file(file, repo, resolved_pathname);
    assert(!ret);
  } else {
    // Create the file.
    char *pathname_dup = strdup(resolved_pathname);
    assert(pathname_dup != NULL);

    int ret = zbox_repo_create_dir_all(repo, dirname(pathname_dup));
    // assert(!ret);
    free(pathname_dup);

    ret = zbox_repo_create_file(file, repo, resolved_pathname);
    assert(!ret);

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

      int ret = zbox_file_write(*file, (const unsigned char *)buf, fsize);
      assert(ret == fsize);
      ret = zbox_file_finish(*file);
      assert(!ret);

      free(buf);
    }
  }

  return zfile_map_size + fd_offset;
}

int ilseek(int fd, off_t offset, int whence) {
  if (fd >= 400) {
    return zbox_file_seek(zfile_map[fd - fd_offset], offset, whence);
  }
  return real_syscall(SYS_lseek, fd, offset, whence, 0, 0, 0);
}

ssize_t iread(int fd, void *buf, size_t count) {
  if (fd >= 400) {
    return zbox_file_read(buf, count, zfile_map[fd - fd_offset]);
  }
  return real_syscall(SYS_read, fd, (long)buf, count, 0, 0, 0);
}

ssize_t iwrite(int fd, const void *buf, size_t count) {
  if (fd >= 400) {
    ssize_t rc = zbox_file_write(zfile_map[fd - fd_offset], buf, count);
    int ret = zbox_file_finish(zfile_map[fd - fd_offset]);
    assert(!ret);
    return rc;
  }
  return real_syscall(SYS_write, fd, (long)buf, count, 0, 0, 0);
}

int iclose(int fd) {
  if (fd >= 400) {
    // zbox_file_finish(file);
    zbox_close_file(zfile_map[fd - fd_offset]);
    zfile_map_size--;
    return 0;
  }
  return real_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
}

int ifstat(int fd, struct stat *statbuf) {
  if (fd >= 400) {
    struct zbox_metadata meta;
    int ret = zbox_file_metadata(&meta, zfile_map[fd - fd_offset]);
    assert(!ret);

    statbuf->st_dev = makedev(0, 49);
    statbuf->st_ino = 3391;
    statbuf->st_mode = S_IFREG | 0644;
    statbuf->st_nlink = 1;
    statbuf->st_uid = 1000;
    statbuf->st_gid = 1000;
    statbuf->st_blksize = 4096;
    statbuf->st_blocks = 8;
    statbuf->st_size = meta.content_len;
    // TODO: meta.created_at, meta.modified_at
    statbuf->st_atime = 1557410314; /* 2019-05-09T13:58:34+0000 */
    // statbuf->st_atime_nsec = 0;
    statbuf->st_mtime = 1557399894; /* 2019-05-09T11:04:54+0000 */
    // statbuf->st_mtime_nsec = 0;
    statbuf->st_ctime = 1557399894; /* 2019-05-09T11:04:54+0000 */
    // statbuf->st_ctime_nsec = 0;
    return 0;
  }
  return real_syscall(SYS_fstat, fd, (long)statbuf, 0, 0, 0, 0);
}

int iunlink(const char *pathname) {
  char resolved_pathname[PATH_MAX];
  char *rv = realpath(pathname, resolved_pathname);
  if (rv == NULL && errno != ENOENT) {
    perror("realpath() failed");
    exit(EXIT_FAILURE);
  }

  int rc = zbox_repo_remove_file(resolved_pathname, repo);
  assert(rc == 0);

  return rc;
}

// TODO: Support AT_REMOVEDIR
int iunlinkat(int dirfd, const char *pathname, int flags) {
  assert((flags & AT_REMOVEDIR) == 0);

  char resolved_pathname[PATH_MAX];
  char *rv = realpath(pathname, resolved_pathname);
  if (rv == NULL && errno != ENOENT) {
    perror("realpath() failed");
    exit(EXIT_FAILURE);
  }

  int rc = zbox_repo_remove_file(resolved_pathname, repo);
  assert(rc == 0);

  return rc;
}

static int sbrsocket = -1;
static int childlistensocket = -1;
static int childacceptsocket = -1;

#define CHILD_ACCEPT_PORT 2321

// TODO: Should we accept more than 1 socket? How will we handle it?
int isocket(int domain, int type, int protocol) {
  // TODO: SOCK_NONBLOCK, SOCK_CLOEXEC
  assert(domain == AF_INET || domain == AF_INET6);
  assert(type == SOCK_STREAM || type == SOCK_SEQPACKET);
  assert((type & SOCK_NONBLOCK) == 0);

  return childlistensocket;
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

  childacceptsocket = dup(childlistensocket);
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
  target.sin_addr.s_addr = htonl(INADDR_ANY);
  target.sin_port = htons(CHILD_ACCEPT_PORT);

  memcpy(addr, &target, copylen);
  *addrlen = copylen;

  return 0;
}

ssize_t isendto(int sockfd, const void *buf, size_t len, int flags,
                const struct sockaddr *dest_addr, socklen_t addrlen) {
  assert(sockfd == childacceptsocket);

  ssize_t rc = sendto(sockfd, buf, len, flags, dest_addr, addrlen);

  // char rbuf[1024] = {0};
  // recv(sbrsocket, rbuf, 1024, 0); // sys: recvfrom
  // printf("sbr: %s", rbuf);

  return rc;
}

ssize_t irecvfrom(int sockfd, void *buf, size_t len, int flags,
                  struct sockaddr *src_addr, socklen_t *addrlen) {
  assert(sockfd == childacceptsocket);

  // char msg[] = "lalalalalo\r\n";
  // send(sbrsocket, msg, sizeof(msg), 0);

  return recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}

long handle_syscall(long sc_no, long arg1, long arg2, long arg3, long arg4,
                    long arg5, long arg6, void *wrapper_sp) {
  if (sc_no == SYS_clone && arg2 != 0) { // clone
    void *ret_addr = get_syscall_return_address(wrapper_sp);
    return clone_syscall(arg1, (void *)arg2, (void *)arg3, (void *)arg4, arg5,
                         ret_addr);
  }

  // TODO: Switch to a switch
  if (sc_no == SYS_openat) {
    return iopenat(arg1, (const char *)arg2, arg3, arg4);
  } else if (sc_no == SYS_lseek) {
    return ilseek(arg1, arg2, arg3);
  } else if (sc_no == SYS_read) {
    return iread(arg1, (void *)arg2, arg3);
  } else if (sc_no == SYS_write) {
    return iwrite(arg1, (const void *)arg2, arg3);
  } else if (sc_no == SYS_close) {
    return iclose(arg1);
  } else if (sc_no == SYS_fstat) {
    return ifstat(arg1, (struct stat *)arg2);
  } else if (sc_no == SYS_unlink) {
    return iunlink((const char *)arg1);
  } else if (sc_no == SYS_unlinkat) {
    return iunlinkat(arg1, (const char *)arg2, arg3);
  }
  // Networking
  else if (sc_no == SYS_socket) {
    return isocket(arg1, arg2, arg3);
    // } else if (sc_no == SYS_getsockopt) {
    //   return igetsockopt(arg1, arg2, arg3, (void *)arg4, (socklen_t *)arg5);
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
    // } else if (sc_no == SYS_getpeername) {
    //   assert(false);
  } else if (sc_no == SYS_select) {
    assert(false);
  } else if (sc_no == SYS_fcntl) {
    assert(false);
  } else if (sc_no == SYS_msgsnd) {
    assert(false);
  } else if (sc_no == SYS_msgrcv) {
    assert(false);
  } else if (sc_no == SYS_sendto) {
    return isendto(arg1, (const void *)arg2, arg3, arg4,
                   (struct sockaddr *)arg5, arg6);
  } else if (sc_no == SYS_recvfrom) {
    return irecvfrom(arg1, (void *)arg2, arg3, arg4, (struct sockaddr *)arg5,
                     (socklen_t *)arg6);
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

  int ret = zbox_init_env();
  assert(!ret);

  // opener
  zbox_opener opener = zbox_create_opener();
  zbox_opener_ops_limit(opener, ZBOX_OPS_INTERACTIVE);
  zbox_opener_mem_limit(opener, ZBOX_MEM_INTERACTIVE);
  zbox_opener_cipher(opener, ZBOX_CIPHER_XCHACHA);
  zbox_opener_create(opener, true);
  zbox_opener_version_limit(opener, 1);

  // open repo
  ret = zbox_open_repo(&repo, opener, "mem://sabre", "password");
  assert(!ret);
  zbox_free_opener(opener);

  // Sockets
  int fd[2];
  int rc = socketpair(AF_LOCAL, SOCK_STREAM, 0, fd);
  if (rc != 0) {
    perror("socketpair() failed");
    exit(EXIT_FAILURE);
  }
  sbrsocket = fd[0];
  childlistensocket = fd[1];
}
