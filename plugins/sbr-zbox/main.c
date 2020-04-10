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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <assert.h>
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

  zfile_map_size++;
  assert(zfile_map_size < 400);
  zbox_file *file = &zfile_map[zfile_map_size];

  if (zbox_repo_path_exists(repo, pathname)) {
    // open the existing file
    int ret = zbox_repo_open_file(file, repo, pathname);
    assert(!ret);
  } else {
    // create file
    char *pathname_dup = strdup(pathname);
    assert(pathname_dup != NULL);

    int ret = zbox_repo_create_dir_all(repo, dirname(pathname_dup));
    assert(!ret);
    free(pathname_dup);

    ret = zbox_repo_create_file(file, repo, pathname);
    assert(!ret);
  }

  // If file exists in the real FS we need to copy it's content.
  if (access(pathname, F_OK) != -1) {
    // TODO:
    // https://eklausmeier.wordpress.com/2016/02/03/performance-comparison-mmap-versus-read-versus-fread/
    FILE *real_file = fopen(pathname, "rb");
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

    free(buf);
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
    return zbox_file_write(zfile_map[fd - fd_offset], buf, count);
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

long handle_syscall(long sc_no, long arg1, long arg2, long arg3, long arg4,
                    long arg5, long arg6, void *wrapper_sp) {
  if (sc_no == SYS_clone && arg2 != 0) { // clone
    void *ret_addr = get_syscall_return_address(wrapper_sp);
    return clone_syscall(arg1, (void *)arg2, (void *)arg3, (void *)arg4, arg5,
                         ret_addr);
  }

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
  }

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
}
