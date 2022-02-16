/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
   This plugin simply intercepts all system calls and vDSO calls and
   reissues them.
*/

#include "real_syscall.h"
#include "sbr_api_defs.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
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

static char *fstring = NULL;
static int ifd = -1;
static int ipos = 0;
static int filesize = 0;

int iopenat(int dirfd, const char *pathname, int flags, mode_t mode) {
  if (strcmp(pathname, "mydb.txt") != 0) {
    return real_syscall(SYS_openat, dirfd, (long)pathname, flags, mode, 0, 0);
  }

  FILE *f = fopen(pathname, "rb");
  fseek(f, 0, SEEK_END);
  long fsize = ftell(f);
  rewind(f);
  fstring = (char *)malloc(sizeof(char) * (fsize + 1));
  size_t result = fread(fstring, sizeof(char), fsize, f);
  assert(result == fsize);
  fstring[fsize] = '\0';
  fclose(f);

  // TODO: get it from fstat
  filesize = strlen(fstring);

  // This is a hack to open the fd and ignore non-read/write syscalls
  ifd = real_syscall(SYS_openat, dirfd, (long)pathname, flags, mode, 0, 0);

  return ifd;
}

int ilseek(int fd, off_t offset, int whence) {
  if (ifd == fd) {
    if (whence == SEEK_SET) {
      ipos = offset;
      return 0;
    } else if (whence == SEEK_CUR) {
      ipos += offset;
      return 0;
    } else if (whence == SEEK_END) {
      fputs("ilseek error: 1\n", stderr);
      exit(1);
    } else {
      fputs("ilseek error: 2\n", stderr);
      exit(1);
    }
  }

  return real_syscall(SYS_lseek, fd, offset, whence, 0, 0, 0);
}

ssize_t iread(int fd, void *buf, size_t count) {
  if (ifd == fd) {
    if (count > filesize - ipos) {
      count = filesize - ipos;
    }

    memcpy(buf, fstring + ipos, count);
    ipos += count;

    // TODO: what if count > than what memory has
    // TODO: -1 for errors
    // TODO: count*sizeof(char)?
    return count;
  }

  return real_syscall(SYS_read, fd, (long)buf, count, 0, 0, 0);
}

ssize_t iwrite(int fd, const void *buf, size_t count) {
  if (ifd == fd) {
    memcpy(fstring + ipos, buf, count);
    ipos += count;

    // TODO: do this cleverly
    // if (count > ipos) {
    filesize = strlen(fstring);

    return count;
  }

  return real_syscall(SYS_write, fd, (long)buf, count, 0, 0, 0);
}

int ifstat(int fd, struct stat *statbuf) {
  if (ifd == fd) {
    statbuf->st_dev = makedev(0, 49);
    statbuf->st_ino = 3391;
    statbuf->st_mode = S_IFREG | 0644;
    statbuf->st_nlink = 1;
    statbuf->st_uid = 1000;
    statbuf->st_gid = 1000;
    statbuf->st_blksize = 4096;
    statbuf->st_blocks = 8;
    statbuf->st_size = filesize;
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
}
