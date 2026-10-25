/* Build a native-architecture, default-deny seccomp filter for the runtime.
 * The allowlist supports a small Python/shell rootfs; it is deliberately not a
 * generic Docker profile. Add syscalls only with a workload + regression test.
 */
#include <seccomp.h>
#include <sched.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <termios.h>

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: seccompgen OUTPUT.bpf\n"); return 2; }
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ERRNO(EPERM));
    if (!ctx) return 1;
    /* libseccomp rejects incompatible syscall architectures before rule lookup. */
    if (seccomp_attr_set(ctx, SCMP_FLTATR_ACT_BADARCH, SCMP_ACT_KILL_PROCESS) < 0) return 1;
    const char *allow[] = {
        "read", "write", "readv", "writev", "pread64", "pwrite64", "close", "close_range",
        "open", "openat", "openat2", "stat", "fstat", "lstat", "newfstatat", "statx",
        "access", "faccessat", "faccessat2", "readlink", "readlinkat", "getdents", "getdents64",
        "lseek", "fcntl", "dup", "dup2", "dup3", "pipe", "pipe2", "poll", "ppoll", "select", "pselect6",
        "mmap", "mprotect", "munmap", "mremap", "madvise", "brk", "msync",
        "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "rt_sigsuspend", "sigaltstack",
        "getpid", "getppid", "gettid", "getuid", "geteuid", "getgid", "getegid", "getgroups",
        "getresuid", "getresgid", "getpgrp", "getpgid", "getsid", "setpgid", "setsid",
        "set_tid_address", "set_robust_list", "rseq", "futex", "futex_waitv", "sched_yield",
        "sched_getaffinity", "sched_getparam", "sched_getscheduler", "sched_get_priority_max", "sched_get_priority_min",
        "arch_prctl", "prlimit64", "getrlimit", "getrusage", "times", "sysinfo", "uname",
        "clock_gettime", "clock_getres", "clock_nanosleep", "gettimeofday", "nanosleep", "restart_syscall",
        "getrandom", "umask", "getcwd", "chdir", "fchdir", "mkdir", "mkdirat", "rmdir",
        "unlink", "unlinkat", "rename", "renameat", "renameat2", "link", "linkat", "symlink", "symlinkat",
        "chmod", "fchmod", "fchmodat", "ftruncate", "truncate", "utimensat", "fsync", "fdatasync",
        "statfs", "fstatfs", "execve", "execveat", "fork", "vfork", "wait4", "waitid",
        "kill", "tkill", "tgkill", "exit", "exit_group", NULL
    };
    for (int i = 0; allow[i]; i++) {
        int nr = seccomp_syscall_resolve_name(allow[i]);
        if (nr == __NR_SCMP_ERROR) continue; /* native architecture lacks this syscall */
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, nr, 0) < 0) { fprintf(stderr, "rule failed: %s\n", allow[i]); return 1; }
    }
    /* Python/glibc use FIOCLEX when opening scripts. Permit only descriptor
     * housekeeping and terminal queries, never arbitrary device ioctls/TIOCSTI. */
    const unsigned long ioctls[] = { TCGETS, FIOCLEX, FIONCLEX, FIONBIO };
    for (unsigned int i = 0; i < sizeof(ioctls) / sizeof(ioctls[0]); i++) {
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1,
            SCMP_A1(SCMP_CMP_EQ, ioctls[i])) < 0) return 1;
    }
    /* Return ENOSYS so libc can fall back to filtered clone rather than clone3. */
    int clone3_nr = seccomp_syscall_resolve_name("clone3");
    if (clone3_nr != __NR_SCMP_ERROR && seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), clone3_nr, 0) < 0) return 1;
    const unsigned long namespace_flags = 0x00020000UL | 0x02000000UL | 0x04000000UL |
        0x08000000UL | 0x10000000UL | 0x20000000UL | 0x40000000UL | 0x00000080UL;
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 1,
        SCMP_A0(SCMP_CMP_MASKED_EQ, namespace_flags, 0)) < 0) return 1;
    int fd = open(argv[1], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (fd < 0) { perror("open output"); return 1; }
    int rc = seccomp_export_bpf(ctx, fd);
    if (fsync(fd) < 0 || close(fd) < 0) rc = -1;
    seccomp_release(ctx);
    return rc < 0 ? 1 : 0;
}
