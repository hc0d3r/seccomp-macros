#include <seccomp-macros.h>
#include <linux/audit.h>
#include <linux/prctl.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <err.h>
#include <sys/reg.h>

#include "utils.h"

void do_execve(void){
    asm volatile("syscall" :: "a"(59));
    asm volatile("int $0x80" :: "a"(11));
}

void child(void){
    /* intercept sys_execve in x86 and x86_64 */

    struct sock_filter filter[]={
        bpf_ld_abs(off_audit_arch),
        bpf_jeq(AUDIT_ARCH_X86_64, 0, 3),
        bpf_ld_abs(off_syscall_nr),
        bpf_jneq(59, 6, 0),
        bpf_ret_imm(SECCOMP_RET_TRACE),
        bpf_jeq(AUDIT_ARCH_I386, 1, 0),
        bpf_ret_imm(SECCOMP_RET_KILL),
        bpf_ld_abs(off_syscall_nr),
        bpf_jneq(11, 1, 0),
        bpf_ret_imm(SECCOMP_RET_TRACE),
        bpf_ret_imm(SECCOMP_RET_ALLOW)
    };

    struct sock_fprog fprog = {
        .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    enable_filter(&fprog);

    ptrace(PTRACE_TRACEME);
    kill(getpid(), SIGSTOP);
    do_execve();
}

int main(void){
    pid_t pid = fork();

    if(pid == 0){
        child();
        exit(0);
    }

    ptrace_loop(pid);

    return 0;
}
