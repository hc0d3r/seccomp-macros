#include <seccomp-macros.h>
#include <linux/audit.h>
#include <linux/prctl.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <err.h>

#include "utils.h"

void run(void){
    register long i __asm__("r10") = 0;

    for(i=0; i<256; i++){
        asm volatile("syscall":: "a"(i), "d"(1234) : "rcx", "r11", "memory");
    }

}

void child(void){
    /*
        intercept syscall if the third arg is equal to 1234,
        in x86_64 to avoid errors I recommend check all the 8 bytes,
        remember that seccomp only store 4 bytes at a time
    */

    struct sock_filter filter[]={
        bpf_ld_abs(off_syscall_arg(2)),
        bpf_jeq(1234, 0, 3),
        bpf_ld_abs(off_syscall_arg(2)+4), /* check all the 8 bytes */
        bpf_jeq(0, 0, 1),
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
    run();
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
