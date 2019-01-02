#include <seccomp-macros.h>
#include <linux/audit.h>
#include <linux/prctl.h>
#include <sys/prctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "utils.h"

void run(void){
    static const int primes[]={
        2, 3, 5, 7, 11, 13, 17, 19,
        23, 29, 31, 37, 41, 43, 47,
        2147483647, 0
    };

    int i;

    for(i=0; primes[i]; i++){
        asm volatile("syscall":: "a"(primes[i]) : "rcx", "r11", "memory");
    }
}


void child(void){
    /* intercept syscall blacklist */

    struct sock_filter filter[]={
        bpf_ld_abs(off_syscall_nr),
        bpf_jneq(2, 0, 15),
        bpf_jneq(3, 0, 14),
        bpf_jneq(5, 0, 13),
        bpf_jneq(7, 0, 12),
        bpf_jneq(11, 0, 11),
        bpf_jneq(13, 0, 10),
        bpf_jneq(17, 0, 9),
        bpf_jneq(19, 0, 8),
        bpf_jneq(23, 0, 7),
        bpf_jneq(29, 0, 6),
        bpf_jneq(31, 0, 5),
        bpf_jneq(37, 0, 4),
        bpf_jneq(41, 0, 3),
        bpf_jneq(43, 0, 2),
        bpf_jneq(47, 0, 1),
        bpf_jneq(2147483647, 1, 0),
        bpf_ret_imm(SECCOMP_RET_TRACE),
        bpf_ret_imm(SECCOMP_RET_ALLOW),
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
