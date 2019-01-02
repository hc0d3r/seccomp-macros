#include "utils.h"
#include <stdio.h>
#include <err.h>

void enable_filter(struct sock_fprog *fprog){

    if(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
        err(1, "prctl set_no_new_privs");

    if(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, fprog) == -1)
        err(1, "prctl set_seccomp");

}


void ptrace_loop(pid_t pid){
    int status, event;

    waitpid(pid, NULL, 0);
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESECCOMP);

    while(1){
        ptrace(PTRACE_CONT, pid, 0, 0);

        if(waitpid(pid, &status, 0) == -1)
            break;

        if(WIFSTOPPED(status)){
            event = status >> 16;

            if(event == PTRACE_EVENT_SECCOMP){
                printf("SECCOMP event --> syscall_nr => %ld\n",
                    ptrace(PTRACE_PEEKUSER, pid, 8*ORIG_RAX, 0));

                /* skip system call */
                ptrace(PTRACE_POKEUSER, pid, 8*ORIG_RAX, -1);
            }
        }
    }
}
