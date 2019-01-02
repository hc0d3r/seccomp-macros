#ifndef __UTILS_H__
#define __UTILS_H__

#ifndef __x86_64__
    #error "this code only work correctly in x86_64"
#endif

#include <linux/filter.h>
#include <linux/seccomp.h>

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/prctl.h>

void enable_filter(struct sock_fprog *fprog);
void ptrace_loop(pid_t pid);

#endif
