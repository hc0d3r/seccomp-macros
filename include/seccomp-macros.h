#ifndef __SECCOMP_MACROS_H__
#define __SECCOMP_MACROS_H__

#include <linux/filter.h>
#include <linux/seccomp.h>

/* offset list */

#define off_syscall_nr ((int)(long)&(((struct seccomp_data *)0)->nr))
#define off_audit_arch ((int)(long)&(((struct seccomp_data *)0)->arch))
#define off_instruction_pointer ((int)(long)&(((struct seccomp_data *)0)->instruction_pointer))
#define off_syscall_arg(n) ((int)(long)&(((struct seccomp_data *)0)->args[n]))

/* copy to A or X */

#define bpf_ld_abs(k) BPF_STMT(BPF_LD|BPF_W|BPF_ABS, k) /* A <- P[k:4]   */
#define bpf_ld_ind(k) BPF_STMT(BPF_LD|BPF_W|BPF_IND, k) /* A <- P[X+k:4] */
#define bpf_ld_mem(k) BPF_STMT(BPF_LD|BPF_MEM, k)       /* A <- M[k]     */
#define bpf_ld_imm(k) BPF_STMT(BPF_LD|BPF_IMM, k)       /* A <- k        */
#define bpf_ld_len() BPF_STMT(BPF_LD|BPF_W|BPF_LEN, 0)  /* A <- sizeof(struct seccomp_data) */

#define bpf_ldx_mem(k) BPF_STMT(BPF_LDX|BPF_W|BPF_MEM, k) /* X <- M[k] */
#define bpf_ldx_imm(k) BPF_STMT(BPF_LDX|BPF_W|BPF_IMM, k) /* X <- k    */
#define bpf_ldx_len() BPF_STMT(BPF_LDX|BPF_W|BPF_LEN, 0)  /* X <- sizeof(struct seccomp_data) */

/* copy to M[k] */

#define bpf_st(k) BPF_STMT(BPF_ST, k)   /* M[k] <- A */
#define bpf_stx(k) BPF_STMT(BPF_STX, k) /* M[k] <- X */

/* ALU instructions, mod appears not work ... */

#define bpf_add(k) BPF_STMT(BPF_ALU|BPF_ADD|BPF_K, k) /* A <- A + k  */
#define bpf_sub(k) BPF_STMT(BPF_ALU|BPF_SUB|BPF_K, k) /* A <- A - k  */
#define bpf_mul(k) BPF_STMT(BPF_ALU|BPF_MUL|BPF_K, k) /* A <- A * k  */
#define bpf_div(k) BPF_STMT(BPF_ALU|BPF_DIV|BPF_K, k) /* A <- A / k  */
#define bpf_mod(k) BPF_STMT(BPF_ALU|BPF_MOD|BPF_K, k) /* A <- A % k  */
#define bpf_and(k) BPF_STMT(BPF_ALU|BPF_AND|BPF_K, k) /* A <- A & k  */
#define bpf_or(k) BPF_STMT(BPF_ALU|BPF_OR|BPF_K, k)   /* A <- A | k  */
#define bpf_xor(k) BPF_STMT(BPF_ALU|BPF_XOR|BPF_K, k) /* A <- A ^ k  */
#define bpf_lsh(k) BPF_STMT(BPF_ALU|BPF_LSH|BPF_K, k) /* A <- A << k */
#define bpf_rsh(k) BPF_STMT(BPF_ALU|BPF_RSH|BPF_K, k) /* A <- A >> k */

#define bpf_addx() BPF_STMT(BPF_ALU|BPF_ADD|BPF_X, 0) /* A <- A + X  */
#define bpf_subx() BPF_STMT(BPF_ALU|BPF_SUB|BPF_X, 0) /* A <- A - X  */
#define bpf_mulx() BPF_STMT(BPF_ALU|BPF_MUL|BPF_X, 0) /* A <- A * X  */
#define bpf_divx() BPF_STMT(BPF_ALU|BPF_DIV|BPF_X, 0) /* A <- A / X  */
#define bpf_modx() BPF_STMT(BPF_ALU|BPF_MOD|BPF_X, 0) /* A <- A % X  */
#define bpf_andx() BPF_STMT(BPF_ALU|BPF_AND|BPF_X, 0) /* A <- A & X  */
#define bpf_orx() BPF_STMT(BPF_ALU|BPF_OR|BPF_X, 0)   /* A <- A | X  */
#define bpf_xorx() BPF_STMT(BPF_ALU|BPF_XOR|BPF_X, 0) /* A <- A ^ X  */
#define bpf_lshx() BPF_STMT(BPF_ALU|BPF_LSH|BPF_X, 0) /* A <- A << X */
#define bpf_rshx() BPF_STMT(BPF_ALU|BPF_RSH|BPF_X, 0) /* A <- A >> X */

#define bpf_neg() BPF_STMT(BPF_ALU|BPF_NEG, 0) /* A <- -A */

/* control flow instructions */

#define bpf_ja(k) BPF_STMT(BPF_JMP|BPF_JA, k) /* pc += k */
#define bpf_jeq(k, t, f) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, k, t, f)   /* pc += (A == k) ? jt : jf */
#define bpf_jgt(k, t, f) BPF_JUMP(BPF_JMP|BPF_JGT|BPF_K, k, t, f)   /* pc += (A > k) ? jt : jf  */
#define bpf_jge(k, t, f) BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, k, t, f)   /* pc += (A >= k) ? jt : jf */
#define bpf_jset(k, t, f) BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, k, t, f) /* pc += (A & k) ? jt : jf  */

#define bpf_jmp(k) bpf_ja(k)

#define bpf_jneq(k, t, f) bpf_jeq(k, f, t)
#define bpf_jlt(k, t, f) bpf_jge(k, f, t)
#define bpf_jle(k, t, f) bpf_jgt(k, f, t)


/* return */

#define bpf_ret() BPF_STMT(BPF_RET|BPF_A, 0)      /* return A */
#define bpf_ret_imm(k) BPF_STMT(BPF_RET|BPF_K, k) /* return K */

/* misc */

#define bpf_tax() BPF_STMT(BPF_MISC|BPF_TAX, 0) /* X <- A */
#define bpf_txa() BPF_STMT(BPF_MISC|BPF_TXA, 0) /* A <- X */


#endif /* __SECCOMP_MACROS_H__ */
