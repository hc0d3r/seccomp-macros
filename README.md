# seccomp-macros

macros to make easy build seccomp filters without using libseccomp

## Install:

for install just execute:

```
# make install
```

you can set the install directory by setting `INSTALLDIR` option (/usr/include is the default):

```
# make install INSTALLDIR=/usr/local/include
```

for uninstall just delete the seccomp-macros.h file or run 

```
# make uninstall
```

## Macro list:

### Offsets

these macros return an offset in `struct seccomp_data`

| macro                   | description                       |
|-------------------------|-----------------------------------|
| off_syscall_nr          | syscall number offset             |
| off_audit_arch          | arch offset                       |
| off_instruction_pointer | instruction pointer offset        |
| off_syscall_arg(n)      | get the nth argument offset (0-5) |

### Copy instructions

these macros copy 4 bytes to A or X

| macro            | description                      |
|------------------|:---------------------------------|
| `bpf_ld_abs(k)`  | A <- P[k:4]                      |
| `bpf_ld_ind(k)`  | A <- P[X+k:4]                    |
| `bpf_ld_mem(k)`  | A <- M[k]                        |
| `bpf_ld_imm(k)`  | A <- k                           |
| `bpf_ld_len()`   | A <- sizeof(struct seccomp_data) |
| `bpf_ldx_mem(k)` | X <- M[k]                        |
| `bpf_ldx_imm(k)` | X <- k                           |
| `bpf_ldx_len()`  | X <- sizeof(struct seccomp_data) |

these macros copy 4 bytes to M[k]

| macro        | description |
|--------------|:------------|
| `bpf_st(k)`  | M[k] <- A   |
| `bpf_stx(k)` | M[k] <- X   |


### ALU instructions

mod appears not work, I only test bpf_and and bpf_mod, dont know if kernel support all these
instructions for seccomp

| macro        | description |
|--------------|:------------|
| `bpf_add(k)` | A <- A + k  |
| `bpf_sub(k)` | A <- A - k  |
| `bpf_mul(k)` | A <- A      |
| `bpf_div(k)` | A <- A / k  |
| `bpf_mod(k)` | A <- A % k  |
| `bpf_and(k)` | A <- A & k  |
| `bpf_or(k)`  | A <- A | k  |
| `bpf_xor(k)` | A <- A ^ k  |
| `bpf_lsh(k)` | A <- A << k |
| `bpf_rsh(k)` | A <- A >> k |
| `bpf_addx()` | A <- A + X  |
| `bpf_subx()` | A <- A - X  |
| `bpf_mulx()` | A <- A      |
| `bpf_divx()` | A <- A / X  |
| `bpf_modx()` | A <- A % X  |
| `bpf_andx()` | A <- A & X  |
| `bpf_orx()`  | A <- A | X  |
| `bpf_xorx()` | A <- A ^ X  |
| `bpf_lshx()` | A <- A << X |
| `bpf_rshx()` | A <- A >> X |
| `bpf_neg()`  | A <- -A     |

### Control flow instructions

| macro               | description                        |
|---------------------|:-----------------------------------|
| `bpf_ja(k)`         | pc += k                            |
| `bpf_jmp(k)`        | pc += k, just an alias to `bpf_ja` |
| `bpf_jeq(k, t, f)`  | pc += (A == k) ? jt : jf           |
| `bpf_jgt(k, t, f)`  | pc += (A > k) ? jt : jf            |
| `bpf_jge(k, t, f)`  | pc += (A >= k) ? jt : jf           |
| `bpf_jset(k, t, f)` | pc += (A & k) ? jt : jf            |
| `bpf_jneq(k, t, f)` | pc += (A != k) ? jt : jf           |
| `bpf_jlt(k, t, f)`  | pc += (A < k) ? jt : jf            |
| `bpf_jle(k, t, f)`  | pc += (A <= k) ? jt : jf           |

### Return

| macro               | description |
|---------------------|:------------|
| `bpf_ret()`         | return A    |
| `bpf_ret_imm(k)`    | return K    |


### Misc

| macro       | description |
|-------------|:------------|
| `bpf_tax()` | X <- A      |
| `bpf_txa()` | A <- X      |

## Examples:

I made a few examples, check the [examples](examples) folder

## Notes:

consider **k** as an `uint32_t` data type and **t** and **f** as `uint8_t` 
