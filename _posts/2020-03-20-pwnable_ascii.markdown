---
layout: post
title:  "Pwnable ascii_easy challenge"
description: libc ROP
date: 2020-03-20
---

![screenshot](../assets/img/ascii_easy.png)

Above is the source code of the vulnerable program.
There is a buffer overflow vulnerabilities in <i><b>vuln</b></i> function.

Let's analyze binary file.

{% highlight c %}
$ readelf -l ascii_easy

Elf file type is EXEC (Executable file)
Entry point 0x8048400
There are 9 program headers, starting at offset 52

Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  PHDR           0x000034 0x08048034 0x08048034 0x00120 0x00120 R E 0x4
  INTERP         0x000154 0x08048154 0x08048154 0x00013 0x00013 R   0x1
      [Requesting program interpreter: /lib/ld-linux.so.2]
  LOAD           0x000000 0x08048000 0x08048000 0x00944 0x00944 R E 0x1000
  LOAD           0x000f08 0x08049f08 0x08049f08 0x00128 0x0012c RW  0x1000
  DYNAMIC        0x000f14 0x08049f14 0x08049f14 0x000e8 0x000e8 RW  0x4
  NOTE           0x000168 0x08048168 0x08048168 0x00044 0x00044 R   0x4
  GNU_EH_FRAME   0x0007bc 0x080487bc 0x080487bc 0x00044 0x00044 R   0x4
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0x10
  GNU_RELRO      0x000f08 0x08049f08 0x08049f08 0x000f8 0x000f8 R   0x1
{% endhighlight %}

As we can see that there is no execution permission in stack.

{% highlight c %}
(gdb) disas vuln
Dump of assembler code for function vuln:
   0x08048518 <+0>:	push   ebp
   0x08048519 <+1>:	mov    ebp,esp
   0x0804851b <+3>:	sub    esp,0x28
   0x0804851e <+6>:	sub    esp,0x8
   0x08048521 <+9>:	push   DWORD PTR [ebp+0x8]
   0x08048524 <+12>:	lea    eax,[ebp-0x1c]
   0x08048527 <+15>:	push   eax
   0x08048528 <+16>:	call   0x8048380 <strcpy@plt>
   0x0804852d <+21>:	add    esp,0x10
   0x08048530 <+24>:	nop
   0x08048531 <+25>:	leave
   0x08048532 <+26>:	ret
End of assembler dump.
{% endhighlight %}

No stack canary in this program.


There are two interesting things in this program.
1. libc is loaded into the fixed location
2. only allow addresses range in ascii

because libc is loaded in fixed location, we can just use libc to launch ROP attack.
So, first, I will hijack control flow of the program by exploiting a buffer overflow vulnerability 
