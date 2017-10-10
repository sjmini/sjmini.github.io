---
layout: post
title:  "Pwnable: FIX Write-up"
description: Write-up of "FIX" problem
img: no image
date: 2016-03-07  +0200
---

```c
private void test(){
printf(..);
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
> 0xfff7bed8: 0xfff7bf08####(old ebp) 0x080485c7####(ret) 0x0804874e 0xfff7bef8
> 0xfff7bee8: 0xf772cff4 0xf75bd1a5 0xf774f660 0x00000000
> 0xfff7bef8: 0x000000c9 0x0000000d

## Headings

Headings by default:

## Heading first level
### Heading second level
#### Heading third level

{% highlight markdown %}
## Heading first level
### Heading second level
#### Heading third level
{% endhighlight %}

## Lists

Unordered list example:
* Unordered list item 1
* Unordered list item 2
* Unordered list item 3
* Unordered list item 4

Ordered list example:
1. Ordered list item 1
2. Ordered list item 1
3. Ordered list item 1
4. Ordered list item 1

{% highlight markdown %}
* Unordered list item 1
* Unordered list item 2

1. Order list item 1
2. Order list item 1
{% endhighlight %}


## Quotes

A quote looks like this:

> Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor
incididunt ut labore et dolore magna.

{% highlight markdown %}
> Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor
incididunt ut labore et dolore magna.
{% endhighlight %}
