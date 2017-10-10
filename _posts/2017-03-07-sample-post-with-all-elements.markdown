---
layout: post
title:  "Pwnable: FIX Write-up"
description: Write-up of "FIX" problem
img:no image
date: 2016-03-07  +0200
---

```c
private void test(){
printf(..);
}
```

If you analyzes binary file, you could figure out that we could modify 1 byte of shellcode, and we must leverage this vulnerability to obtain privileged shell.
The shellcode is embedded in the binary and I have checked whether it is valid shellcode as below:

xor    %eax,%eax  
push   %eax  
push   $0x68732f2f  
push   $0x6e69622f  
mov    %esp,%ebx  
push   %eax  
push   %ebx  
mov    %esp,%ecx  
mov    $0xb,%al  
int    $0x80  

Indeed it is valud shellcoded.

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
