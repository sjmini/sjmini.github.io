---
layout: post
title:  "Exploit code using pipe"
description: I tested how `PIPE` is working.
img: 
date:   2017-02-27 14:55:52 +0200
categories: 
---
I tested how `PIPE` is working in lunux. Understanding how PIPE works is kind of interesting to me as a lot of exploit codes use it.  

If we pass argument using pipe as below, the input is going into stdin buffer not argv1.  
> sungje.hwang@LGEARND15B13:~/hacking/pipe$ echo "1111122222333" | ./test  

My question is that how this input value is used by program if there are multiple scanf functions in the program.  
I developed simple test program as follow  
{% highlight c %}
#include <stdio.h>

int main() {
 char name[5];
 char name2[5];
 char name3[3];
 
 printf("first input\n");
 scanf("%5c", name);
 
 printf("second input\n");
 scanf("%5c", name2);
 
 printf("third input\n");
 scanf("%3c", name3);
 
 printf("1=%s, 2=%s, 3=%s\n", name, name2, name3);
 return 0;
}

{% endhighlight %}

sungje.hwang@LGEARND15B13:~/hacking/pipe$ echo "1111122222333" | ./test  
first input  
second input  
third input  
1=11111, 2=2222, 3=333  
sungje.hwang@LGEARND15B13:~/hacking/pipe$

As you can see, correct values are automatically stored into the corresponding buffers.  
The result is same with scanf function with %s format string.  

Then, what happen if we pass small input data through pipe?  

sungje.hwang@LGEARND15B13:~/hacking/pipe$ echo "1111122" | ./test  
first input  
second input  
third input  
1=11111, 2=22  
▒, 3=▒▒▒  
sungje.hwang@LGEARND15B13:~/hacking/pipe$  

some kine of unknown value is stored into buffer 2 & 3. However, buffer 1 obtained correct value.

**So, we could concluded that Linux automatically pass necessary value (within buffer size) into corresponding buffer.**  
  
  
**Note that scanf functions receives user input value through stdin buffer. That is why it can automatically receives the values passed through pipe. This is very basic concept but you need to understand this properly.**
