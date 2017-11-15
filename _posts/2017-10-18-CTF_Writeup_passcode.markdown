---
layout: post
title:  "CTF: Second Write-up"
description: Write-up of Passcode problem
img: no image
date: 2017-10-18  +0200
---

Below is the source code of vulnerable binary file.  

{% highlight c %}
#include <stdio.h>
#include <stdlib.h>

void login(){
        int passcode1;
        int passcode2;

        printf("enter passcode1 : ");
        scanf("%d", passcode1);
        fflush(stdin);

        // ha! mommy told me that 32bit is vulnerable to bruteforcing :)
        printf("enter passcode2 : ");
        scanf("%d", passcode2);

        printf("checking...\n");
        if(passcode1==338150 && passcode2==13371337){
                printf("Login OK!\n");
                system("/bin/cat flag");
        }
        else{
                printf("Login Failed!\n");
                exit(0);
        }
}

void welcome(){
        char name[100];
        printf("enter you name : ");
        scanf("%100s", name);
        printf("Welcome %s!\n", name);
} 

int main(){
        printf("Toddler's Secure Login System 1.0 beta.\n");
        welcome();
        login();

        // something after login...
        printf("Now I can safely trust you that you have credential :)\n");
        return 0;
}
{% endhighlight %}

This is typical GOT overwrite problem.

The problem in this program is straight forward. It misuses scanf function.
e.x. scanf("%d", passcode1); should be scanf("%d", &passcode1);
Because of this vulnerable code, we can hijeck control flow.

I did following to solve this problem.
1. point passcode1 to printf got by exploiting buffer overflow vulnerability
2. change printf got value to system function's got value
3. make the program called enter which reads flag value.

First of all, I need to figure out got values.

