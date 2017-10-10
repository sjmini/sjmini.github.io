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

To add new posts, simply add a file in the `_posts` directory that follows the convention `YYYY-MM-DD-name-of-post.ext` and includes the necessary front matter. Take a look at the source for this post to get an idea about how it works.

Jekyll also offers powerful support for code snippets:

{% highlight ruby %}
def print_hi(name)
  puts "Hi, #{name}"
end
print_hi('Tom')
#=> prints 'Hi, Tom' to STDOUT.
{% endhighlight %}

Check out the [Jekyll docs][jekyll-docs] for more info on how to get the most out of Jekyll. File all bugs/feature requests at [Jekyll’s GitHub repo][jekyll-gh]. If you have questions, you can ask them on [Jekyll Talk][jekyll-talk].

[jekyll-docs]: https://jekyllrb.com/docs/home
[jekyll-gh]:   https://github.com/jekyll/jekyll
[jekyll-talk]: https://talk.jekyllrb.com/
