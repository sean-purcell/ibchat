---
layout: page
title: ibchat
---

ibchat is an end-to-end encrypted messaging program that runs through a centralized server for convenience of key-distribution and message delivery, without requiring trust of anyone, including the server, but the people you want to talk to.

I wrote it for fun to practice writing secure software, and so its written entirely from scratch in C, which sounds like a security nightmare, and it is.  Therefore, you really shouldn't use this for anything real, but feel free to [read the code](https://github.com/iburinoc/ibchat) and let me know if you find any security holes :)

## Installation 

Clone the repository at [https://github.com/iburinoc/ibchat](https://github.com/iburinoc/ibchat) or [download the zip](https://github.com/iburinoc/ibchat/archive/master.zip), and once in the ibchat directory run

{% highlight bash %}
make
sudo make install
{% endhighlight %}

### Security

The user data files should be completely secure, even to anyone who has read/write access to your computer, as they're all encrypted.  When you connect to a server for the first time, make sure you verify the server's public key with a trusted source.  If using the default server (ibchat.seanp.xyz), the public key signature must match

{% highlight bash %}
INSERT HERE
{% endhighlight %}

If it doesn't, do not accept the server's public key, as it is an impersonation attempt!

The same holds for adding friends.  Since the server doesn't know your username, only the sha256 hash of it, it cannot provide a list of users, so you must communicate with a friend beforehand to get their username.  When adding friends, you should verify their public key signature with them before accepting the request.  You can see your own public key signature in the header in the main menu.

