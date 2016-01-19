---
layout: page
title: ibchat
---

ibchat is an end-to-end encrypted messaging program that runs through a centralized server for convenience of key-distribution and message delivery, without requiring trust of anyone, including the server, but the people you want to talk to.

I wrote it for fun to practice writing secure software, and so its written entirely from scratch in C, which sounds like a security nightmare, and it is (which helped me learn a lot).  Therefore, you really shouldn't use this for anything you need to be actually secure (if you want NSA protection look into GPG), but feel free to [read the code](https://github.com/iburinoc/ibchat) and let me know if you find any security holes :)

## Installation 

Clone the repository at [https://github.com/iburinoc/ibchat](https://github.com/iburinoc/ibchat) and once in the ibchat directory run
{% highlight bash %}
make client
sudo make install
{% endhighlight %}

## Security

The user data files should be completely secure, even to anyone who has read/write access to your computer, as they're all encrypted.  When you connect to a server for the first time, make sure you verify the server's public key with a trusted source.  If using the default server (ibchat.seanp.xyz), the public key signature must match

{% highlight bash %}
26fa61b57be5b49c0aa7035fa4c7c5136f15e67836b24b15d60aa35aadd56050
{% endhighlight %}

If it doesn't, do not accept the server's public key, as it is an impersonation attempt!

The same holds for adding friends.  Since the server doesn't know your username, only the sha256 hash of it, it cannot provide a list of users, so you must communicate with a friend beforehand to get their username.  When adding friends, you should verify their public key signature with them before accepting the request.  You can see your own public key signature in the header in the main menu.

## Protocols

Since I was building this project entirely from scratch, I decided to design my own protocols for it as well.  There are two main levels of protocols.

The first is the client-server protocol, which ensures that outsiders can't read or tamper with your communications with the server, so only the server can see what user you're communicating with.  This layer is built using RSA keys for authentication, so you know you're talking to the server you think you are, and then ephemeral Diffie-Hellman is used for key exchange to ensure perfect forward secrecy (meaning that if the server key is ever compromised, it doesn't compromise past conversations with the server).  The key exchange is used to generate a session symmetric key, which is used with CHACHA and HMAC-SHA256 to ensure privacy and authentication.

The second is the client-client protocol, which runs on top of the client-server protocol, ensuring that the server can't read or tamper with your messages to other users.  It uses RSA keys for authentication and key exchange, and then uses CHACHA and HMAC-SHA256 again to ensure efficient secrecy over the length of the conversation.

