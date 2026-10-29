
# What's "lines", and why did I make it?

Lines takes a **stochastic datagram** transport layer, and makes it a layer that is reliable, multiplexed, ultra-secure, un-analysable and tamper-resistant, and by multiplexed, we mean it provides many "channels".

Also, any one could read all contents sent, could tamper with em, could retransmit em...

### What's a stochastic datagram?

It is a physical transport which delivers a series of bytes in a bundle each time, but doesnt guarantee the bundles arrive in order, also, a bundle could be lost, or could be corrupted.


It's really bitpacked (the overhead is ~11 bytes), lightweight, supports full encryption ( no plaintext metadata, even the bundle id is masked ), it supports fragmentation, pub-pri handshakes...



# Cases of use:
* On games? there are unimportant packets like movement packets, if we receive packet #6 and packet #5 both contain movement data, and #5 is lost, we wouldnt want to transmit the #5 again, there are also important packets like inventory packets, which need to be delivered no matter what.
* On LoRa? as you see the mtu of lora is super small (~255 bytes), you would need a protocol that uses the least num of bytes while leaving the rest for app data.
* On wired? let's assume you have a device A with 10 differential pairs, and a device B with 3, without any formal negotiation, Lines will learn to use the shared pairs.
* On radio? lets assume u've got n bands 433MHz and n bands on 5GHz, you would want to automatically use 433MHz when you are far, and automatically switch to 5GHz ( or a hybrid )
* You were home, you had an IP address, you left, you got another IP address, and you dont want to lose your current video stream or your game session, lines handles continuation smooooothly...
* Why do I need to read a spec of hundreds of pages just to make a protocol that achieves the same goal, for lines, you could say everything you need is here!



Full documentation at [ksee.dev/lines/1-lines](https://ksee.dev/lines/1-lines), you could find examples there.

Licenced under the Apache2.0 license.

