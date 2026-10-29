
# What's "lines", and why did I make it?

Lines takes a **stochastic datagram** transport layer, and makes it a layer that is reliable, multiplexed, ultra-secure, un-analysable and tamper-resistant, and by multiplexed, we mean it provides many "channels".

Also, any one could read all contents sent, could tamper with em, could retransmit em...

### What's a stochastic datagram?

It is a physical transport which delivers a series of bytes in a bundle each time, but doesnt guarantee the bundles arrive in order, also, a bundle could be lost, or could be corrupted.


It's really bitpacked (the overhead is ~11 bytes), lightweight, supports full encryption ( no plaintext metadata, even the bundle id is masked ), it supports fragmentation, pub-pri handshakes...


Full documentation at [ksee.dev/lines/1-lines](https://ksee.dev/lines/1-line), you could find examples there.

Licenced under the Apache2.0 license.

