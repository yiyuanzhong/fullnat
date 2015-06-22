FULLNAT
=======
## What is LVS-FULLNAT?
Well, fullnat is the forth mode for LVS, it's technically identical to LVS-NAT
But it tries to preserve actual client IP addresses to real servers. In order
to do that, FULLNAT server alters the incoming packet to inject the actual
IP address into TCP/SYN packet, and real servers must load a kernel module
to extract the information and present it to the user mode application.

## The catch?
The real server module (client) is implemented long ago by some Baidu folks
for Linux 2.6.9, and they failed to find a perfect solution that minimize
the impact on altering IP addresses the user mode see, aka NAT. So they came
to an interesting but hacking way: hijack the getpeername() kernel API. The
catch is you have to patch the real server kernel, thus is dangerous and
unfriendly to kernel changes.

## So?
This is an alternative. I provide this kernel module for real servers to see
actual client IP through LVS-FULLNAT without patching, via NAT implemented by
netfilter. It's actually the reverse way SNAT and DNAT works: it does SNAT on
incoming packets and does DNAT on outgoing packets. There's no need to patch
anything, and as long as netfilter/conntrack is present in the kernel, you
can simply load the module and see what happens.

## TODO?
I don't really have time to work on FULLNAT servers, so I didn't write the
codes to extract information from SYN packets. Instead I hardcoded an incoming
IP address, and change it into a hardcoded __fake__ IP address whenever a new
TCP connection is established from this IP. You can see that big __TODO__ in
the code, where you can actually change the incoming IP and port to anything
you like.

Since 3.14, need_ipv4_conntrack() is removed, so you'll have to modprobe
nf_conntrack_ipv4 manually.

Also UDP and IPv6 are not yet implemented.

Well, it's my first time doing kernel programming, so be gentle please.
