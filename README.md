# pingw
ping via a gateway without touching the kernel's routing table

given an interface + prospective gateway ip address on that interface's network, pingw will:
- arp resolve the MAC address of the gateway, then
- use the mac address of the gateway to construct the raw frame
- populate the contained ICMP packet with

this approach permits gateways to be checked for liveness concurrently, without flapping routes in the kernel (which limits us to checking one gateway at a time per ping destination).

given that the most appealing things to ping are well-known DNS servers (which 3rd party daemons may rely on), leaving the kernel routing table alone prevents ping tests from leading to unwanted side-effects
