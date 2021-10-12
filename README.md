-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

PEPsal: A TCP Performance Enhancing Proxy for satellite links
http://www.sourceforge.net/projects/pepsal

-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

PEPsal is a Performance Enhancing Proxy (PEP), used for optimizing TCP connections on satellite links. It works at multiple layers (IP, TCP, and Application): it uses netfilter to intercept those connections that would involve a satellite links and “steals” the TCP SYN packet in the three-way handshake phase of a TCP connection, then pretends to be the other side of that connection, and initiate a new connection to the real endpoint, using a userspace application that directly copy data between the two sockets. It thus effectively splits the TCP connection in two.

PEPsal represents a valid solution for the degraded TCP performance when satellite links are involved. It does not require modifications on content servers, or satellite receivers, it is sufficient to set it up in a computer traversed by the TCP connections.
It is designed to follow the advices in [IETF RFC3135](https://datatracker.ietf.org/doc/html/rfc3135), to implement a simple TCP Split technique.

- [Installation manual](#installation-manual)
- [User manual](#user-manual)
- [OpenSAND and OpenBACH manual](#opensand-and-openbach-manual)
- [Design document](#design-document)
- [Authors and contributors](#authors-and-contributors)
- [License](#license)
- [References](#references)

# Installation manual

<details><summary>Deploy to see how to install PEPSal</summary>

TODO

</details>

# User manual 

<details><summary>Deploy to see how to use PEPSal</summary>

TODO

</details>

# OpenSAND and OpenBACH manual

<details><summary>Deploy to see how to use PEPSal alongside OpenSAND and OpenBACH</summary>

TODO

</details>

# Design document

<details><summary>Deploy to see PEPSal design document</summary>

TODO

</details>

# Authors and contributors

Idea and Design	: 
- Carlo Caini <ccaini@deis.unibo.it>, 
- Rosario Firrincieli <rfirrincieli@arces.unibo.it>  
- Daniele Lacamera <root@danielinux.net>

Author		: 
- Daniele Lacamera <root@danielinux.net>

Co-Author	: 
- Sergio Ammirata <sergio.ammirata@wialan.com>

CNES has proposed to maintain and make some evolutions for the satellite community alongside OpenSAND and OpenBACH, in a complementary way. 

# License 

Please Refer to [COPYING](https://gitlab.cnes.fr/openbach/pepsal/-/blob/master/COPYING) for more information on the license.

# References

- C. Caini, R. Firrincieli and D. Lacamera, “PEPsal: A Performance Enhancing Proxy for TCP Satellite Connections [Internetworking and Resource Management in Satellite Systems Series],” in IEEE Aerospace and Electronic Systems Magazine, vol. 22, no. 8, pp. B-9-B-16, Aug. 2007. URL: http://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=4301030&isnumber=4300990

- C. Caini, R. Firrincieli and D. Lacamera, “PEPsal: a Performance Enhancing Proxy designed for TCP satellite connections,” 2006 IEEE 63rd Vehicular Technology Conference, Melbourne, Vic., 2006, pp. 2607-2611. URL: http://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=1683339&isnumber=35446

- “PEPsal: A Performance Enhancing Proxy for TCP Satellite Connections [for Internetworking and Resource Management in Satellite Systems (Series)],” in IEEE Aerospace and Electronic Systems Magazine, vol. 22, no. 8, pp. B-5-B-5, Aug. 2007. URL: http://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=4301026&isnumber=4300990

