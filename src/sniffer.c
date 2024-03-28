/*
 * PEPsal : A Performance Enhancing Proxy for Satellite Links
 *
 * Copyright Thales Alenia Space 2024
 * See AUTHORS and COPYING before using this software.
 *
 */


#include "sniffer.h"
#include "config.h"
#include "listener.h"
#include "log.h"
#include "pepdefs.h"
#include "pepsal.h"
#include "syntab.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

struct duplicated_fields {
    uint8_t tos;
    int tc;
};

#ifndef NDEBUG
static inline const char*
ether_type_str(uint16_t ether_type)
{
    switch (ether_type) {
    case 0x0800:
        return "Internet Protocol version 4 (IPv4)";
    case 0x0806:
        return "Address Resolution Protocol (ARP)";
    case 0x0842:
        return "Wake-on-LAN";
    case 0x22EA:
        return "Stream Reservation Protocol";
    case 0x22F0:
        return "Audio Video Transport Protocol (AVTP) ";
    case 0x22F3:
        return "IETF TRILL Protocol";
    case 0x6002:
        return "DEC MOP RC";
    case 0x6003:
        return "DECnet Phase IV, DNA Routing";
    case 0x6004:
        return "DEC LAT";
    case 0x8035:
        return "Reverse Address Resolution Protocol (RARP)";
    case 0x809B:
        return "AppleTalk (EtherTalk)";
    case 0x80F3:
        return "AppleTalk Address Resolution Protocol (AARP)";
    case 0x8100:
        return "VLAN-tagged";
    case 0x8102:
        return "Simple Loop Prevention Protocol (SLPP)";
    case 0x8103:
        return "Virtual Link Aggregation Control Protocol (VLACP)";
    case 0x8137:
        return "IPX";
    case 0x8204:
        return "QNX Qnet";
    case 0x86DD:
        return "Internet Protocol Version 6 (IPv6)";
    case 0x8808:
        return "Ethernet flow control";
    case 0x8809:
        return "Ethernet Slow Protocols such as the Link Aggregation Control Protocol (LACP)";
    case 0x8819:
        return "CobraNet";
    case 0x8847:
        return "MPLS unicast";
    case 0x8848:
        return "MPLS multicast";
    case 0x8863:
        return "PPPoE Discovery Stage";
    case 0x8864:
        return "PPPoE Session Stage";
    case 0x887B:
        return "HomePlug 1.0 MME";
    case 0x888E:
        return "EAP over LAN (IEEE 802.1X)";
    case 0x8892:
        return "PROFINET Protocol";
    case 0x889A:
        return "HyperSCSI (SCSI over Ethernet)";
    case 0x88A2:
        return "ATA over Ethernet";
    case 0x88A4:
        return "EtherCAT Protocol";
    case 0x88A8:
        return "Service VLAN tag identifier (S-Tag) on Q-in-Q tunnel";
    case 0x88AB:
        return "Ethernet Powerlink";
    case 0x88B8:
        return "GOOSE (Generic Object Oriented Substation event)";
    case 0x88B9:
        return "GSE (Generic Substation Events) Management Services";
    case 0x88BA:
        return "SV (Sampled Value Transmission)";
    case 0x88BF:
        return "MikroTik RoMON (unofficial)";
    case 0x88CC:
        return "Link Layer Discovery Protocol (LLDP)";
    case 0x88CD:
        return "SERCOS III";
    case 0x88E1:
        return "HomePlug Green PHY";
    case 0x88E3:
        return "Media Redundancy Protocol (IEC62439-2)";
    case 0x88E5:
        return "IEEE 802.1AE MAC security (MACsec)";
    case 0x88E7:
        return "Provider Backbone Bridges (PBB) (IEEE 802.1ah)";
    case 0x88F7:
        return "Precision Time Protocol (PTP) over IEEE 802.3 Ethernet";
    case 0x88F8:
        return "NC-SI";
    case 0x88FB:
        return "Parallel Redundancy Protocol (PRP)";
    case 0x8902:
        return "IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)";
    case 0x8906:
        return "Fibre Channel over Ethernet (FCoE)";
    case 0x8914:
        return "FCoE Initialization Protocol";
    case 0x8915:
        return "RDMA over Converged Ethernet (RoCE)";
    case 0x891D:
        return "TTEthernet Protocol Control Frame (TTE)";
    case 0x893a:
        return "1905.1 IEEE Protocol";
    case 0x892F:
        return "High-availability Seamless Redundancy (HSR)";
    case 0x9000:
        return "Ethernet Configuration Testing Protocol";
    case 0xF1C1:
        return "Redundancy Tag (IEEE 802.1CB Frame Replication and Elimination for Reliability) ";
    default:
        return "???";
    }
}
#endif

static inline int
duplicate_ip_fields(int fd, struct duplicated_fields* duped)
{
    if (duped->tos) {
        if (setsockopt(fd, IPPROTO_IP, IP_TOS, &duped->tos, sizeof(duped->tos)) == -1) {
            pep_warning("Failed to duplicate IP_TOS field! [%s:%d]", strerror(errno), errno);
            return -1;
        }
    }

    if (duped->tc) {
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &duped->tc, sizeof(duped->tc)) == -1) {
            pep_warning("Failed to duplicate IPV6_TCLASS field! [%s:%d]", strerror(errno), errno);
            return -1;
        }
    }

    return 0;
}

static inline size_t
parse_tcp_header(struct tcphdr* packet, uint8_t* is_syn, struct pep_proxy* proxy)
{
    // L4 de-encapsulation
    *is_syn = (packet->th_flags & TH_SYN) && !(packet->th_flags & TH_ACK);
    proxy->src.port = ntohs(packet->th_sport);
    proxy->dst.port = ntohs(packet->th_dport);
    PEP_DEBUG("Source Port: %d", proxy->src.port);
    PEP_DEBUG("Destination Port: %d", proxy->dst.port);

    // Convert number of 32-bits words into number of bytes
    return packet->th_off * 4;
}

static inline size_t
parse_ip_header(struct iphdr* packet, uint8_t* protocol, struct duplicated_fields* duped, struct pep_proxy* proxy)
{
    // L3 de-encapsulation
    *protocol = packet->protocol;
    duped->tos = packet->tos;
    uint32_t saddr = ntohl(packet->saddr);
    uint32_t daddr = ntohl(packet->daddr);
    proxy->src.addr[0] = 0;
    proxy->src.addr[1] = 0;
    proxy->src.addr[2] = 0;
    proxy->src.addr[3] = 0;
    proxy->src.addr[4] = 0;
    proxy->src.addr[5] = 0xffff;
    proxy->src.addr[6] = (saddr & 0xffff0000) >> 16;
    proxy->src.addr[7] = saddr & 0x0000ffff;
    proxy->dst.addr[0] = 0;
    proxy->dst.addr[1] = 0;
    proxy->dst.addr[2] = 0;
    proxy->dst.addr[3] = 0;
    proxy->dst.addr[4] = 0;
    proxy->dst.addr[5] = 0xffff;
    proxy->dst.addr[6] = (daddr & 0xffff0000) >> 16;
    proxy->dst.addr[7] = daddr & 0x0000ffff;

    CHECK_LOGGING(
        char src_address[IP_ADDR_LEN], dst_address[IP_ADDR_LEN];
        toip(src_address, saddr);
        toip(dst_address, daddr);
        PEP_DEBUG("IP version: %d", packet->version);
        PEP_DEBUG("IP header length: %d", packet->ihl);
        PEP_DEBUG("TOS Field: %u", duped->tos);
        PEP_DEBUG("Protocol: %u", *protocol);
        PEP_DEBUG("IP src address: %s", src_address);
        PEP_DEBUG("IP dst address: %s", dst_address););

    // Convert number of 32-bits words into number of bytes
    return packet->ihl * 4;
}

static inline size_t
parse_ip6_header(struct ip6_hdr* packet, uint8_t* protocol, struct duplicated_fields* duped, struct pep_proxy* proxy)
{
    // L3 de-encapsulation
    uint16_t payload_length = ntohs(packet->ip6_ctlun.ip6_un1.ip6_un1_plen);
    duped->tc = (0x0FF00000 & ntohl(packet->ip6_ctlun.ip6_un1.ip6_un1_flow)) >> 20;
    for (size_t i = 0; i < 8; ++i) {
        proxy->src.addr[i] = ntohs(packet->ip6_src.s6_addr16[i]);
        proxy->dst.addr[i] = ntohs(packet->ip6_dst.s6_addr16[i]);
    }

    CHECK_LOGGING(
        char src_address[IP_ADDR_LEN], dst_address[IP_ADDR_LEN];
        toip6(src_address, proxy->src.addr);
        toip6(dst_address, proxy->dst.addr);
        PEP_DEBUG("IP version: %u", (0xF0 & packet->ip6_ctlun.ip6_un2_vfc) >> 4);
        PEP_DEBUG("Traffic Class: %u", duped->tc);
        PEP_DEBUG("Payload Length: %u", payload_length);
        PEP_DEBUG("IP src address: %s", src_address);
        PEP_DEBUG("IP dst address: %s", dst_address););

    *protocol = packet->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    size_t offset = sizeof(struct ip6_hdr);
    size_t packet_size = offset + payload_length;
    for (;;) {
        PEP_DEBUG("Next header: 0x%02x", *protocol);
        if (offset >= packet_size) {
            // Somehow got past the end of the packet
            // (or this is an IPv6 jumbogram and we don't care)
            *protocol = 0xFF;
            return offset;
        }
        // Check for extension header and advance to find the actual payload
        switch (*protocol) {
        case 0: // IPv6 Hop-by-Hop Option
        case 43: // Routing Header for IPv6
        case 44: // Fragment Header for IPv6
        case 50: // Encapsulating Security Payload
        case 51: // Authentication Header
        case 60: // Destination Options for IPv6
        case 135: // Mobility Header
        case 139: // Host Identity Protocol
        case 140: // Shim6 Protocol
        case 253: // Use for experimentation and testing
        case 254: // Use for experimentation and testing
        {
            struct ip6_ext* extension_header = (struct ip6_ext*)((uint8_t*)(packet) + offset);
            *protocol = extension_header->ip6e_nxt;
            offset += 8 * (extension_header->ip6e_len + 1);
            break;
        }
        default:
            return offset;
        }
    }
}

static inline size_t
parse_ethernet_header(struct ether_header* packet, uint16_t* ether_type)
{
    // L2 de-encapsulation;
    PEP_DEBUG_MAC(packet->ether_dhost, "Destination MAC");
    PEP_DEBUG_MAC(packet->ether_shost, "Source MAC");

    size_t header_offset = sizeof(struct ether_header);
    *ether_type = ntohs(packet->ether_type);
#ifndef NDEBUG
    PEP_DEBUG("EtherType: 0x%04x (%s)", *ether_type, ether_type_str(*ether_type));
#else
    PEP_DEBUG("EtherType: 0x%04x", *ether_type);
#endif
    for (;;) {
        switch (*ether_type) {
        case 0x8100:
        case 0x88A8: {
            uint16_t* packet_option = (uint16_t*)(packet + header_offset);
            *ether_type = ntohs(packet_option[1]);
            PEP_DEBUG("VLAN Id: %d", ntohs(packet_option[0]));
#ifndef NDEBUG
            PEP_DEBUG("Real EtherType: 0x%04x (%s)", *ether_type, ether_type_str(*ether_type));
#else
            PEP_DEBUG("Real EtherType: 0x%04x", *ether_type);
#endif
            header_offset += 2 * sizeof(*packet_option);
        }
        default:
            return header_offset;
        }
    }

    return header_offset;
}

static inline void
analyse_packet(const struct sockaddr_ll* source, const unsigned char* packet, ssize_t pkt_length, int epoll_fd)
{
    if (source) {
        PEP_DEBUG_MAC(source->sll_addr,
            "Packet received: family %d, protocol %d, interface index %d, ARP type %d, packet type %d",
            source->sll_family,
            source->sll_protocol,
            source->sll_ifindex,
            source->sll_hatype,
            source->sll_pkttype);
    }

    uint16_t ether_type = 0;
    size_t offset = parse_ethernet_header((struct ether_header*)packet, &ether_type);

    struct duplicated_fields duped = {
        .tos = 0,
        .tc = 0,
    };
    struct pep_proxy* proxy = alloc_proxy();
    uint8_t protocol = 0;
    switch (ether_type) {
    case 0x0800:
        offset += parse_ip_header((struct iphdr*)(packet + offset), &protocol, &duped, proxy);
        break;
    case 0x86dd:
        offset += parse_ip6_header((struct ip6_hdr*)(packet + offset), &protocol, &duped, proxy);
        break;
    default:
        PEP_DEBUG("Not an IP payload");
        return;
    }

    uint8_t is_syn = 0;
    if (protocol == 0x06) {
        // TCP payload found
        offset += parse_tcp_header((struct tcphdr*)(packet + offset), &is_syn, proxy);
    } else {
        PEP_DEBUG("Not a TCP payload");
        return;
    }

    if (!is_syn) {
        PEP_DEBUG("Not a SYN packet");
        return;
    }

    PEP_DEBUG("Found a SYN packet, creating the associated syntab entry");
    proxy->syn_time = time(NULL);
    if (syntab_add_if_not_duplicate(proxy) < 0) {
        pep_warning("Failed to insert sniffed pep_proxy into a hash table!");

        struct syntab_key key;
        syntab_format_key(proxy, &key);
        unpin_proxy(proxy);
        SYNTAB_LOCK_READ();
        proxy = syntab_find(&key);
        /*
         * If still can't find key in the table, there is an error.
         */
        if (!proxy) {
            pep_warning("Can not find the connection in SYN table. "
                        "Terminating!");
            SYNTAB_UNLOCK_READ();
            return;
        }
    } else {
        /*
         * We need to lock here as the 'configure_out_socket' call
         * next will call to SYNTAB_UNLOCK_READ()
         */
        SYNTAB_LOCK_READ();
    }

    int out_fd = configure_out_socket(proxy, ether_type == 0x0800);
    if (out_fd < 0) {
        destroy_proxy(proxy, epoll_fd);
        return;
    }

    if (duplicate_ip_fields(out_fd, &duped) != 0) {
        close(out_fd);
        destroy_proxy(proxy, epoll_fd);
    } else {
        proxy->dst.fd = out_fd;
        proxy->status = PST_PENDING_IN;
    }
}

#define USE_AUXDATA 0
static inline void
sniff_packets(const char* ifname, int epoll_fd)
{
    int ret;
#if USE_AUXDATA
    int one = 1;
#endif
    struct sockaddr_ll interface;
    struct ifreq interface_request;

    int sniffer_fd = socket(AF_PACKET, SOCK_RAW, htons(0x0003));
    if (sniffer_fd < 0) {
        pep_warning("Cannot create sniffer socket. Deactivating SYN sniffing!");
        return;
    }

    bzero(&interface_request, sizeof(interface_request));
    if (ifname != NULL) {
        snprintf(interface_request.ifr_name, sizeof(interface_request.ifr_name), "%s", ifname);
        ret = ioctl(sniffer_fd, SIOCGIFINDEX, &interface_request);
        if (ret < 0) {
            pep_warning("Cannot retrieve interface index to sniff. Deactivating SYN sniffing!");
            goto teardown;
        }
    }

    bzero(&interface, sizeof(interface));
    interface.sll_family = AF_PACKET;
    interface.sll_protocol = htons(0x0003);
    interface.sll_ifindex = interface_request.ifr_ifindex;
    ret = bind(sniffer_fd, (struct sockaddr*)&interface, sizeof(interface));
    if (ret < 0) {
        pep_warning("Cannot bind sniffer socket to interface. Deactivating SYN sniffing!");
        goto teardown;
    }

#if USE_AUXDATA
    ret = setsockopt(sniffer_fd, SOL_PACKET, PACKET_AUXDATA, &one, sizeof(one));
    if (ret < 0) {
        pep_warning("Cannot collect ancillary data on sniffer socket. Deactivating SYN sniffing!");
        goto teardown;
    }
#endif

    for (;;) {
#if USE_AUXDATA
        unsigned char read_array[2048];
        struct iovec iov = {
            .iov_base = read_array,
            .iov_len = sizeof(read_array)
        };
        union {
            struct cmsghdr cmsg;
            char buf[CMSG_SPACE(sizeof(struct tpacket_auxdata))];
        } cmsg_buf;
        struct msghdr msg = {
            .msg_iov = &iov,
            .msg_iovlen = 1,
            .msg_control = &cmsg_buf,
            .msg_controllen = sizeof(cmsg_buf)
        };

        ssize_t temp_bytes = recvmsg(sniffer_fd, &msg, MSG_TRUNC);
        if (temp_bytes == -1 && errno != EINTR) {
            pep_warning("recvmsg failed on sniffer socket");
        }
        if (temp_bytes <= 0) {
            pep_warning("No data received on sniffer socket. Deactivating SYN sniffing!");
            break;
        }

        analyse_packet(NULL, read_array, temp_bytes, epoll_fd);
        for (struct cmsghdr* cmsg_ptr = CMSG_FIRSTHDR(&msg); cmsg_ptr; cmsg_ptr = CMSG_NXTHDR(&msg, cmsg_ptr)) {
            if ((cmsg_ptr->cmsg_len < CMSG_LEN(sizeof(struct tpacket_auxdata))) || (cmsg_ptr->cmsg_level != SOL_PACKET) || (cmsg_ptr->cmsg_type != PACKET_AUXDATA)) {
                PEP_DEBUG("Non auxiliary data header found: len %d, level %d, type %d\n", cmsg_ptr->cmsg_len, cmsg_ptr->cmsg_level, cmsg_ptr->cmsg_type);
                continue;
            }
            struct tpacket_auxdata* aux_ptr = (struct tpacket_auxdata*)CMSG_DATA(cmsg_ptr);
            PEP_DEBUG("tpid: 0x%04x tci: %d\n", aux_ptr->tp_vlan_tpid, aux_ptr->tp_vlan_tci);
        }
#else
        unsigned char buffer[2048];
        struct sockaddr_ll source_address;
        socklen_t address_length = sizeof(source_address);
        ssize_t pkt_length = recvfrom(sniffer_fd, buffer, 2048, MSG_TRUNC, (struct sockaddr*)&source_address, &address_length);
        if (pkt_length == -1 && errno != EINTR) {
            pep_warning("recvfrom failed on sniffer socket");
        }
        if (pkt_length <= 0) {
            pep_warning("No data received on sniffer socket. Deactivating SYN sniffing!");
            break;
        }
        analyse_packet(&source_address, buffer, pkt_length, epoll_fd);
#endif
    }

teardown:
    close(sniffer_fd);
}

void* sniffer_loop(void* arg)
{
    struct sniffer_thread_arguments* args = (struct sniffer_thread_arguments*)arg;
    if (args->interface_name) {
        PEP_DEBUG("Sniffing SYN packets on interface %s", args->interface_name);
        sniff_packets(args->interface_name, args->epoll_fd);
    } else {
        PEP_DEBUG("No interface to sniff!");
    }
    return NULL;
}
