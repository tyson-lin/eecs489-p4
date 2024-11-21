#ifndef ROUTERTYPES_H
#define ROUTERTYPES_H

#include <chrono>
#include <vector>
#include <array>

#include "protocol.h"

constexpr inline size_t ETHERNET_HEADER_SIZE = sizeof(sr_ethernet_hdr_t);
constexpr inline size_t ARP_PACKET_SIZE = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
constexpr inline size_t ICMP_T3_PACKET_SIZE = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
constexpr inline size_t ICMP_PACKET_SIZE = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
constexpr inline size_t IP_PACKET_SIZE = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
constexpr inline uint8_t INIT_TTL = 255;

using mac_addr = std::array<uint8_t, 6>;
using ip_addr = uint32_t;
using Packet = std::vector<uint8_t>;

#endif //ROUTERTYPES_H
