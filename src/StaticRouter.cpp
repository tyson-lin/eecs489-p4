#include "StaticRouter.h"

#include <spdlog/spdlog.h>
#include <cstring>

#include "protocol.h"
#include "utils.h"

#include <iostream>

StaticRouter::StaticRouter(std::unique_ptr<IArpCache> arpCache, std::shared_ptr<IRoutingTable> routingTable,
                           std::shared_ptr<IPacketSender> packetSender)
    : routingTable(routingTable)
      , packetSender(packetSender)
      , arpCache(std::move(arpCache))
{
}



void StaticRouter::handlePacket(std::vector<uint8_t> packet, std::string iface)
{
    std::unique_lock lock(mutex);

    std::unordered_map<std::string, RoutingInterface> interfaces = routingTable->getRoutingInterfaces();
    for (auto & [key, value] : interfaces) {
        print_addr_eth(value.mac.data());
    }

    if (packet.size() < sizeof(sr_ethernet_hdr_t))
    {
        spdlog::error("Packet is too small to contain an Ethernet header.");
        return;
    }

    // TODO: Your code below

    // Must first decide between ARP or IP 
    sr_ethernet_hdr_t* ehdr = (sr_ethernet_hdr_t*)packet.data();
    uint16_t ethtype = ntohs(ehdr->ether_type);

    switch (ethtype) {
        case ethertype_arp:
            handleARP_Packet(packet, iface);
            break;
        case ethertype_ip:
            handleIP_Packet(packet, iface);
            break;
        default:
            std::cout << "Unrecognized packet type" << std::endl;
    } 
}

void StaticRouter::handleIP_Packet(std::vector<uint8_t> packet, std::string iface) {
    sr_ip_hdr_t* iphdr = (sr_ip_hdr_t*)(packet.data() + sizeof(sr_ethernet_hdr_t));

    // Is the destination IP one of my interfaces?
    uint32_t ip_dst = ntohl(iphdr->ip_dst);

    // Is the IP packet checksum invalid?
    uint16_t received_checksum = iphdr->ip_sum;
    iphdr->ip_sum = 0;
    uint16_t correct_checksum = cksum(iphdr, sizeof(sr_ip_hdr_t));
    if (received_checksum != correct_checksum) {
        return;
    }

    // Is the ICMP packet checksum invalid?
    sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet.data()+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
    uint16_t received_icmp_checksum = icmp_hdr->icmp_sum;
    icmp_hdr->icmp_sum = 0;
    uint16_t correct_icmp_checksum = cksum(icmp_hdr, packet.size()-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));
    if (received_icmp_checksum != correct_icmp_checksum) {
        return;
    }

    std::unordered_map<std::string, RoutingInterface> interfaces = routingTable->getRoutingInterfaces();
    
    bool exists = false;
    for (const auto& [key, interface] : interfaces) {
        std::optional<RoutingEntry> entry = routingTable->getRoutingEntry(interface.ip);
        if (entry) {
            exists = true;
            break;
        }
    }

    if (exists) {
        // forward
        handleIP_PacketToMyInterfaces(packet, iface);
    } else {
        // do TTL stuff
        handleIP_PacketTTL(packet, iface);
    }

    return;
}

void StaticRouter::handleARP_Packet(std::vector<uint8_t> packet, std::string iface) {
    print_hdrs(packet.data(), packet.size());

    sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet.data() + sizeof(sr_ethernet_hdr_t));

    uint32_t target_ip_addr = ntohl(arp_hdr->ar_tip);

    // Check if Target IP address isn't my IP address
    RoutingInterface arrival_interface = routingTable->getRoutingInterface(iface);
    ip_addr my_ip = ntohl(arrival_interface.ip);
    if (target_ip_addr != my_ip) {
        return; // drop the packet
    }

    // Request or response?
    sr_arp_opcode opcode = (sr_arp_opcode)ntohs(arp_hdr->ar_op);
    switch (opcode) {
        case arp_op_request:
            sendARP_Response(packet, iface);
            break;
        case arp_op_reply:
            handleARP_Response(packet, iface);
            break;
        default:
            break;
    }
    return;
}

void StaticRouter::sendARP_Response(std::vector<uint8_t> packet, std::string iface) {
    RoutingInterface arrival_interface = routingTable->getRoutingInterface(iface);
    mac_addr arrival_mac_addr = arrival_interface.mac;

    // First generate the ethernet header
    sr_ethernet_hdr_t* ehdr = (sr_ethernet_hdr_t*)packet.data();
    for (int i = 0; i < ETHER_ADDR_LEN; i++) { 
        // set the destination to the source of the request packet
        ehdr->ether_dhost[i] = ehdr->ether_shost[i];
        // set the source to be the mac addr of the arrival interface
        ehdr->ether_shost[i] = arrival_mac_addr[i];
    }
    
    // packet type shouldn't change

    // Generate the arp header
    sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet.data() + sizeof(sr_ethernet_hdr_t));
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        // target hardware address set to the sender hardware address
        arp_hdr->ar_tha[i] = arp_hdr->ar_sha[i];
        // sender hardware address set to the mac addr of the arrival interface
        arp_hdr->ar_sha[i] = arrival_mac_addr[i];
    }
    // swap sender and target IP addresses    
    uint32_t temp_ip;
    std::memcpy(&temp_ip, &arp_hdr->ar_sip, sizeof(temp_ip)); // Copy sender IP into temp
    std::memcpy(&arp_hdr->ar_sip, &arp_hdr->ar_tip, sizeof(temp_ip)); // Replace sender IP with target IP
    std::memcpy(&arp_hdr->ar_tip, &temp_ip, sizeof(temp_ip)); // Replace target IP with original sender IP

    // formats and lengths shouldn't change

    arp_hdr->ar_op = htons(arp_op_reply);

    // Generate ARP response
    std::memcpy(packet.data(), ehdr, sizeof(sr_ethernet_hdr_t));
    std::memcpy(packet.data()+sizeof(sr_ethernet_hdr_t), arp_hdr, sizeof(sr_arp_hdr_t));

    // Send response
    packetSender->sendPacket(packet, iface);
}

void StaticRouter::handleARP_Response(std::vector<uint8_t> packet, std::string iface) {
    // IP address associated with this interface
    RoutingInterface arrival_iface = routingTable->getRoutingInterface(iface);
    ip_addr arrival_ip = arrival_iface.ip;

    // Have I issued this response?
    std::optional<mac_addr> entry_mac_addr = arpCache->getEntry(arrival_ip);
    if (entry_mac_addr) {
        return; // Entry already exists in ARP cache
    }

    // Cache ARP
    sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet.data() + sizeof(sr_ethernet_hdr_t));
    ip_addr sender_ip_addr = ntohl(arp_hdr->ar_sip);
    
    mac_addr sender_mac_addr;
    memcpy(sender_mac_addr.data(), arp_hdr->ar_sha, ETHER_ADDR_LEN);

    arpCache->addEntry(sender_ip_addr, sender_mac_addr);
}

void StaticRouter::handleIP_PacketToMyInterfaces(std::vector<uint8_t> packet, std::string iface) {
    sr_ip_hdr_t* iphdr = (sr_ip_hdr_t*)(packet.data() + sizeof(sr_ethernet_hdr_t));
    
    switch (iphdr->ip_p) {
        case ip_protocol_icmp:
            sendICMP_Packet(packet, iface, 0, 0);
            return;
        case ip_protocol_tcp:
        case ip_protocol_udp:
            sendICMP_Packet(packet, iface, 3, 3);
            return;
        default:
            return;
    }
}

void StaticRouter::handleIP_PacketTTL(std::vector<uint8_t> packet, std::string iface) {
    sr_ip_hdr_t* iphdr = (sr_ip_hdr_t*)(packet.data() + sizeof(sr_ethernet_hdr_t));

    switch (iphdr->ip_ttl) {
        case 0: // drop the packet
            return; 
        case 1: 
            sendICMP_Packet(packet, iface, 11, 0);
            return;
        default: // TTL>1
            // is destination IP in routing table ?
            std::optional<RoutingEntry> entry = routingTable->getRoutingEntry(iphdr->ip_dst);
            if (!entry) {
                sendICMP_Packet(packet, iface, 3, 0); // not in table
            } else {
                forwardIP_Packet(packet, routingTable->getRoutingInterface(entry->iface), *entry);
            }
            return;
    }
}

void StaticRouter::sendICMP_Packet(std::vector<uint8_t> packet, std::string iface, uint8_t type, uint8_t code) {
    RoutingInterface arrival_interface = routingTable->getRoutingInterface(iface);
    mac_addr arrival_mac_addr = arrival_interface.mac;

    // First generate the ethernet header
    sr_ethernet_hdr_t* ehdr = (sr_ethernet_hdr_t*)packet.data();
    for (int i = 0; i < ETHER_ADDR_LEN; i++) { 
        // set the destination to the source of the request packet
        ehdr->ether_dhost[i] = ehdr->ether_shost[i];
        // set the source to be the mac addr of the arrival interface
        ehdr->ether_shost[i] = arrival_mac_addr[i];
    }
    std::memcpy(packet.data(), ehdr, sizeof(sr_ethernet_hdr_t));

    // packet type shouldn't change

    // Generate the IP header
    sr_ip_hdr_t* iphdr = (sr_ip_hdr_t*)(packet.data() + sizeof(sr_ethernet_hdr_t));
    // theoretically all we need to do is swap source and destination
    uint32_t temp_ip;
    std::memcpy(&temp_ip, &iphdr->ip_src, sizeof(temp_ip)); // Copy sender IP into temp
    std::memcpy(&iphdr->ip_src, &iphdr->ip_dst, sizeof(temp_ip)); // Replace sender IP with target IP
    std::memcpy(&iphdr->ip_dst, &temp_ip, sizeof(temp_ip)); // Replace target IP with original sender IP

    iphdr->ip_sum = 0;
    iphdr->ip_sum = cksum(iphdr, sizeof(sr_ip_hdr_t));

    std::memcpy(packet.data()+sizeof(sr_ethernet_hdr_t), iphdr, sizeof(sr_ip_hdr_t));

    // Generate the ICMP header
    switch (type) {
        // TODO: Type 11
        case 3: {
            sr_icmp_t3_hdr_t* icmp_t3_hdr = (sr_icmp_t3_hdr_t*)(packet.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            icmp_t3_hdr->icmp_type = type;
            icmp_t3_hdr->icmp_code = code;
            icmp_t3_hdr->icmp_sum = 0;
            icmp_t3_hdr->next_mtu = 1500;

            // TODO: how do i fill out the data part?
            
            // Generate checksum
            icmp_t3_hdr->icmp_sum = cksum(icmp_t3_hdr, packet.size()-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));
            memcpy(packet.data()+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t), icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));

            break;
        }
        default: {
            sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            icmp_hdr->icmp_type = type;
            icmp_hdr->icmp_code = code;
            icmp_hdr->icmp_sum = 0;

            // Generate checksum
            icmp_hdr->icmp_sum = cksum(icmp_hdr, packet.size()-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));
            memcpy(packet.data()+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t), icmp_hdr, sizeof(sr_icmp_hdr_t));
            break;
        }
    }

    packetSender->sendPacket(packet, iface);
}

void StaticRouter::forwardIP_Packet(std::vector<uint8_t> packet, RoutingInterface interface, RoutingEntry next_hop) {
    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet.data();
    sr_ip_hdr_t* iphdr = (sr_ip_hdr_t*)(packet.data() + sizeof(sr_ethernet_hdr_t));
    
    // let's prepare our new packet - we know everything but the destination mac addr

    // Generate ethernet header
    memcpy(eth_hdr->ether_shost, interface.mac.data(), ETHER_ADDR_LEN);
    memcpy(packet.data(), eth_hdr, sizeof(sr_ethernet_hdr_t));

    // Generate IP header
    iphdr->ip_ttl -= 1;

    iphdr->ip_sum = 0;
    iphdr->ip_sum = cksum(iphdr, sizeof(sr_ip_hdr_t));
    memcpy(packet.data()+sizeof(sr_ethernet_hdr_t), iphdr, sizeof(sr_ip_hdr_t));

    std::optional<mac_addr> mac = arpCache->getEntry(next_hop.dest);

    if (mac) {
        // Forward packet

        // Only for testing sending a request
        arpCache->queuePacket(next_hop.dest, packet, next_hop.iface);

        memcpy(eth_hdr->ether_dhost, mac->data(), ETHER_ADDR_LEN);
        memcpy(packet.data(), eth_hdr, sizeof(sr_ethernet_hdr_t));
        packetSender->sendPacket(packet, next_hop.iface);
    } else {
        // Add to ARP cache
        arpCache->queuePacket(next_hop.dest, packet, next_hop.iface);
    }
}