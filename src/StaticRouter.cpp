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

    std::cout << std::endl << "HANDLE PACKET START ----------------------------" << std::endl;

    // Must first decide between ARP or IP 
    sr_ethernet_hdr_t* ehdr = (sr_ethernet_hdr_t*)packet.data();
    uint16_t ethtype = ntohs(ehdr->ether_type);

    switch (ethtype) {
        case ethertype_arp:
            std::cout << "Handling ARP packet" << std::endl;
            handleARP_Packet(packet, iface);
            break;
        case ethertype_ip:
            std::cout << "Handling IP packet" << std::endl;
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
        std::cout << "IP checksum invalid" << std::endl;
        return;
    }
    iphdr->ip_sum = received_checksum;

    // Is the ICMP packet checksum invalid?
    if (iphdr->ip_p == ip_protocol_icmp) {
        sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet.data()+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
        uint16_t received_icmp_checksum = icmp_hdr->icmp_sum;
        icmp_hdr->icmp_sum = 0;
        uint16_t correct_icmp_checksum = cksum(icmp_hdr, packet.size()-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));
        if (received_icmp_checksum != correct_icmp_checksum) {
            print_hdrs(packet.data(), packet.size());
            std::cout << "ICMP checksum invalid" << std::endl;
            return;
        }
    }

    // Is the interface one of my interfaces?
    std::unordered_map<std::string, RoutingInterface> interfaces = routingTable->getRoutingInterfaces();
    bool exists = false;
    for (const auto& [key, interface] : interfaces) {
        if (iphdr->ip_dst == interface.ip) {
            exists = true;
        }
    }

    if (exists) {
        // forward
        std::cout << "Handling IP packet to one of my interfaces" << std::endl;
        handleIP_PacketToMyInterfaces(packet, iface);
    } else {
        // do TTL stuff
        std::cout << "Handling packet TTL stuff" << std::endl;
        handleIP_PacketTTL(packet, iface);
    }

    return;
}

void StaticRouter::handleARP_Packet(std::vector<uint8_t> packet, std::string iface) {
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
            std::cout << "Handling ARP request" << std::endl;
            sendARP_Response(packet, iface);
            break;
        case arp_op_reply:
            std::cout << "Handling ARP reply" << std::endl;
            handleARP_Response(packet, iface);
            break;
        default:
            break;
    }
    return;
}

void StaticRouter::sendARP_Response(std::vector<uint8_t> packet, std::string iface) {
    // std::cout << std::endl << "CORRECT ARP REQUEST" << std::endl;
    // print_hdrs(packet.data(), packet.size());

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
    std::cout << "ARP Response: " << std::endl;
    print_hdrs(packet.data(), packet.size());

    // IP address associated with this interface]
    sr_arp_hdr_t arp_hdr;
    memcpy(&arp_hdr, packet.data() + sizeof(sr_ethernet_hdr_t), sizeof(sr_arp_hdr_t));
    ip_addr sender_ip_addr = arp_hdr.ar_sip;

    // Have I issued this response?
    std::optional<mac_addr> entry_mac_addr = arpCache->getEntry(sender_ip_addr);
    if (entry_mac_addr) {
        return; // Entry already exists in ARP cache
    }

    // Cache ARP
    mac_addr sender_mac_addr;
    memcpy(sender_mac_addr.data(), arp_hdr.ar_sha, ETHER_ADDR_LEN);

    arpCache->addEntry(sender_ip_addr, sender_mac_addr);
}

void StaticRouter::handleIP_PacketToMyInterfaces(std::vector<uint8_t> packet, std::string iface) {
    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet.data();
    sr_ip_hdr_t* iphdr = (sr_ip_hdr_t*)(packet.data() + sizeof(sr_ethernet_hdr_t));
    
    switch (iphdr->ip_p) {
        case ip_protocol_icmp:
            std::cout << "Sending ICMP packet 0 0" << std::endl;
            sendEcho(packet, iface, 0, 0);
            return;
        case ip_protocol_tcp: {
            std::cout << "Sending ICMP packet 3 3" << std::endl;
            mac_addr s_mac;
            uint32_t s_ip;
            mac_addr d_mac;
            uint32_t d_ip;
            memcpy(d_mac.data(), eth_hdr->ether_shost, ETHER_ADDR_LEN);
            s_ip = iphdr->ip_dst;
            d_ip = iphdr->ip_src;
            auto temp = routingTable->getRoutingEntry(iphdr->ip_src);
            auto inter = routingTable->getRoutingInterface(temp->iface);
            sendICMP_Packet(packet, iface, 3, 3, inter.mac, s_ip, d_mac, d_ip);
            return;
        }
        case ip_protocol_udp: {
            std::cout << "Sending ICMP packet 3 3" << std::endl;
            mac_addr s_mac;
            uint32_t s_ip;
            mac_addr d_mac;
            uint32_t d_ip;
            memcpy(d_mac.data(), eth_hdr->ether_shost, ETHER_ADDR_LEN);
            s_ip = iphdr->ip_dst;
            d_ip = iphdr->ip_src;
            auto temp = routingTable->getRoutingEntry(iphdr->ip_src);
            auto inter = routingTable->getRoutingInterface(temp->iface);
            sendICMP_Packet(packet, iface, 3, 3, inter.mac, s_ip, d_mac, d_ip);
            return;
        }
        default:
            return;
    }
}

void StaticRouter::handleIP_PacketTTL(std::vector<uint8_t> packet, std::string iface) {
    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet.data();
    sr_ip_hdr_t* iphdr = (sr_ip_hdr_t*)(packet.data() + sizeof(sr_ethernet_hdr_t));

    switch (iphdr->ip_ttl) {
        case 0: // drop the packet
            std::cout << "Packet TTL=0, dropping packet" << std::endl;
            return; 
        case 1: {
            std::cout << "Sending time exceeded" << std::endl;
            mac_addr s_mac;
            mac_addr d_mac;
            uint32_t d_ip;
            memcpy(d_mac.data(), eth_hdr->ether_shost, ETHER_ADDR_LEN);
            d_ip = iphdr->ip_src;
            auto temp = routingTable->getRoutingEntry(iphdr->ip_src);
            auto inter = routingTable->getRoutingInterface(temp->iface);
            sendICMP_Packet(packet, iface, 11, 0, inter.mac, inter.ip, d_mac, d_ip);
            return;
        }
        default: // TTL>1
            std::optional<RoutingEntry> entry = routingTable->getRoutingEntry(iphdr->ip_dst);
            if (!entry) {
                auto s = routingTable->getRoutingInterface(iface);
                mac_addr d_mac;
                memcpy(d_mac.data(), eth_hdr->ether_shost, ETHER_ADDR_LEN);
                sendICMP_Packet(packet, iface, 3, 0,s.mac, s.ip, d_mac, iphdr->ip_src);
            } else {
                std::cout << "Forwarding IP Packet" << std::endl;
                forwardIP_Packet(packet, routingTable->getRoutingInterface(entry->iface), *entry);
            }
            return;
    }
}

static void printBytes(const void* ptr) {
    // Cast the pointer to an unsigned char* for byte-wise access
    const unsigned char* bytePtr = static_cast<const unsigned char*>(ptr);

    for (size_t i = 0; i < 28; ++i) {
        // Print each byte as a two-digit hexadecimal number
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytePtr[i]) << " ";
    }
    std::cout << std::dec << std::endl; // Reset to decimal formatting
}

void StaticRouter::sendEcho(std::vector<uint8_t> packet, std::string iface, uint8_t type, uint8_t code) {
    sr_ethernet_hdr_t ehdr;
    memcpy(&ehdr,packet.data(),sizeof(sr_ethernet_hdr_t));
    sr_ip_hdr_t iphdr; 
    memcpy(&iphdr,packet.data()+sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));
    std::optional<RoutingEntry> next_hop = routingTable->getRoutingEntry(iphdr.ip_src);
    // if not there, just drop it
    if (!next_hop) {
        std::optional<mac_addr> entry = arpCache->getEntry(iphdr.ip_src);
    }

    // Generate the IP header
    // theoretically all we need to do is swap source and destination
    uint32_t temp_ip;
    std::memcpy(&temp_ip, &iphdr.ip_src, sizeof(temp_ip)); // Copy sender IP into temp
    std::memcpy(&iphdr.ip_src, &iphdr.ip_dst, sizeof(temp_ip)); // Replace sender IP with target IP
    std::memcpy(&iphdr.ip_dst, &temp_ip, sizeof(temp_ip)); // Replace target IP with original sender IP

    iphdr.ip_sum = 0;
    iphdr.ip_sum = cksum(&iphdr, sizeof(sr_ip_hdr_t));

    std::memcpy(packet.data()+sizeof(sr_ethernet_hdr_t), &iphdr, sizeof(sr_ip_hdr_t));

    // First generate the ethernet header
    RoutingInterface arrival_interface = routingTable->getRoutingInterface(iface);
    mac_addr arrival_mac_addr = arrival_interface.mac;

    mac_addr dest_mac_addr;
    std::memcpy(dest_mac_addr.data(), ehdr.ether_shost, sizeof(mac_addr));    
    // do we know the destination mac addr?
    

    for (int i = 0; i < ETHER_ADDR_LEN; i++) { 
        // set the source to be the mac addr of the arrival interface
        ehdr.ether_shost[i] = arrival_mac_addr[i];
    }

    for (int i = 0; i < ETHER_ADDR_LEN; i++) { 
        // set the dest to be the mac addr of the dest interface
        ehdr.ether_dhost[i] = dest_mac_addr[i];
    }
    std::memcpy(packet.data(), &ehdr, sizeof(sr_ethernet_hdr_t));

    sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = code;
    icmp_hdr->icmp_sum = 0;

    // Generate checksum
    icmp_hdr->icmp_sum = cksum(icmp_hdr, packet.size()-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));
    memcpy(packet.data()+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t), icmp_hdr, sizeof(sr_icmp_hdr_t));
    packetSender->sendPacket(packet, iface);
}

void StaticRouter::sendICMP_Packet(std::vector<uint8_t> packet, std::string iface, uint8_t type, uint8_t code, mac_addr arrival_mac_addr, uint32_t sIP, mac_addr dest_mac_addr, uint32_t dIP) {
    sr_ethernet_hdr_t ehdr;
    sr_ip_hdr_t iphdr;
    sr_icmp_t3_hdr_t icmphdr; 

    memcpy(&ehdr,packet.data(),sizeof(sr_ethernet_hdr_t));
    std::memcpy(&iphdr, packet.data() + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));
    
    //ETH HEADER
    for (int i = 0; i < ETHER_ADDR_LEN; i++) { 
        ehdr.ether_shost[i] = arrival_mac_addr[i];
        ehdr.ether_dhost[i] = dest_mac_addr[i];
    }
    ehdr.ether_type = htons(ethertype_ip);

    //IP HEADER
    iphdr.ip_id = htons(0);
    iphdr.ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    iphdr.ip_p = ip_protocol_icmp;
    iphdr.ip_off = htons(0);
    iphdr.ip_tos = 0;
    iphdr.ip_src = sIP;
    iphdr.ip_dst = dIP;
    iphdr.ip_ttl = 64; 
    iphdr.ip_sum = 0;
    iphdr.ip_sum = cksum(&iphdr, sizeof(sr_ip_hdr_t));

    //ICMP HEADER
    icmphdr.icmp_type = type;
    icmphdr.icmp_code = code;
    icmphdr.icmp_sum = 0;
    icmphdr.unused = 0;
    icmphdr.next_mtu = 0;
    std::memcpy(icmphdr.data, packet.data() + sizeof(sr_ethernet_hdr_t), ICMP_DATA_SIZE);
    icmphdr.icmp_sum = cksum(&icmphdr, sizeof(sr_icmp_t3_hdr_t));

    std::vector<uint8_t> help(sizeof(sr_ethernet_hdr_t) +sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    std::memcpy(help.data(), &ehdr, sizeof(sr_ethernet_hdr_t));
    std::memcpy(help.data() + sizeof(sr_ethernet_hdr_t), &iphdr, sizeof(sr_ip_hdr_t));
    std::memcpy(help.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), &icmphdr, sizeof(sr_icmp_t3_hdr_t));

    packetSender->sendPacket(help, iface);
}


void StaticRouter::forwardIP_Packet(std::vector<uint8_t> packet, RoutingInterface interface, RoutingEntry next_hop) {
    std::cout << "Packet to be forwarded: " << std::endl;
    print_hdrs(packet.data(), packet.size());

    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet.data();
    sr_ip_hdr_t* iphdr = (sr_ip_hdr_t*)(packet.data() + sizeof(sr_ethernet_hdr_t));
    // let's prepare our new packet - we know everything but the destination mac addr

    // Generate IP header
    iphdr->ip_ttl -= 1;
    iphdr->ip_sum = 0;
    iphdr->ip_sum = cksum(iphdr, sizeof(sr_ip_hdr_t));
    memcpy(packet.data()+sizeof(sr_ethernet_hdr_t), iphdr, sizeof(sr_ip_hdr_t));

    // Verify ICMP header checksum
    sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet.data()+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_sum = 0;
    int icmp_header_size = packet.size() - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
    icmp_hdr->icmp_sum = cksum(icmp_hdr, icmp_header_size);
    memcpy(packet.data()+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t), icmp_hdr, sizeof(sr_icmp_hdr_t));

    // Generate ethernet header
    
    std::optional<mac_addr> mac = arpCache->getEntry(next_hop.gateway);

    if (mac) {
        // Forward packet
        std::cout << "Destination mac address found in ARP cache, forwarding" << std::endl;
        memcpy(eth_hdr->ether_shost, interface.mac.data(), ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_dhost, mac->data(), ETHER_ADDR_LEN);
        memcpy(packet.data(), eth_hdr, sizeof(sr_ethernet_hdr_t));

        // std::cout << "Forwarding packet: " << std::endl;
        // print_hdrs(packet.data(), packet.size());
        packetSender->sendPacket(packet, next_hop.iface);
    } else {
        std::cout << "Queuing packet into ARP cache" << std::endl;
        // Add to ARP cache
        arpCache->queuePacket(next_hop.gateway, packet, next_hop.iface);
    }
}