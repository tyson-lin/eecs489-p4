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
            std::cout << "Processing ARP packet" << std::endl;
            handleARP_Packet(packet, iface);
            break;
        case ethertype_ip:
            std::cout << "Processing IP packet" << std::endl;
            handleIP_Packet(packet, iface);
            break;
        default:
            std::cout << "Unrecognized packet type" << std::endl;
    } 
}

void StaticRouter::handleIP_Packet(std::vector<uint8_t> packet, std::string iface) {
    return;
}

void StaticRouter::handleARP_Packet(std::vector<uint8_t> packet, std::string iface) {
    sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet.data() + sizeof(sr_ethernet_hdr_t));

    uint32_t target_ip_addr = ntohl(arp_hdr->ar_tip);
    std::cout << "Target IP Address: ";
    print_addr_ip_int(target_ip_addr);

    // Check if Target IP address isn't my IP address
    RoutingInterface arrival_interface = routingTable->getRoutingInterface(iface);
    ip_addr my_ip = ntohl(arrival_interface.ip);
    std::cout << "Arrival IP Address: ";
    print_addr_ip_int(my_ip);
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
            break;
        default:
            break;
    }
    return;
}

void StaticRouter::sendARP_Response(std::vector<uint8_t> packet, std::string iface) {
    std::cout << "Request packet: " << std::endl;
    print_hdrs(packet.data(), packet.size());

    // First generate the ethernet header
    sr_ethernet_hdr_t* ehdr = (sr_ethernet_hdr_t*)packet.data();
    for (int i = 0; i < ETHER_ADDR_LEN; i++) { 
        // source and destination get switched (opposite direction)
        std::swap(ehdr->ether_dhost[i], ehdr->ether_shost[i]);
    }
    // packet type shouldn't change

    // Generate the arp header
    sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet.data() + sizeof(sr_ethernet_hdr_t));
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        // sender and target hardware addresses get switched
        std::swap(arp_hdr->ar_sha[i], arp_hdr->ar_tha[i]);
    }
    // swap sender and target IP addresses    
    uint32_t temp_ip;
    std::memcpy(&temp_ip, &arp_hdr->ar_sip, sizeof(temp_ip)); // Copy sender IP into temp
    std::memcpy(&arp_hdr->ar_sip, &arp_hdr->ar_tip, sizeof(temp_ip)); // Replace sender IP with target IP
    std::memcpy(&arp_hdr->ar_tip, &temp_ip, sizeof(temp_ip)); // Replace target IP with original sender IP
    // formats and lengths shouldn't change
    
    arp_hdr->ar_op = arp_op_reply;

    // Generate ARP response
    std::memcpy(packet.data(), ehdr, sizeof(sr_ethernet_hdr_t));
    std::memcpy(packet.data()+sizeof(sr_ethernet_hdr_t), arp_hdr, sizeof(sr_arp_hdr_t));

    std::cout << "Response packet: " << std::endl;
    print_hdrs(packet.data(), packet.size());

    // Send response
    packetSender->sendPacket(packet, iface);
}

