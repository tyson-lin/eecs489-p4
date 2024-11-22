#include "RoutingTable.h"

#include <arpa/inet.h>
#include <fstream>
#include <sstream>
#include <spdlog/spdlog.h>

RoutingTable::RoutingTable(const std::filesystem::path& routingTablePath) {
    if (!std::filesystem::exists(routingTablePath)) {
        throw std::runtime_error("Routing table file does not exist");
    }

    std::ifstream file(routingTablePath);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open routing table file");
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) {
            continue;
        }

        std::istringstream iss(line);
        std::string dest, gateway, mask, iface;
        iss >> dest >> gateway >> mask >> iface;

        uint32_t dest_ip, gateway_ip, subnet_mask;

        if (inet_pton(AF_INET, dest.c_str(), &dest_ip) != 1 ||
            inet_pton(AF_INET, gateway.c_str(), &gateway_ip) != 1 ||
            inet_pton(AF_INET, mask.c_str(), &subnet_mask) != 1) {
            spdlog::error("Invalid IP address format in routing table file: {}", line);
            throw std::runtime_error("Invalid IP address format in routing table file");
            }

        routingEntries.push_back({dest_ip, gateway_ip, subnet_mask, iface});
    }
}

// Function to calculate the CIDR length of a netmask
//
// Assumptions:
// All netmasks are valid netmasks
//      255.255.0.1 will not appear
static unsigned int netmaskToCIDR(uint32_t netmask) {
    unsigned int cidrLength = 0;
    // Count the number of 1 bits in the netmask
    while (netmask) {
        cidrLength += (netmask & 1); // Check the least significant bit
        netmask >>= 1;               // Shift right by 1 bit
    }
    return cidrLength;
}


std::optional<RoutingEntry> RoutingTable::getRoutingEntry(ip_addr ip) {
    // TODO: Your code below
    unsigned int longest_match_index = -1;
    unsigned int longest_match_length = 0;

    for (unsigned int i = 0; i < routingEntries.size(); i++) {
        uint32_t mask = routingEntries[i].mask;
        uint32_t masked_gateway = routingEntries[i].gateway & mask;
        uint32_t masked_input = ip & mask;
        if (masked_gateway == masked_input) {
            unsigned int match_length = netmaskToCIDR(mask);
            if (match_length > longest_match_length) {
                longest_match_index = i;
                longest_match_length = match_length;
            }
        }
    }
    if (longest_match_index != -1) {
        return routingEntries[longest_match_index];
    }

    return routingEntries[0]; // Placeholder
}

RoutingInterface RoutingTable::getRoutingInterface(const std::string& iface) {
    return routingInterfaces.at(iface);
}

void RoutingTable::setRoutingInterface(const std::string& iface, const mac_addr& mac, const ip_addr& ip) {
    routingInterfaces[iface] = {iface, mac, ip};
}

const std::unordered_map<std::string, RoutingInterface>& RoutingTable::getRoutingInterfaces() const
{
    return routingInterfaces;
}
