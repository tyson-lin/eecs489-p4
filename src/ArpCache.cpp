#include "ArpCache.h"

#include <thread>
#include <cstring>
#include <spdlog/spdlog.h>

#include "protocol.h"
#include "utils.h"


ArpCache::ArpCache(std::chrono::milliseconds timeout, std::shared_ptr<IPacketSender> packetSender, std::shared_ptr<IRoutingTable> routingTable)
: timeout(timeout)
, packetSender(std::move(packetSender))
, routingTable(std::move(routingTable)) {
    thread = std::make_unique<std::thread>(&ArpCache::loop, this);
}

ArpCache::~ArpCache() {
    shutdown = true;
    if (thread && thread->joinable()) {
        thread->join();
    }
}

void ArpCache::loop() {
    while (!shutdown) {
        tick();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void ArpCache::tick() {
    std::unique_lock lock(mutex);
    // TODO: Your code here

    // In the case of a cache miss, an ARP request should be sent to a target IP 
    // address about once every second until a reply comes in. If the ARP request 
    // is sent seven times with no reply, an ICMP destination host unreachable is 
    // sent back to the source IP as stated above. The provided ARP request queue 
    // will help you manage the request queue.

    // Within the tick() function, do we resend ARP request once for each awaitingPacket, 
    // or once per IP addr? Currently I am doing the first approach and there seems to 
    // be issues arising from that function.

    // once per ip addr per second ED #844

    for (auto it = requests.begin(); it != requests.end();) {
        ArpRequest* request = &(it->second);

        auto current_time = std::chrono::steady_clock::now();
        auto duration = current_time - request->lastSent;
        auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();

        if (duration_ms > 1000) {
            if (request->timesSent < 7) {
                std::optional<RoutingEntry> next_hop = routingTable->getRoutingEntry(request->ip);
                sendARP_Request(request->ip, next_hop->iface);
                request->timesSent += 1;
                std::cout << "Sending ARP request number " << request->timesSent << std::endl;
                ++it;
                request->lastSent = current_time;
            } else {
                it = requests.erase(it); 
            }
        }
    }

    // TODO: Your code should end here

    // Remove entries that have been in the cache for too long
    std::erase_if(entries, [this](const auto& entry) {
        return std::chrono::steady_clock::now() - entry.second.timeAdded >= timeout;
    });
}

void ArpCache::addEntry(uint32_t ip, const mac_addr& mac) {
    std::unique_lock lock(mutex);

    // TODO: Your code below

    // Entry already exists in cache
    if (entries.find(ip) != entries.end()) {
        return;
    }

    // Entry doesn't exist yet, create new one
    ArpEntry new_entry;
    new_entry.ip = ip;
    new_entry.mac = mac;
    new_entry.timeAdded = std::chrono::steady_clock::now();
    std::pair<ip_addr,ArpEntry> entry(ip, new_entry);
    entries.insert(entry);

    // TODO: i assume i need to use the information in the ARP response to update all the awaiting packets
    // forward awaiting packets
}

std::optional<mac_addr> ArpCache::getEntry(uint32_t ip) {
    std::unique_lock lock(mutex);

    // TODO: Your code below
    if (entries.find(ip) != entries.end()) {
        ArpEntry desired_entry = entries.at(ip);
        return desired_entry.mac;
    }

    return std::nullopt; // Placeholder
}

void ArpCache::queuePacket(uint32_t ip, const Packet& packet, const std::string& iface) {
    std::unique_lock lock(mutex);

    // TODO: Your code below

    // Assume that the packet has everything set except for the mac address
    AwaitingPacket queue_me;
    queue_me.packet = packet;
    queue_me.iface = iface;

    // ArpRequest doesn't exist yet
    if (requests.find(ip) == requests.end()) {
        std::cout << "Creating new ARP request" << std::endl;
        std::list<AwaitingPacket> packets;
        packets.push_back(queue_me);

        ArpRequest request;
        request.ip = ip;
        request.lastSent = std::chrono::steady_clock::now();
        request.timesSent = 1; // ED #827, see below
        request.awaitingPackets = packets;

        std::pair<ip_addr,ArpRequest> new_request(ip, request);
        requests.insert(new_request);

        // If there is no pending ARP request already, it is probably 
        // a good idea to send one out immediately. ED #827
        std::cout << "Sending ARP request number 1" << std::endl;
        sendARP_Request(ip, iface);
    }
    // ArpRequest already exists
    else {
        std::cout << "Adding to existing ARP request" << std::endl;
        requests[ip].awaitingPackets.push_back(queue_me);
    }
}

// TODO: separate sending an ARP request out into a function
void ArpCache::sendARP_Request(uint32_t ip, const std::string &iface) {
    Packet arp_request(sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t));

    sr_ethernet_hdr_t eth_hdr;
    memset(&eth_hdr.ether_dhost, 0xff, ETHER_ADDR_LEN);
    
    RoutingInterface interface = routingTable->getRoutingInterface(iface);
    memcpy(&eth_hdr.ether_shost, interface.mac.data(), ETHER_ADDR_LEN);

    eth_hdr.ether_type = htons(ethertype_arp);

    memcpy(arp_request.data(), &eth_hdr, sizeof(sr_ethernet_hdr_t));

    sr_arp_hdr_t arp_hdr;
    arp_hdr.ar_hrd = htons(arp_hrd_ethernet);
    arp_hdr.ar_pro = htons(2048);
    arp_hdr.ar_hln = 6;
    arp_hdr.ar_pln = 4;
    arp_hdr.ar_op = htons(arp_op_request);
    memcpy(&arp_hdr.ar_sha, interface.mac.data(), ETHER_ADDR_LEN);
    memcpy(&arp_hdr.ar_sip, &interface.ip, sizeof(uint32_t));
    memset(&arp_hdr.ar_tha, 0x00, ETHER_ADDR_LEN);
    memcpy(&arp_hdr.ar_tip, &interface.ip, sizeof(uint32_t));

    memcpy(arp_request.data()+sizeof(sr_ethernet_hdr_t), &arp_hdr, sizeof(sr_arp_hdr_t));  

    // std::cout << "Sending on interface:" << std::endl;
    // std::cout << interface.name << std::endl;
    // print_addr_eth(interface.mac.data());
    // print_addr_ip_int(interface.ip);

    packetSender->sendPacket(arp_request, iface);

    // std::cout << std::endl << "MY ARP REQUEST" << std::endl;
    // print_hdrs(arp_request.data(), arp_request.size());
}