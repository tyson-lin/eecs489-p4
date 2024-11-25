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


    // TODO: Your code should end here

    // Remove entries that have been in the cache for too long
    std::erase_if(entries, [this](const auto& entry) {
        return std::chrono::steady_clock::now() - entry.second.timeAdded >= timeout;
    });
}

void ArpCache::addEntry(uint32_t ip, const mac_addr& mac) {
    std::unique_lock lock(mutex);

    // TODO: Your code below
    ArpEntry new_entry;
    new_entry.ip = ip;
    new_entry.mac = mac;
    new_entry.time_added = 0;
    std::pair<std::string,double> new_entry(ip, mac);
    entries.insert()
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
    AwaitingPacket queue_me;
    queue_me.packet = packet;
    queue_me.iface = iface;

    // ArpRequest doesn't exist yet
    if (requests.find(ip) != requests.end()) {
        std::list<AwaitingPacket> packets;
        packets.push_back(queue_me);

        ArpRequest request;
        request.ip = ip;
        request.awaitingPackets = packets;

        std:pair<ip_addr,ArpRequest> new_request(ip, request);
        requests.insert(new_request);
    }
    // ArpRequest already exists
    else {
        requests[ip].awaitingPackets.push_back(queue_me);
    }
}
