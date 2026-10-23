
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

static const char* REPLACEMENT_IP = "172.16.1.30";
static const char* OUTPUT_FILE = "generated_packet.bin";

static void append_u16(std::vector<unsigned char>& out,
                       uint16_t value) {
    out.push_back(static_cast<unsigned char>(value >> 8));
    out.push_back(static_cast<unsigned char>(value & 0xff));
}

static uint16_t checksum(const unsigned char* data, size_t len) {
    uint32_t sum = 0;

    while (len >= 2) {
        sum += (static_cast<uint16_t>(data[0]) << 8) | data[1];
        data += 2;
        len -= 2;
    }

    if (len != 0)
        sum += static_cast<uint16_t>(data[0]) << 8;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return static_cast<uint16_t>(~sum);
}

static bool is_example_com_a_response(
    const unsigned char* dns, size_t dns_len
) {
    if (!dns || dns_len < 12) return false;

    uint16_t flags = (dns[2] << 8) | dns[3];
    uint16_t qdcount = (dns[4] << 8) | dns[5];
    uint16_t ancount = (dns[6] << 8) | dns[7];

    if (!(flags & 0x8000) || qdcount != 1 || ancount == 0)
        return false;

    size_t pos = 12;
    std::string name;

    while (pos < dns_len) {
        uint8_t label_len = dns[pos++];

        if (label_len == 0) break;

        if ((label_len & 0xc0) != 0 ||
            pos + label_len > dns_len)
            return false;

        if (!name.empty()) name += '.';

        name.append(
            reinterpret_cast<const char*>(dns + pos),
            label_len
        );

        pos += label_len;
    }

    if (pos + 4 > dns_len) return false;

    uint16_t qtype = (dns[pos] << 8) | dns[pos + 1];
    uint16_t qclass = (dns[pos + 2] << 8) | dns[pos + 3];

    return name == "example.com" && qtype == 1 && qclass == 1;
}

// Build a controlled test DNS response from a query.
static std::vector<unsigned char> build_test_dns_response(
    const unsigned char* query,
    size_t query_len,
    const char* replacement_ip
) {
    std::vector<unsigned char> response;

    if (!query || query_len < 12) return response;

    uint16_t flags = (query[2] << 8) | query[3];
    uint16_t qdcount = (query[4] << 8) | query[5];

    if ((flags & 0x8000) || qdcount != 1) return response;

    size_t pos = 12;

    while (pos < query_len) {
        uint8_t label_len = query[pos++];

        if (label_len == 0) break;

        if ((label_len & 0xc0) != 0 ||
            pos + label_len > query_len)
            return {};

        pos += label_len;
    }

    if (pos + 4 > query_len) return {};

    uint16_t qtype = (query[pos] << 8) | query[pos + 1];
    uint16_t qclass = (query[pos + 2] << 8) | query[pos + 3];

    const unsigned char expected[] = {
        7, 'e','x','a','m','p','l','e',
        3, 'c','o','m', 0
    };

    if (qtype != 1 || qclass != 1 ||
        pos - 12 != sizeof(expected) ||
        std::memcmp(query + 12, expected, sizeof(expected)) != 0)
        return {};

    unsigned char ip[4];

    if (inet_pton(AF_INET, replacement_ip, ip) != 1)
        return {};

    response.insert(response.end(), query, query + pos + 4);

    response[2] = 0x81;
    response[3] = 0x80 | (query[3] & 0x01);

    response[4] = 0;
    response[5] = 1;
    response[6] = 0;
    response[7] = 1;
    response[8] = response[9] = 0;
    response[10] = response[11] = 0;

    response.push_back(0xc0);
    response.push_back(0x0c);

    append_u16(response, 1);
    append_u16(response, 1);

    response.push_back(0);
    response.push_back(0);
    response.push_back(1);
    response.push_back(44);

    append_u16(response, 4);
    response.insert(response.end(), ip, ip + 4);

    return response;
}

static std::vector<unsigned char> build_test_ipv4_udp_packet(
    const std::vector<unsigned char>& dns,
    const char* source_ip,
    const char* destination_ip,
    uint16_t source_port = 53,
    uint16_t destination_port = 53000
) {
    constexpr size_t IP_LEN = 20;
    constexpr size_t UDP_LEN = 8;

    std::vector<unsigned char> packet;

    if (dns.empty() ||
        IP_LEN + UDP_LEN + dns.size() > 65535)
        return packet;

    unsigned char src[4], dst[4];

    if (inet_pton(AF_INET, source_ip, src) != 1 ||
        inet_pton(AF_INET, destination_ip, dst) != 1)
        return packet;

    const size_t total_len = IP_LEN + UDP_LEN + dns.size();
    const size_t udp_size = UDP_LEN + dns.size();

    packet.assign(total_len, 0);

    packet[0] = 0x45;
    packet[2] = total_len >> 8;
    packet[3] = total_len & 0xff;
    packet[5] = 1;
    packet[6] = 0x40;
    packet[8] = 64;
    packet[9] = IPPROTO_UDP;

    std::memcpy(packet.data() + 12, src, 4);
    std::memcpy(packet.data() + 16, dst, 4);

    uint16_t ip_sum = checksum(packet.data(), IP_LEN);
    packet[10] = ip_sum >> 8;
    packet[11] = ip_sum & 0xff;

    const size_t u = IP_LEN;

    packet[u] = source_port >> 8;
    packet[u + 1] = source_port & 0xff;
    packet[u + 2] = destination_port >> 8;
    packet[u + 3] = destination_port & 0xff;
    packet[u + 4] = udp_size >> 8;
    packet[u + 5] = udp_size & 0xff;

    std::memcpy(packet.data() + IP_LEN + UDP_LEN,
                dns.data(), dns.size());

    std::vector<unsigned char> pseudo(12 + udp_size, 0);
    std::memcpy(pseudo.data(), src, 4);
    std::memcpy(pseudo.data() + 4, dst, 4);
    pseudo[9] = IPPROTO_UDP;
    pseudo[10] = udp_size >> 8;
    pseudo[11] = udp_size & 0xff;

    std::memcpy(pseudo.data() + 12,
                packet.data() + u, udp_size);

    uint16_t udp_sum = checksum(pseudo.data(), pseudo.size());
    if (udp_sum == 0) udp_sum = 0xffff;

    packet[u + 6] = udp_sum >> 8;
    packet[u + 7] = udp_sum & 0xff;

    return packet;
}

static bool validate_test_packet(
    const std::vector<unsigned char>& packet
) {
    constexpr size_t IP_LEN = 20;
    constexpr size_t UDP_LEN = 8;

    if (packet.size() < IP_LEN + UDP_LEN ||
        (packet[0] >> 4) != 4 ||
        (packet[0] & 0x0f) != 5 ||
        packet[9] != IPPROTO_UDP)
        return false;

    size_t ip_size = (packet[2] << 8) | packet[3];
    size_t udp_size = (packet[24] << 8) | packet[25];

    if (ip_size != packet.size() ||
        udp_size != packet.size() - IP_LEN)
        return false;

    if (checksum(packet.data(), IP_LEN) != 0)
        return false;

    std::vector<unsigned char> pseudo(12 + udp_size, 0);
    std::memcpy(pseudo.data(), packet.data() + 12, 8);
    pseudo[9] = IPPROTO_UDP;
    pseudo[10] = udp_size >> 8;
    pseudo[11] = udp_size & 0xff;

    std::memcpy(pseudo.data() + 12,
                packet.data() + IP_LEN, udp_size);

    return checksum(pseudo.data(), pseudo.size()) == 0;
}

static bool save_packet(
    const std::vector<unsigned char>& packet,
    const char* filename
) {
    std::ofstream file(filename, std::ios::binary);

    if (!file) return false;

    file.write(
        reinterpret_cast<const char*>(packet.data()),
        static_cast<std::streamsize>(packet.size())
    );

    return file.good();
}

static int packet_callback(
    nfq_q_handle* queue,
    nfgenmsg*,
    nfq_data* packet,
    void*
) {
    nfqnl_msg_packet_hdr* header =
        nfq_get_msg_packet_hdr(packet);

    if (!header) return 0;

    uint32_t packet_id = ntohl(header->packet_id);

    unsigned char* payload = nullptr;
    int length = nfq_get_payload(packet, &payload);

    if (length > 0 && payload &&
        length >= static_cast<int>(sizeof(iphdr))) {

        const auto* ip =
            reinterpret_cast<const iphdr*>(payload);

        if (ip->version == 4 && ip->ihl >= 5 &&
            ip->protocol == IPPROTO_UDP) {

            size_t ip_len = ip->ihl * 4;

            if (static_cast<size_t>(length) >=
                ip_len + sizeof(udphdr)) {

                const auto* udp =
                    reinterpret_cast<const udphdr*>(
                        payload + ip_len);

                size_t udp_len = ntohs(udp->len);

                if (udp_len >= sizeof(udphdr) + 12 &&
                    udp_len <= static_cast<size_t>(length) - ip_len) {

                    const unsigned char* dns =
                        payload + ip_len + sizeof(udphdr);

                    size_t dns_len = udp_len - sizeof(udphdr);

                    if (ntohs(udp->source) == 53 &&
                        is_example_com_a_response(dns, dns_len)) {
                        std::cout
                            << "[DNS match] example.com A response\n";
                    }
                }
            }
        }
    }

    return nfq_set_verdict(
        queue, packet_id, NF_ACCEPT, 0, nullptr);
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

    nfq_q_handle* queue =
        nfq_create_queue(handle, 0, &packet_callback, nullptr);

    if (!queue ||
        nfq_set_mode(queue, NFQNL_COPY_PACKET, 0xffff) < 0) {
        std::cerr << "Could not configure NFQUEUE\n";
        if (queue) nfq_destroy_queue(queue);
        nfq_close(handle);
        return 1;
    }

    std::cout << "[interceptor] NFQUEUE 0 ready\n";

    int fd = nfq_fd(handle);
    unsigned char buffer[65536];

    while (true) {
        int received = recv(fd, buffer, sizeof(buffer), 0);

        if (received < 0) {
            std::perror("NFQUEUE recv");
            break;
        }

        if (nfq_handle_packet(
                handle,
                reinterpret_cast<char*>(buffer),
                received) < 0) {
            std::cerr << "Failed to process queue message\n";
        }
    }

    nfq_destroy_queue(queue);
    nfq_close(handle);
    return 0;
}
