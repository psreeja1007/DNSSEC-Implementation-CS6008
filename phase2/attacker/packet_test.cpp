
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

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

static std::vector<unsigned char> build_test_ipv4_udp_packet(
    const std::vector<unsigned char>& dns,
    const char* source_ip,
    const char* destination_ip,
    uint16_t source_port = 53,
    uint16_t destination_port = 53000
) {
    std::vector<unsigned char> packet;

    constexpr size_t IP_LEN = 20;
    constexpr size_t UDP_LEN = 8;

    if (dns.empty() ||
        IP_LEN + UDP_LEN + dns.size() > 65535) {
        return packet;
    }

    unsigned char src[4], dst[4];

    if (inet_pton(AF_INET, source_ip, src) != 1 ||
        inet_pton(AF_INET, destination_ip, dst) != 1) {
        return packet;
    }

    const size_t total_len = IP_LEN + UDP_LEN + dns.size();
    packet.resize(total_len, 0);

    // IPv4 header.
    packet[0] = 0x45;                   // IPv4, 20-byte header
    packet[1] = 0;                      // DSCP/ECN
    packet[2] = total_len >> 8;
    packet[3] = total_len & 0xff;
    packet[4] = 0;
    packet[5] = 1;                      // Test identification
    packet[6] = 0x40;                   // Don't fragment
    packet[7] = 0;
    packet[8] = 64;                     // TTL
    packet[9] = IPPROTO_UDP;
    std::memcpy(packet.data() + 12, src, 4);
    std::memcpy(packet.data() + 16, dst, 4);

    uint16_t ip_sum = checksum(packet.data(), IP_LEN);
    packet[10] = ip_sum >> 8;
    packet[11] = ip_sum & 0xff;

    // UDP header.
    const size_t udp_offset = IP_LEN;
    packet[udp_offset] = source_port >> 8;
    packet[udp_offset + 1] = source_port & 0xff;
    packet[udp_offset + 2] = destination_port >> 8;
    packet[udp_offset + 3] = destination_port & 0xff;

    const uint16_t udp_size = UDP_LEN + dns.size();
    packet[udp_offset + 4] = udp_size >> 8;
    packet[udp_offset + 5] = udp_size & 0xff;

    // DNS payload.
    std::memcpy(
        packet.data() + IP_LEN + UDP_LEN,
        dns.data(),
        dns.size()
    );

    // UDP checksum includes the IPv4 pseudo-header.
    std::vector<unsigned char> pseudo(12 + udp_size, 0);
    std::memcpy(pseudo.data(), src, 4);
    std::memcpy(pseudo.data() + 4, dst, 4);
    pseudo[9] = IPPROTO_UDP;
    pseudo[10] = udp_size >> 8;
    pseudo[11] = udp_size & 0xff;

    std::memcpy(
        pseudo.data() + 12,
        packet.data() + udp_offset,
        udp_size
    );

    uint16_t udp_sum = checksum(pseudo.data(), pseudo.size());
    if (udp_sum == 0) udp_sum = 0xffff;

    packet[udp_offset + 6] = udp_sum >> 8;
    packet[udp_offset + 7] = udp_sum & 0xff;

    return packet;
}

static bool validate_test_packet(
    const std::vector<unsigned char>& packet
) {
    constexpr size_t IP_LEN = 20;
    constexpr size_t UDP_LEN = 8;

    if (packet.size() < IP_LEN + UDP_LEN) return false;
    if ((packet[0] >> 4) != 4 || (packet[0] & 0x0f) != 5)
        return false;

    const size_t ip_size = (packet[2] << 8) | packet[3];
    const size_t udp_offset = IP_LEN;
    const size_t udp_size =
        (packet[udp_offset + 4] << 8) |
        packet[udp_offset + 5];

    if (ip_size != packet.size() ||
        udp_size != packet.size() - IP_LEN ||
        packet[9] != IPPROTO_UDP) {
        return false;
    }

    // A valid IPv4 header checksum verifies to zero.
    if (checksum(packet.data(), IP_LEN) != 0) return false;

    // Verify UDP checksum using the IPv4 pseudo-header.
    std::vector<unsigned char> pseudo(12 + udp_size, 0);
    std::memcpy(pseudo.data(), packet.data() + 12, 8);
    pseudo[9] = IPPROTO_UDP;
    pseudo[10] = udp_size >> 8;
    pseudo[11] = udp_size & 0xff;

    std::memcpy(
        pseudo.data() + 12,
        packet.data() + udp_offset,
        udp_size
    );

    return checksum(pseudo.data(), pseudo.size()) == 0;
}

int main() {
    // Example DNS message bytes for test construction only.
    // Replace this with the output of your DNS response builder.
    const std::vector<unsigned char> dns = {
        0x12, 0x34, 0x81, 0x80,
        0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x07, 'e','x','a','m','p','l','e',
        0x03, 'c','o','m', 0x00,
        0x00, 0x01, 0x00, 0x01,
        0xc0, 0x0c,
        0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x01, 0x2c,
        0x00, 0x04,
        192, 0, 2, 25
    };

    auto packet = build_test_ipv4_udp_packet(
        dns,
        "192.0.2.53",
        "192.0.2.10"
    );

    if (packet.empty()) {
        std::cerr << "Packet construction failed\n";
        return 1;
    }

    std::cout << "Constructed IPv4 packet: "
              << packet.size() << " bytes\n";

    std::cout << "Validation: "
              << (validate_test_packet(packet) ? "PASS" : "FAIL")
              << '\n';

    return validate_test_packet(packet) ? 0 : 1;
}
