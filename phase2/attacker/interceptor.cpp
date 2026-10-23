
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

struct EthernetHeader {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
};

struct DnsHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

static std::string read_dns_name(
    const unsigned char* dns,
    size_t dns_len,
    size_t& offset
) {
    std::string name;
    size_t pos = offset;
    size_t consumed = 0;
    bool jumped = false;
    size_t steps = 0;

    while (pos < dns_len && steps++ < dns_len) {
        uint8_t len = dns[pos];

        if (len == 0) {
            if (!jumped) consumed++;
            break;
        }

        if ((len & 0xC0) == 0xC0) {
            if (pos + 1 >= dns_len) return "<invalid>";

            size_t pointer =
                ((len & 0x3F) << 8) | dns[pos + 1];

            if (pointer >= dns_len) return "<invalid>";

            if (!jumped) consumed += 2;
            pos = pointer;
            jumped = true;
            continue;
        }

        if ((len & 0xC0) != 0 || pos + 1 + len > dns_len)
            return "<invalid>";

        if (!name.empty()) name += '.';

        name.append(
            reinterpret_cast<const char*>(dns + pos + 1), len
        );

        pos += 1 + len;
        if (!jumped) consumed += 1 + len;
    }

    if (consumed == 0) return "<invalid>";

    offset += consumed;
    return name.empty() ? "." : name;
}

static void packet_callback(
    unsigned char*,
    const pcap_pkthdr* header,
    const unsigned char* packet
) {
    if (header->caplen < sizeof(EthernetHeader)) return;

    const auto* eth =
        reinterpret_cast<const EthernetHeader*>(packet);

    if (ntohs(eth->type) != 0x0800) return;

    size_t offset = sizeof(EthernetHeader);

    if (header->caplen < offset + sizeof(iphdr)) return;

    const auto* ip =
        reinterpret_cast<const iphdr*>(packet + offset);

    if (ip->version != 4 || ip->protocol != IPPROTO_UDP)
        return;

    size_t ip_len = ip->ihl * 4;

    if (ip_len < sizeof(iphdr) ||
        header->caplen < offset + ip_len + sizeof(udphdr))
        return;

    const auto* udp =
        reinterpret_cast<const udphdr*>(packet + offset + ip_len);

    if (ntohs(udp->source) != 53 && ntohs(udp->dest) != 53)
        return;

    size_t dns_offset = offset + ip_len + sizeof(udphdr);

    if (header->caplen < dns_offset + sizeof(DnsHeader))
        return;

    const auto* dns =
        reinterpret_cast<const DnsHeader*>(packet + dns_offset);

    char src[INET_ADDRSTRLEN] = {};
    char dst[INET_ADDRSTRLEN] = {};

    inet_ntop(AF_INET, &ip->saddr, src, sizeof(src));
    inet_ntop(AF_INET, &ip->daddr, dst, sizeof(dst));

    std::cout << "\n[DNS packet]"
              << "\n  " << src << ':' << ntohs(udp->source)
              << " -> " << dst << ':' << ntohs(udp->dest)
              << "\n  DNS ID: " << ntohs(dns->id)
              << "\n  Type: "
              << ((ntohs(dns->flags) & 0x8000) ? "response" : "query")
              << "\n  Questions: " << ntohs(dns->qdcount);

    size_t dns_len = ntohs(udp->len) >= sizeof(udphdr)
        ? ntohs(udp->len) - sizeof(udphdr)
        : 0;

    if (dns_len >= sizeof(DnsHeader) &&
        header->caplen >= dns_offset + dns_len &&
        ntohs(dns->qdcount) > 0) {
        size_t qname_offset = sizeof(DnsHeader);
        std::string qname = read_dns_name(
            reinterpret_cast<const unsigned char*>(dns),
            dns_len,
            qname_offset
        );

        std::cout << "\n  Name: " << qname;

        if (qname_offset + 4 <= dns_len) {
            uint16_t qtype;
            std::memcpy(&qtype,
                        reinterpret_cast<const unsigned char*>(dns)
                            + qname_offset,
                        sizeof(qtype));

            std::cout << "\n  QTYPE: " << ntohs(qtype);
        }
    }

    std::cout << "\n  Captured bytes: " << header->caplen
              << std::endl;
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE] = {};

    pcap_t* handle = pcap_open_live(
        "eth0", 65535, 0, 100, errbuf
    );

    if (!handle) {
        std::cerr << "pcap_open_live failed: "
                  << errbuf << '\n';
        return 1;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        std::cerr << "Expected Ethernet packets on eth0\n";
        pcap_close(handle);
        return 1;
    }

    bpf_program filter{};

    if (pcap_compile(handle, &filter, "udp port 53", 1,
                     PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Filter compilation failed: "
                  << pcap_geterr(handle) << '\n';
        pcap_close(handle);
        return 1;
    }

    if (pcap_setfilter(handle, &filter) == -1) {
        std::cerr << "Setting filter failed: "
                  << pcap_geterr(handle) << '\n';
        pcap_freecode(&filter);
        pcap_close(handle);
        return 1;
    }

    pcap_freecode(&filter);

    // Capture incoming packets only to avoid logging our own
    // forwarded outgoing packets twice.
    if (pcap_setdirection(handle, PCAP_D_IN) == -1) {
        std::cerr << "Could not set capture direction: "
                  << pcap_geterr(handle) << '\n';
    }

    std::cout << "[attacker] Monitoring DNS on eth0\n";
    std::cout << "[attacker] Linux kernel handles forwarding\n";

    int result = pcap_loop(handle, -1, packet_callback, nullptr);

    if (result == -1) {
        std::cerr << "Capture failed: "
                  << pcap_geterr(handle) << '\n';
    }

    pcap_close(handle);
    return result == -1 ? 1 : 0;
}
