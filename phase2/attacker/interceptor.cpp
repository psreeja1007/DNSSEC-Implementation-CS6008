
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>

#pragma pack(push, 1)
struct DnsHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};
#pragma pack(pop)

static const char* CAPTURE_IFACE = "eth0";
static const char* BPF_FILTER = "udp port 53";
class PcapSession {
public:
    explicit PcapSession(const char* iface) {
        char errbuf[PCAP_ERRBUF_SIZE]{};

        handle = pcap_open_live(
            iface, BUFSIZ, 1, 1000, errbuf
        );

        if (!handle) {
            throw std::runtime_error(
                std::string("pcap_open_live(") + iface + "): " + errbuf
            );
        }

        if (pcap_datalink(handle) != DLT_EN10MB) {
            const int datalink = pcap_datalink(handle);
            pcap_close(handle);
            handle = nullptr;
            throw std::runtime_error(
                "unsupported capture link type " +
                std::to_string(datalink) +
                " (expected Ethernet)"
            );
        }

        bpf_program filter{};

        if (pcap_compile(
                handle, &filter, BPF_FILTER, 1,
                PCAP_NETMASK_UNKNOWN) < 0) {
            std::string error = pcap_geterr(handle);
            pcap_close(handle);
            handle = nullptr;
            throw std::runtime_error(
                std::string("pcap_compile(") + BPF_FILTER + "): " + error
            );
        }

        if (pcap_setfilter(handle, &filter) < 0) {
            std::string error = pcap_geterr(handle);
            pcap_freecode(&filter);
            pcap_close(handle);
            handle = nullptr;
            throw std::runtime_error("pcap_setfilter: " + error);
        }

        pcap_freecode(&filter);
        std::cout << "[interceptor] capture interface: " << iface
                  << " (Ethernet), filter: " << BPF_FILTER << '\n';
    }

    ~PcapSession() {
        if (handle) {
            pcap_close(handle);
        }
    }

    pcap_t* get() const {
        return handle;
    }

    bool relay(const u_char* packet, int length) {
        return pcap_inject(handle, packet, length) == length;
    }

private:
    pcap_t* handle = nullptr;
};

enum class Mode {
    NormalRelay,
    InterceptMonitor
};

struct HandlerContext {
    PcapSession* session;
    Mode mode;
};

// Parse an uncompressed DNS QNAME safely.
// Returns false for malformed packets or compressed QNAMEs.
static bool extract_qname(
    const u_char* dns, int length, std::string& result
) {
    if (!dns || length < static_cast<int>(sizeof(DnsHeader))) {
        return false;
    }

    const auto* header =
        reinterpret_cast<const DnsHeader*>(dns);

    if (ntohs(header->qdcount) == 0) {
        return false;
    }

    size_t pos = sizeof(DnsHeader);
    result.clear();

    while (pos < static_cast<size_t>(length)) {
        uint8_t label_len = dns[pos++];

        if (label_len == 0) {
            return !result.empty();
        }

        // Compression pointers and invalid label lengths.
        if ((label_len & 0xC0) != 0 || label_len > 63) {
            return false;
        }

        if (pos + label_len >
            static_cast<size_t>(length)) {
            return false;
        }

        if (!result.empty()) {
            result += '.';
        }

        for (unsigned i = 0; i < label_len; ++i) {
            unsigned char c = dns[pos++];

            if (c >= 'A' && c <= 'Z') {
                c = static_cast<unsigned char>(
                    c - 'A' + 'a'
                );
            }

            result += static_cast<char>(c);
        }

        if (result.size() > 253) {
            return false;
        }
    }

    return false;
}

static void packet_handler(
    u_char* user,
    const pcap_pkthdr* packet_header,
    const u_char* packet
) {
    auto* context = reinterpret_cast<HandlerContext*>(user);

    const size_t ethernet_len = sizeof(ether_header);

    if (packet_header->caplen <
        ethernet_len + sizeof(struct ip)) {
        return;
    }

    const auto* eth =
        reinterpret_cast<const ether_header*>(packet);

    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        return;
    }

    const auto* ip = reinterpret_cast<const struct ip*>(
        packet + ethernet_len
    );

    const size_t ip_len = static_cast<size_t>(ip->ip_hl) * 4;

    if (ip->ip_v != 4 || ip_len < sizeof(struct ip) ||
        packet_header->caplen < ethernet_len + ip_len) {
        return;
    }

    if (ip->ip_p != IPPROTO_UDP ||
        ntohs(ip->ip_off) & (IP_MF | IP_OFFMASK)) {
        return;
    }

    const size_t udp_offset = ethernet_len + ip_len;

    if (packet_header->caplen <
        udp_offset + sizeof(struct udphdr)) {
        return;
    }

    const auto* udp = reinterpret_cast<const struct udphdr*>(
        packet + udp_offset
    );

    if (ntohs(udp->uh_sport) != 53 &&
        ntohs(udp->uh_dport) != 53) {
        return;
    }

    const size_t dns_offset =
        udp_offset + sizeof(struct udphdr);

    const size_t captured_len =
        packet_header->caplen - dns_offset;

    const size_t udp_len = ntohs(udp->uh_ulen);

    if (udp_len < sizeof(struct udphdr) ||
        udp_len - sizeof(struct udphdr) > captured_len ||
        udp_len - sizeof(struct udphdr) <
            sizeof(DnsHeader)) {
        return;
    }

    const int dns_len = static_cast<int>(
        udp_len - sizeof(struct udphdr)
    );

    std::string qname;

    if (extract_qname(packet + dns_offset, dns_len, qname)) {
        std::cout
            << "[interceptor] DNS packet: "
            << qname
            << " | source=" << inet_ntoa(ip->ip_src)
            << " | destination=" << inet_ntoa(ip->ip_dst)
            << '\n';
    } else {
        std::cout << "[interceptor] DNS packet with unreadable question"
                  << " | source=" << inet_ntoa(ip->ip_src)
                  << " | destination=" << inet_ntoa(ip->ip_dst)
                  << '\n';
    }

    if (context->mode == Mode::InterceptMonitor) {
        return;
    }

    // Normal mode relays the captured packet without changing its contents.
    if (!context->session->relay(packet, packet_header->caplen)) {
        std::cerr << "[interceptor] relay failed: "
                  << pcap_geterr(context->session->get())
                  << '\n';
    }
}

int main(int argc, char** argv) {
    std::string mode = (argc > 1) ? argv[1] : "normal";

    if (mode != "normal" && mode != "intercept") {
        std::cerr << "Usage: ./interceptor [normal|intercept]\n"
                  << "  normal: capture and relay DNS packets unchanged\n"
                  << "  intercept: observe DNS packets without relaying "
                  << "or modifying them\n";
        return 1;
    }

    const Mode selected_mode = mode == "normal"
        ? Mode::NormalRelay
        : Mode::InterceptMonitor;

    try {
        PcapSession session(CAPTURE_IFACE);
        HandlerContext context{&session, selected_mode};
        if (selected_mode == Mode::NormalRelay) {
            std::cout << "[interceptor] normal mode; DNS packets are "
                      << "relayed unchanged\n";
        } else {
            std::cout << "[interceptor] intercept mode; monitoring only, "
                      << "DNS packets are neither relayed nor modified. "
                      << "Resolver replies routed through this container "
                      << "will be dropped, so DNS lookups may time out.\n";
        }

        const int result = pcap_loop(
            session.get(),
            0,
            packet_handler,
            reinterpret_cast<u_char*>(&context)
        );

        if (result == -1) {
            throw std::runtime_error(
                std::string("pcap_loop: ") +
                pcap_geterr(session.get())
            );
        }

        pcap_stat stats{};
        if (pcap_stats(session.get(), &stats) == 0) {
            std::cout << "[interceptor] capture stats: received="
                      << stats.ps_recv << ", dropped=" << stats.ps_drop
                      << ", interface_dropped=" << stats.ps_ifdrop << '\n';
        } else {
            std::cerr << "[interceptor] unable to read capture stats: "
                      << pcap_geterr(session.get()) << '\n';
        }
    } catch (const std::exception& e) {
        std::cerr << "[interceptor] fatal: "
                  << e.what() << '\n';
        return 1;
    }

    return 0;
}
