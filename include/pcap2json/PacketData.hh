//
// pcap2json / PacketData.hh
// Created by brian on 2024-11-17.
//

#ifndef PACKETDATA_HH
#define PACKETDATA_HH

#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <ostream>

#include <pcap/pcap.h>

#include <github/nlohmann/json.hh>
#include <pcap2json/Using.hh>
#include <pcap2json/Global.hh>

#define ETHERTYPE_IPV4 ETHERTYPE_IP

struct vlan_header {
  uint16_t vlan;
  uint16_t etherType;
} __attribute__((__packed__));

struct PacketData {

  /// @brief 将元数据和字节数据一并复制一份
  PacketData(meta_data_t meta, pcap_data_t pcap);
  ~PacketData();
  ND auto Empty() const -> bool { return empty_; }
  ND auto Key() const -> std::string_view { return key_; }
  ND nlohmann::json Json() const;

  friend std::ostream& operator<<(std::ostream& os, PacketData const& obj);

private:
  ND std::string DateTime() const;
  ND std::string UBytes() const;
  ND long Timestamp() const;

  void ProcessEther(u_char const* start);

  void ProcessIPv4(u_char const* start);

  template <typename HeaderType>
  void CopyPayloadToBlob(ip const* ipv4, u_char const* trans_header,
                         std::string_view suffix, int const data_offset) {
    auto const* pHeaderType = reinterpret_cast<HeaderType const*>(trans_header);
    auto port1{ ::ntohs(pHeaderType->source) };
    auto port2{ ::ntohs(pHeaderType->dest) };
    port_src_ = port1;
    port_dst_ = port2;

    if (port1 > port2) { std::swap(port1, port2); }

    key_.append(std::to_string(port1))
      .append("_")
      .append(std::to_string(port2))
      .append(suffix);
    // payload
    const int available = ntohs(ipv4->ip_len) - ipv4->ip_hl * 4 - data_offset;
    size_t const payload_len =
      std::min(std::max(available, 0), glb::argument.payload_);
    ubytes_.append(&trans_header[data_offset], payload_len);
    int const padding{ (int)glb::argument.LenAfter() - (int)ubytes_.size() };
    if (padding > 0) [[unlikely]] {
      ubytes_.append(padding, glb::argument.fill_val_);
    }
  }

private: // NOLINT 解析前
  pcap_pkthdr meta_;
  ustring_t pcap_;

private: // NOLINT 解析后
  bool empty_;
  uint8_t protocol_{};
  uint16_t port_src_{};
  uint16_t port_dst_{};

  ustring_t ubytes_;

  std::string key_;
  std::string addr_src_;
  std::string addr_dst_;
  // std::string timestamp_;
  // std::string packet_len_;
};

using packet_data_t = std::shared_ptr<PacketData>;

#endif //PACKETDATA_HH
