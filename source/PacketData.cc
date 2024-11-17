//
// pcap2json / PacketData.cc
// Created by brian on 2024-11-17.
//

#include <pcap2json/pcap2json.hh>

PacketData::PacketData(meta_data_t const meta, pcap_data_t const pcap)
    : meta_{ meta->ts, meta->caplen, meta->len }
    , pcap_{ pcap, glb::argument.LenCapture() }
    , empty_{ false } {
  ProcessEther(pcap_.data());
}

PacketData::~PacketData() { XLOG_TRACE << __PRETTY_FUNCTION__; }

nlohmann::json PacketData::Json() const {
  nlohmann::json json;
  std::stringstream ss;
  ss << addr_src_ << ":" << port_src_ << " -> " << addr_dst_ << ":"
     << port_dst_;

  json["addr_from"]    = addr_src_;
  json["addr_to"]    = addr_dst_;
  json["datetime"]    = DateTime();
  json["direction"]   = ss.str();
  json["port_src"]    = port_src_;
  json["port_dst"]    = port_dst_;
  json["portion_len"] = meta_.caplen;
  json["packet_len"]  = meta_.len;
  json["packet_data"] = UBytes();
  json["timestamp"]   = Timestamp();
  json["time.sec"]    = meta_.ts.tv_sec;
  json["time.usec"]   = meta_.ts.tv_usec;
  return json;
}

std::string PacketData::DateTime() const {
  time_point_t const point{ util::TimeValToTimePoint(meta_.ts) };
  auto const duration{ point.time_since_epoch() };
  using ms_t = std::chrono::milliseconds;
  auto const millis{ std::chrono::duration_cast<ms_t>(duration) % 1000 };

  std::time_t const timeT{ std::chrono::system_clock::to_time_t(point) };
  std::tm const tm{ *std::localtime(&timeT) };

  std::ostringstream oss;
  oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
  oss << "." << std::setfill('0') << std::setw(3) << millis.count();
  return oss.str();
}

std::string PacketData::UBytes() const {
  auto const bitCount{ glb::argument.LenAfter() << 3 };
  auto const stride{ glb::stride_map.at(glb::argument.type_) };

  std::stringstream ss;
  size_t bitOffset = 0; // 当前 bit 偏移

  while (bitOffset < bitCount) {
    uint64_t value = 0; // 每组的值
    for (size_t bitsRead{ 0 }; bitsRead < stride and bitOffset < bitCount;) {
      size_t const byteIndex{ bitOffset >> 3 };
      size_t const bitIndex{ bitOffset & 0x7 };
      size_t const restBits{ std::min(stride - bitsRead, 8 - bitIndex) };
      uint64_t const mask{ ((1ULL << restBits) - 1) << bitIndex };
      value |= (ubytes_[byteIndex] & mask) >> bitIndex << bitsRead;
      bitsRead += restBits;
      bitOffset += restBits;
    }
    ss << util::Convert(value);
    if (bitOffset < bitCount) { ss << ","; }
  }

  return ss.str();
}

long PacketData::Timestamp() const {
  time_point_t const point{ util::TimeValToTimePoint(meta_.ts) };
  using sec_t = std::chrono::seconds;
  return std::chrono::duration_cast<sec_t>(point.time_since_epoch()).count();
}

void PacketData::ProcessEther(u_char const* start) {
  auto eth{ reinterpret_cast<ether_header const*>(start) };
  if (ntohs(eth->ether_type) == ETHERTYPE_VLAN) {
    start += static_cast<int>(sizeof(vlan_header));
    eth = reinterpret_cast<ether_header const*>(start);
  }
  auto const ether_type{ ntohs(eth->ether_type) };
  if (ether_type not_eq ETHERTYPE_IPV4) {
    if (ether_type == ETHERTYPE_IPV6) {
      XLOG_TRACE << "ETHER TYPE: IPV6";
    } else {
      XLOG_TRACE << "ETHER TYPE 不是 IPV4/6";
    }
    empty_ = true;
    return;
  }
  constexpr int offset{ sizeof(ether_header) };
  ProcessIPv4(start + offset);
}

void PacketData::ProcessIPv4(u_char const* start) {
  auto const ipv4_data = reinterpret_cast<ip const*>(start);
  protocol_            = static_cast<int>(ipv4_data->ip_p);
  empty_ = protocol_ not_eq IPPROTO_UDP and protocol_ not_eq IPPROTO_TCP;
  if (empty_) {
    XLOG_TRACE << "传输层协议类型不是TCP/UDP";
    return;
  }

  in_addr ad1{ ipv4_data->ip_src }, ad2{ ipv4_data->ip_dst };
  addr_src_ = inet_ntoa(ad1);
  addr_dst_ = inet_ntoa(ad2);
  if (ad1.s_addr > ad2.s_addr) { std::swap(ad1, ad2); }
  key_.append(inet_ntoa(ad1)).append("_").append(inet_ntoa(ad2)).append("_");

  uint32_t const ipv4HL{ ipv4_data->ip_hl * 4 };
  ubytes_.append(start, ipv4HL);

  if (ipv4HL < 60) [[likely]] {
    ubytes_.append(60 - ipv4HL, glb::argument.fill_val_);
  }

  if (protocol_ == IPPROTO_TCP) {
    const auto tcph{ reinterpret_cast<tcphdr const*>(start + ipv4HL) };
    const int len{ tcph->doff * 4 };
    ubytes_.append(start + ipv4HL, len);
    const auto padding{ 60 - len };
    if (padding > 0) [[likely]] {
      ubytes_.append(padding, glb::argument.fill_val_);
    }
    ubytes_.append(8, glb::argument.fill_val_);
    CopyPayloadToBlob<tcphdr>(ipv4_data, start + ipv4HL, "_TCP", len);
  }
  if (protocol_ == IPPROTO_UDP) {
    ubytes_.append(start + ipv4HL, 8).append(60, glb::argument.fill_val_);
    CopyPayloadToBlob<udphdr>(ipv4_data, start + ipv4HL, "_UDP", 8);
  }
  if (ubytes_.size() not_eq glb::argument.LenAfter()) {
    XLOG_WARN << "ubytes_.size() = " << ubytes_.size(); // 128
  }
}

std::ostream& operator<<(std::ostream& os, PacketData const& obj) {
  os << obj.Json();
  return os;
}
