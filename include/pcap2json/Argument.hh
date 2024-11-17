//
// pcap2json / Argument.hh
// Created by brian on 2024-11-14.
//
#pragma once

#include <filesystem>
#include <list>
#include <ostream>
#include <sstream>
#include <string>

#include <pcap2json/Macros.hh>
#include <pcap2json/util.hh>
#include <xlog/api.hh>

namespace fs = std::filesystem;

struct Argument {
  bool ipv4_{ false };   // 是否包含ipv4
  bool ipv6_{ false };   // 是否包含ipv6
  bool vlan_{ false };   // 是否包含vlan
  bool key_{ false };    // 是否包含五元组信息
  bool time_{ false };   // 是否包含时间戳
  bool length_{ false }; // 是否包含报文的总长度

  int32_t fill_val_{ 0 }; // 填充
  int32_t min_pkt_{ 0 };  // 最小packet数
  int32_t max_pkt_{ 0 };  // 最大packet数
  int32_t stride_{ 0 };   // 转10进制的步长
  int32_t payload_{ 0 };  // payload多少字节
  int32_t threads_{ 0 };  // 多少个线程

  std::string inputs_{};   // pcap文件/目录
  std::string key_fmt_{};  // 五元组格式
  std::string time_fmt_{}; // 时间格式
  std::string type_;       // 转换类型
  std::string output_{};   // 输出文件名pattern
  std::string filter_{};   // packet filter

  Argument() = default;

  Argument& operator=(Argument&& other) noexcept {
    if (this == &other) return *this;
    ipv4_     = other.ipv4_;
    ipv6_     = other.ipv6_;
    vlan_     = other.vlan_;
    key_      = other.key_;
    time_     = other.time_;
    length_   = other.length_;
    fill_val_ = other.fill_val_;
    min_pkt_  = other.min_pkt_;
    max_pkt_  = other.max_pkt_;
    stride_   = other.stride_;
    payload_  = other.payload_;
    threads_  = other.threads_;
    inputs_   = std::move(other.inputs_);
    type_     = std::move(other.type_);
    output_   = std::move(other.output_);
    filter_   = std::move(other.filter_);
    return *this;
  }

  Argument(Argument&& other) noexcept
      : ipv4_{ other.ipv4_ }
      , ipv6_{ other.ipv6_ }
      , vlan_{ other.vlan_ }
      , key_{ other.key_ }
      , time_{ other.time_ }
      , length_{ other.length_ }
      , fill_val_{ other.fill_val_ }
      , min_pkt_{ other.min_pkt_ }
      , max_pkt_{ other.max_pkt_ }
      , stride_{ other.stride_ }
      , payload_{ other.payload_ }
      , threads_{ other.threads_ }
      , inputs_{ std::move(other.inputs_) }
      , type_{ std::move(other.type_) }
      , output_{ std::move(other.output_) }
      , filter_{ std::move(other.filter_) } {}

  Argument& operator=(Argument const& other) = delete;
            Argument(Argument const& other)  = delete;

  friend std::ostream& operator<<(std::ostream& os, Argument const& obj) {
    os << std::boolalpha;
    os << "\t include:\n";
    if (obj.ipv4_) os << "\t\t- ipv4\n";
    if (obj.ipv6_) os << "\t\t- ipv6\n";
    if (obj.vlan_) os << "\t\t- vlan\n";
    if (obj.length_) os << "\t\t- length\n";
    if (obj.key_) {
      os << "\t\t- key: " << obj.key_fmt_ << '\n';
    }
    if (obj.time_) {
      os << "\t\t- timestamp: " << obj.time_fmt_ << '\n';
    }
    os << "\t stride: " << obj.stride_ << '\n'                             //
       << "\t fill_value: " << obj.fill_val_ << " (" << obj.type_ << ")\n" //
       << "\t min_pkt: " << obj.min_pkt_ << '\n'                           //
       << "\t max_pkt: " << obj.max_pkt_ << '\n'                           //
       << "\t payload: " << obj.payload_ << '\n'                           //
       << "\t threads: " << obj.threads_ << '\n'                           //
       << "\t filter: " << obj.filter_ << '\n'                             //
       << "\t output: " << obj.output_ << '\n'                             //
       << "\t inputs: （展开）\n";                                         //
    for (auto const& file : obj.PcapFiles()) {
      os << "\t\t- " << file.filename().string() << '\n';
    }
    return os;
  }

  ND std::list<fs::path> PcapFiles() const {
    static std::list<fs::path> paths;
    if (not paths.empty()) { return paths; }
    std::string       entry;
    std::stringstream ss{ inputs_ };
    while (std::getline(ss, entry, ',')) {
      auto const abs_path{ fs::absolute(entry) };
      bool const is_dir{ fs::is_directory(abs_path) };
      bool const is_file{ fs::is_regular_file(abs_path) };
      if (not(is_dir or is_file)) { continue; }
      if (is_file) {
        auto const ext{ abs_path.extension().string() };
        if (ext == ".pcap" or ext == ".pcapng") {
          paths.emplace_back(abs_path);
          XLOG_DEBUG << "添加" << ext << "文件: " << abs_path.string();
        }
      } else {
        auto const pcap_files{ util::GetAllPcapFiles(abs_path) };
        paths.insert(paths.end(), pcap_files.begin(), pcap_files.end());
      }
    }
    if (paths.empty()) {
      XLOG_WARN << "No files given, quit.";
      exit(EXIT_FAILURE);
    }
    return paths;
  }

};
