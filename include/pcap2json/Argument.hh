//
// pcap2json / Argument.hh
// Created by brian on 2024-11-14.
//
#pragma once

#include <filesystem>
#include <list>
#include <ostream>
#include <string>

#include <pcap2json/Macros.hh>
#include <pcap2json/Using.hh>

struct Argument {
  bool pretty_{ false };
  int32_t fill_val_{ 0 }; // 填充
  int32_t payload_{ 0 };  // payload多少字节
  int32_t threads_{ 0 };  // 多少个线程

  std::string inputs_{}; // pcap文件/目录
  std::string type_;     // 转换类型
  std::string output_{}; // 输出文件名pattern
  std::string filter_{}; // packet filter

  Argument();

  Argument& operator=(Argument&& other) noexcept;

  Argument(Argument&& other) noexcept;

  Argument& operator=(Argument const& other) = delete;
  Argument(Argument const& other)            = delete;

  friend std::ostream& operator<<(std::ostream& os, Argument const& obj);

  ND auto PcapFiles() const -> std::list<fs::path>;

  /// 处理离线数据的话 不需要加上4字节vlan头部
  ND auto LenAfter() const -> size_t;
  /// 抓包在线数据的话, 数据长度需要保留到前payload个字节
  /// 算下来应该是ether_header+vlan+ip_header+tcp/udp_header+payload
  ND auto LenCapture() const -> size_t;
};
