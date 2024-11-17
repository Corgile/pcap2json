//
// pcap2json / Util.hh
// Created by brian on 2024-11-14.
//
#pragma once
#include <filesystem>
#include <list>

#include <pcap2json/Using.hh>
#include <pcap2json/Global.hh>

namespace util {

void ParseArguments(int argc, char* argv[]);
void ReadProfile(fs::path const& profilePath);
void DumpPcapToJson(fs::path const& file);
void PacketHandler(u_char* uData, meta_data_t meta, pcap_data_t packet);

auto GetAllPcapFiles(fs::path const& dir) -> std::list<fs::path>;
auto TimeValToTimePoint(timeval const& tv) -> time_point_t;

template <typename T>
void Order(T& t1, T& t2, std::function<bool()> const& less) {
  if (not less) { std::swap(t1, t2); }
}

template<typename Numeric>
auto Convert(Numeric value) -> std::string {
  const auto& target_type{ glb::type_map.at(glb::argument.type_) };
  std::ostringstream ss;
  std::visit(
    [&]<typename T>(T t) {
      if constexpr (std::is_same_v<T, uint8_t> or std::is_same_v<T, int8_t>) {
        ss << static_cast<int>(value);
      } else {
        ss << static_cast<T>(value);
      }
    },
    target_type);
  return ss.str();
}

} // namespace util
