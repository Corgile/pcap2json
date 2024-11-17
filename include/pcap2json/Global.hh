//
// pcap2json / Global.hh
// Created by brian on 2024-11-19.
//

#pragma once
#include <pcap2json/Argument.hh>
#include <pcap2json/Using.hh>

namespace glb {
extern Argument argument;
extern std::unordered_map<std::string, type_t> type_map;
extern std::unordered_map<std::string, int> stride_map;
} // namespace glb
