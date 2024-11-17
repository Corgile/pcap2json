//
// pcap2json / global.cc
// Created by brian on 2024-11-14.
//
#include <pcap2json/pcap2json.hh>

namespace glb {
Argument argument{};

std::unordered_map<std::string, type_t> type_map{
  { "uint8_t", uint8_t{} },   { "uint16_t", uint16_t{} },
  { "uint32_t", uint32_t{} }, { "uint64_t", uint64_t{} },
  { "int8_t", int8_t{} },     { "int16_t", int16_t{} },
  { "int32_t", int32_t{} },   { "int64_t", int64_t{} },
};

std::unordered_map<std::string, int> stride_map{
  { "uint8_t", 8 }, { "uint16_t", 16 }, { "uint32_t", 32 }, { "uint64_t", 64 },
  { "int8_t", 8 },  { "int16_t", 16 },  { "int32_t", 32 },  { "int64_t", 64 },
};
} // namespace glb
