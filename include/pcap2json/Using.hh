//
// pcap2json / Using.hh
// Created by brian on 2024-11-17.
//

#ifndef USING_HH
#define USING_HH

#include <pcap/pcap.h>
#include <string>
#include <variant>

namespace fs       = std::filesystem;
using meta_data_t  = pcap_pkthdr const*;
using pcap_data_t  = u_char const*;
using ustring_t    = std::basic_string<u_char>;
using time_point_t = std::chrono::system_clock::time_point;
using type_t = std::variant<uint8_t, uint16_t, uint32_t, uint64_t, int8_t,
                            int16_t, int32_t, int64_t>;

#endif // USING_HH
