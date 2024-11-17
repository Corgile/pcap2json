//
// pcap2json / util.hh
// Created by brian on 2024-11-14.
//
#pragma once
#include <filesystem>
#include <pcap2json/Macros.hh>

namespace fs = std::filesystem;
namespace util {

void ParseArguments(int argc, char *argv[]);
void ReadConfig(fs::path const &profilePath);

ND std::list<fs::path> GetAllPcapFiles(fs::path const &dir);

} // namespace util
