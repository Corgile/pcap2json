//
// pcap2json / JsonDumper.hh
// Created by brian on 2024-11-17.
//

#ifndef JSONDUMPER_HH
#define JSONDUMPER_HH

#include <list>
#include <map>
#include <thread>
#include <vector>

#include <pcap2json/PacketData.hh>
#include <pcap2json/Using.hh>
#include <pcap2json/ThreadPool.hh>

class JsonDumper {
public:
  explicit JsonDumper(fs::path file);
  ~JsonDumper();
  void Emplace(meta_data_t meta, pcap_data_t pcap);

private:
  void DumpFile();
  std::vector<std::thread> workers_;
  std::mutex mtx_;
  std::map<std::string_view, std::list<packet_data_t>> flows_;
  fs::path file_;
  ThreadPool pool_;

};

#endif // JSONDUMPER_HH
