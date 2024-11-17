//
// pcap2json / JsonDumper.cc
// Created by brian on 2024-11-17.
//

#include <pcap2json/pcap2json.hh>
#include <utility>

JsonDumper::JsonDumper(fs::path file)
    : file_{ std::move(file) } {
  workers_.reserve(glb::argument.threads_);
}

void JsonDumper::Emplace(meta_data_t const meta, pcap_data_t const pcap) {
  auto const data{ std::make_shared<PacketData>(meta, pcap) };
  if (data->Empty()) return;
  auto const key{ data->Key() };
  auto& packet_list{ flows_[key] };
  packet_list.emplace_back(data);
}

JsonDumper::~JsonDumper() {
  fs::path const json_file{ file_.replace_extension(".json") };
  std::ofstream ff{ json_file, std::ios::out };
  nlohmann::json json;
  for (auto& [key, data] : flows_) {
    nlohmann::json obj;
    obj["key"]   = key;
    obj["count"] = data.size();
    for (auto const& ptr : data) { obj["packet"].emplace_back(ptr->Json()); }
    json.emplace_back(obj);
  }
  ff << json.dump(glb::argument.pretty_ ? 2 : -1);
  XLOG_INFO << "已写入文件: " << json_file;
}
