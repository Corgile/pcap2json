//
// pcap2json / Argument.cc
// Created by brian on 2024-11-19.
//
#include <pcap2json/pcap2json.hh>

Argument::Argument() = default;
Argument& Argument::operator=(Argument&& other) noexcept {
  if (this == &other) return *this;
  pretty_   = other.pretty_;
  fill_val_ = other.fill_val_;
  payload_  = other.payload_;
  threads_  = other.threads_;
  inputs_   = std::move(other.inputs_);
  type_     = std::move(other.type_);
  output_   = std::move(other.output_);
  filter_   = std::move(other.filter_);
  return *this;
}

Argument::Argument(Argument&& other) noexcept
    : pretty_{ other.pretty_ }
    , fill_val_{ other.fill_val_ }
    , payload_{ other.payload_ }
    , threads_{ other.threads_ }
    , inputs_{ std::move(other.inputs_) }
    , type_{ std::move(other.type_) }
    , output_{ std::move(other.output_) }
    , filter_{ std::move(other.filter_) } {}

auto Argument::PcapFiles() const -> std::list<fs::path> {
  static std::list<fs::path> paths;
  if (not paths.empty()) { return paths; }
  std::string entry;
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

auto Argument::LenAfter() const -> size_t {
  return payload_ + 128; // payload, ip/tcp/udp
}

auto Argument::LenCapture() const -> size_t {
  return LenAfter() + 4 + sizeof(ether_header);
}

std::ostream& operator<<(std::ostream& os, Argument const& obj) {
  os << std::boolalpha;
  os << "\t json_pretty: " << obj.pretty_ << '\n';
  os << "\t fill_value: " << obj.fill_val_ << " (" << obj.type_ << ")\n";
  os << "\t payload: " << obj.payload_ << '\n';
  os << "\t threads: " << obj.threads_ << '\n';
  os << "\t filter: " << obj.filter_ << '\n';
  os << "\t output: " << obj.output_ << '\n';
  os << "\t inputs: （展开）\n";
  for (auto const& file : obj.PcapFiles()) {
    os << "\t\t- " << file.filename().string() << '\n';
  }
  return os;
}
