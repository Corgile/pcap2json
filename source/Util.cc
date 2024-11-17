//
// pcap2json / util.cc
// Created by brian on 2024-11-14.
//
#include <fstream>
#include <pcap/pcap.h>

#include <github/mcmtroffaes/inipp.hh>
#include <github/taywee/args.hh>

#include <pcap2json/pcap2json.hh>

namespace util {
void ParseArguments(int const argc, char* argv[]) {
  using string_tag = args::ValueFlag<std::string>;
  args::ArgumentParser parser{ "pcap2json", "made by xhl." };
  string_tag profile{ parser, "", ".ini配置文件", { 'p', "profile" }, "./" };
  args::HelpFlag help{ parser, "help", "程序用法说明", { 'h', "help" } };
  fs::path profilePath;
  try {
    parser.ParseCLI(argc, argv);
    profilePath.assign(args::get(profile));
  } catch (args::Help&) {
    std::cout << parser;
    exit(EXIT_SUCCESS);
  } catch (args::ParseError& e) {
    std::cerr << e.what() << std::endl;
    std::cerr << parser;
    exit(EXIT_FAILURE);
  } catch (args::ValidationError& e) {
    std::cerr << e.what() << std::endl;
    std::cerr << parser;
    exit(EXIT_FAILURE);
  }
  if (not fs::is_regular_file(profilePath)) {
    profilePath = fs::current_path() / "profile.ini";
  }
  if (not fs::exists(profilePath)) {
    XLOG_WARN << "配置文件" << profilePath.string() << "不存在.";
    exit(EXIT_FAILURE);
  }
  ReadProfile(profilePath);
  XLOG_DEBUG << "当前程序运行参数： \n" << glb::argument;
}

void ReadProfile(fs::path const& profilePath) {
  inipp::Ini<char> ini;
  std::ifstream is{ profilePath, std::ios::in };
  ini.parse(is);
  ini.strip_trailing_comments();
  inipp::Ini<char>::Section sec{ ini.sections["Arguments"] };
  inipp::get_value(sec, "dtype", glb::argument.type_);
  inipp::get_value(sec, "json_pretty", glb::argument.pretty_);
  inipp::get_value(sec, "fill_value", glb::argument.fill_val_);
  inipp::get_value(sec, "payload", glb::argument.payload_);
  inipp::get_value(sec, "threads", glb::argument.threads_);
  inipp::get_value(sec, "filter", glb::argument.filter_);
  inipp::get_value(sec, "inputs", glb::argument.inputs_);
  inipp::get_value(sec, "output", glb::argument.output_);

  glb::argument.fill_val_ = std::stoi(util::Convert(glb::argument.fill_val_));

  if (not glb::type_map.contains(glb::argument.type_)) {
    XLOG_WARN << "不支持的 `as_type`参数: " << glb::argument.type_
              << ", 已Fallback为 uint8_t";
    glb::argument.type_ = "uint8_t";
  }
}

auto GetAllPcapFiles(fs::path const& dir) -> std::list<fs::path> {
  std::list<fs::path> pcaps;
  for (auto const& entry : fs::directory_iterator{ dir }) {
    if (not entry.is_regular_file()) continue;
    auto ext{ entry.path().extension().string() };
    if (ext not_eq ".pcap" and ext not_eq ".pcapng") continue;
    fs::path abs_path{ absolute(entry) };
    XLOG_DEBUG << "添加" << ext << "文件: " << abs_path.string();
    pcaps.emplace_back(abs_path);
  }
  return pcaps;
}

void DumpPcapToJson(fs::path const& file) {
  if (not fs::exists(file)) {
    XLOG_WARN << file << "不存在.";
    return;
  }
  using open_offline = pcap_t* (*)(const char*, u_int, char*);
  open_offline const open_func{ pcap_open_offline_with_tstamp_precision };
  std::array<char, PCAP_ERRBUF_SIZE> err_buff{};
  // PCAP_TSTAMP_PRECISION_MICRO, PCAP_TSTAMP_PRECISION_NANO
  auto const handle{ open_func(file.c_str(), 0, err_buff.data()) };
  auto guard{ [](pcap_t* h) { pcap_close(h); } };
  std::unique_ptr<pcap_t, decltype(guard)> handle_ptr{ handle, guard };
  if (not handle) {
    XLOG_ERROR << "文件" << file.string() << "无法打开: " << err_buff.data();
    return;
  }
  JsonDumper dumper{ file };
  pcap_loop(handle, -1, PacketHandler, reinterpret_cast<u_char*>(&dumper));
}

void PacketHandler(u_char* uData, meta_data_t const meta,
                   pcap_data_t const packet) {
  auto const dumper{ reinterpret_cast<JsonDumper*>(uData) };
  // 在dumper对象内部对这些数据进行集中地、多线程地处理
  dumper->Emplace(meta, packet);
}

auto TimeValToTimePoint(timeval const& tv) -> time_point_t {
  std::chrono::seconds const seconds{ tv.tv_sec };
  std::chrono::microseconds const microseconds{ tv.tv_usec };
  return time_point_t{ seconds + microseconds };
}


} // namespace util
