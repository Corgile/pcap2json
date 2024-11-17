//
// pcap2json / util.cc
// Created by brian on 2024-11-14.
//
#include <fstream>
#include <github/mcmtroffaes/inipp.hh>
#include <github/taywee/args.hh>

#include <pcap2json/common.hh>
#include <pcap2json/util.hh>

namespace util {
void ParseArguments(int const argc, char* argv[]) {
  using string_tag = args::ValueFlag<std::string>;
  args::ArgumentParser parser{ "pcap2json", "made by xhl." };
  string_tag profile{ parser, "", ".ini配置文件", { 'p', "profile" }, "./" };
  args::HelpFlag help{ parser, "help", "程序用法说明", { 'h', "help" } };
  fs::path       profilePath;
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
  ReadConfig(profilePath);
  XLOG_DEBUG << "当前程序运行参数： \n" << glb::argument;
}

void ReadConfig(fs::path const& profilePath) {
  inipp::Ini<char> ini;
  std::ifstream    is{ profilePath, std::ios::in };
  ini.parse(is);
  ini.strip_trailing_comments();
  inipp::Ini<char>::Section sec{ ini.sections["Arguments"] };
  inipp::get_value(sec, "include.ipv4", glb::argument.ipv4_);
  inipp::get_value(sec, "include.ipv6", glb::argument.ipv6_);
  inipp::get_value(sec, "include.vlan", glb::argument.vlan_);
  inipp::get_value(sec, "include.length", glb::argument.length_);
  inipp::get_value(sec, "include.key", glb::argument.key_);
  inipp::get_value(sec, "include.time", glb::argument.time_);
  inipp::get_value(sec, "key.pattern", glb::argument.key_fmt_);
  inipp::get_value(sec, "time.format", glb::argument.time_fmt_);
  inipp::get_value(sec, "stride", glb::argument.stride_);
  inipp::get_value(sec, "convert_type", glb::argument.type_);
  inipp::get_value(sec, "fill_value", glb::argument.fill_val_);
  inipp::get_value(sec, "min_pkt", glb::argument.min_pkt_);
  inipp::get_value(sec, "max_pkt", glb::argument.max_pkt_);
  inipp::get_value(sec, "payload", glb::argument.payload_);
  inipp::get_value(sec, "threads", glb::argument.threads_);
  inipp::get_value(sec, "filter", glb::argument.filter_);
  inipp::get_value(sec, "inputs", glb::argument.inputs_);
  inipp::get_value(sec, "output", glb::argument.output_);
}

std::list<fs::path> GetAllPcapFiles(fs::path const& dir) {
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


} // namespace util
