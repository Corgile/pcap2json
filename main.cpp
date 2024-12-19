#include <pcap2json/pcap2json.hh>

int main(int const argc, char* argv[]) {
  xlog::InstantiateFileLogger(xlog::Level::DEBUG, "main.log");
  xlog::ToggleAsyncLogging(TOGGLE_ON);
  xlog::ToggleConsoleLogging(TOGGLE_ON);
  util::ParseArguments(argc, argv);

  std::vector<std::thread> threads;
  auto const concurrency{ std::thread::hardware_concurrency() / 8 + 1 };
  threads.reserve(concurrency);
  auto const files{ glb::argument.PcapFiles() };
  moodycamel::ConcurrentQueue<fs::path> queue;
  queue.enqueue_bulk(files.begin(), files.size());
  for (int i{ 0 }; i < concurrency; ++i) {
    threads.emplace_back([&] {
      while (queue.size_approx()) {
        fs::path pcap;
        bool const ok{ queue.try_dequeue(pcap) };
        if (not ok or pcap.empty()) { continue; }
        util::DumpPcapToJson(pcap);
      }
    });
  }
  for (auto& t : threads) { t.join(); }
  return 0;
}
