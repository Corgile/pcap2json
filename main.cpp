#include <pcap2json/Argument.hh>
#include <pcap2json/common.hh>
#include <pcap2json/util.hh>

#include <github/mcmtroffaes/inipp.hh>
#include <github/taywee/args.hh>
#include <iostream>

int main(int const argc, char *argv[]) {
  xlog::InstantiateFileLogger(xlog::Level::DEBUG, "main.log");
  xlog::toggleAsyncLogging(TOGGLE_OFF);
  xlog::toggleConsoleLogging(TOGGLE_ON);
  util::ParseArguments(argc, argv);

  return 0;
}
