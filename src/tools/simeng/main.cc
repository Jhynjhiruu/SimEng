#include <getopt.h>

#include <chrono>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <string>

#include "simeng/Core.hh"
#include "simeng/CoreInstance.hh"
#include "simeng/GDBStub.hh"
#include "simeng/config/SimInfo.hh"
#include "simeng/memory/MemoryInterface.hh"
#include "simeng/version.hh"

/** Tick the provided core model until it halts. */
uint64_t simulate(simeng::Core& core,
                  simeng::memory::MemoryInterface& dataMemory,
                  simeng::memory::MemoryInterface& instructionMemory) {
  uint64_t iterations = 0;

  // Tick the core and memory interfaces until the program has halted
  while (!core.hasHalted() || dataMemory.hasPendingRequests()) {
    // Tick the core
    core.tick();

    // Tick memory
    instructionMemory.tick();
    dataMemory.tick();

    iterations++;
  }

  return iterations;
}

int main(int argc, char** argv) {
  // Print out build metadata
  std::cout << "[SimEng] Build metadata:" << std::endl;
  std::cout << "[SimEng] \tVersion: " SIMENG_VERSION << std::endl;
  std::cout << "[SimEng] \tCompile Time - Date: " __TIME__ " - " __DATE__
            << std::endl;
  std::cout << "[SimEng] \tBuild type: " SIMENG_BUILD_TYPE << std::endl;
  std::cout << "[SimEng] \tCompile options: " SIMENG_COMPILE_OPTIONS
            << std::endl;
  std::cout << "[SimEng] \tTest suite: " SIMENG_ENABLE_TESTS << std::endl;
  std::cout << "[SimEng] \tGDB stub enabled: " SIMENG_ENABLE_GDB << std::endl;
  std::cout << std::endl;

#if GDB_ENABLED

  // Parse options first using getopt_long
  auto gdb_verbose = false;
  uint16_t gdb_port = 2424;
  auto use_gdb = false;

  const std::string prog_name = argv[0];

  while (true) {
    static const struct option long_options[] = {
        {"gdb-verbose", no_argument, nullptr, 'v'},
        {"gdb-port", required_argument, nullptr, 'p'},
        {"use-gdb", no_argument, nullptr, 'g'},
        {"help", no_argument, nullptr, 'h'},
        {0, 0, 0, 0}};

    int option_index = 0;

    const int c =
        getopt_long(argc, argv, "gvp:h?", long_options, &option_index);

    if (c == -1) {
      break;
    }

    switch (c) {
      case '0': {
      }

      case 'g': {
        use_gdb = true;
        break;
      }

      case 'v': {
        use_gdb = true;
        gdb_verbose = true;
        break;
      }

      case 'p': {
        use_gdb = true;

        int port;
        try {
          port = std::stoi(optarg);
        } catch (const std::exception& e) {
          std::cerr << "[SimEng] Invalid port number: " << optarg << std::endl;
          exit(EXIT_FAILURE);
        }

        if ((port < 0) || (port > UINT16_MAX)) {
          std::cerr << "[SimEng] Port out of range: " << port << std::endl;
          exit(EXIT_FAILURE);
        }

        gdb_port = static_cast<uint16_t>(port);
        break;
      }

      case 'h':
      case '?': {
        std::cout << prog_name << " usage:\n"
                  << std::endl
                  << "\t--use-gdb,     -g     : enable GDB "
                     "stub"
                  << std::endl
                  << "\t--gdb-verbose, -v     : print verbose "
                     "communication info (implies --use-gdb)"
                  << std::endl
                  << "\t--gdb-port,    -p port: listen on "
                     "port <port> (default: 2424, implies --use-gdb)"
                  << std::endl
                  << "\t--help,        -h -?  : "
                     "show this help"
                  << std::endl;

        exit(EXIT_FAILURE);
      }

      default: {
        std::cerr << "[SimEng] Ignoring unrecognised option '" << c << "'"
                  << std::endl;
        break;
      }
    }
  }

  // continue argument parsing as usual
  // argv[0] will be incorrect, but that's not used here
  argc -= optind - 1;
  argv += optind - 1;

#endif

  // Create the instance of the core to be simulated
  std::unique_ptr<simeng::CoreInstance> coreInstance;
  std::string executablePath = "";
  std::string configFilePath = "";
  std::vector<std::string> executableArgs = {};

  // Determine if a config file has been supplied.
  if (argc > 1) {
    // Set the global config file to one at the file path defined.
    simeng::config::SimInfo::setConfig(argv[1]);

    // Determine if an executable has been supplied
    if (argc > 2) {
      executablePath = std::string(argv[2]);
      // Create a vector of any potential executable arguments from their
      // relative position within the argv variable
      char** startOfArgs = argv + 3;
      int numberofArgs = argc - 3;
      executableArgs =
          std::vector<std::string>(startOfArgs, startOfArgs + numberofArgs);
    } else {
      // Use the default program if not
      configFilePath = DEFAULT_STR;
      executablePath = SIMENG_SOURCE_DIR "/SimEngDefaultProgram";
    }
  } else {
    // Without a config file, no executable can be supplied so pass default
    // values for executable information
    configFilePath = DEFAULT_STR;
    executablePath = SIMENG_SOURCE_DIR "/SimEngDefaultProgram";
  }

  coreInstance =
      std::make_unique<simeng::CoreInstance>(executablePath, executableArgs);

  // Replace empty executablePath string with more useful content for
  // outputting
  if (executablePath == "") executablePath = DEFAULT_STR;

  // Get simulation objects needed to forward simulation
  std::shared_ptr<simeng::Core> core = coreInstance->getCore();
  std::shared_ptr<simeng::memory::MemoryInterface> dataMemory =
      coreInstance->getDataMemory();
  std::shared_ptr<simeng::memory::MemoryInterface> instructionMemory =
      coreInstance->getInstructionMemory();

  // Output general simulation details
  std::cout << "[SimEng] Running in "
            << simeng::config::SimInfo::getSimModeStr() << " mode" << std::endl;
  std::cout << "[SimEng] Workload: " << executablePath;
  for (const auto& arg : executableArgs) std::cout << " " << arg;
  std::cout << std::endl;
  std::cout << "[SimEng] Config file: "
            << simeng::config::SimInfo::getConfigPath() << std::endl;
  std::cout << "[SimEng] ISA: " << simeng::config::SimInfo::getISAString()
            << std::endl;
  std::cout << "[SimEng] Auto-generated Special File directory: ";
  if (simeng::config::SimInfo::getGenSpecFiles())
    std::cout << "True";
  else
    std::cout << "False";
  std::cout << std::endl;
  std::cout << "[SimEng] Special File directory used: "
            << simeng::config::SimInfo::getConfig()["CPU-Info"]
                                                   ["Special-File-Dir-Path"]
                                                       .as<std::string>()
            << std::endl;
  std::cout << "[SimEng] Number of Cores: "
            << simeng::config::SimInfo::getConfig()["CPU-Info"]["Core-Count"]
                   .as<uint16_t>()
            << std::endl;

  // Run simulation
  std::cout << "[SimEng] Starting...\n" << std::endl;
  uint64_t iterations = 0;
  auto startTime = std::chrono::high_resolution_clock::now();

#if GDB_ENABLED

  if (use_gdb) {
    auto GDBStub = simeng::GDBStub(*coreInstance, gdb_verbose, gdb_port);
    iterations = GDBStub.run();
  } else {
#endif
    iterations = simulate(*core, *dataMemory, *instructionMemory);
#if GDB_ENABLED
  }
#endif

  // Get timing information
  auto endTime = std::chrono::high_resolution_clock::now();
  auto duration =
      std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime)
          .count();
  double khz = (iterations / (static_cast<double>(duration) / 1000.0)) / 1000.0;
  uint64_t retired = core->getInstructionsRetiredCount();
  double mips = (retired / (static_cast<double>(duration))) / 1000.0;

  // Print stats
  std::cout << std::endl;
  auto stats = core->getStats();
  for (const auto& [key, value] : stats) {
    std::cout << "[SimEng] " << key << ": " << value << std::endl;
  }
  std::cout << std::endl;

#if GDB_ENABLED
  // Timing stats are useless when using GDB
  if (!use_gdb) {
#endif
    std::cout << "[SimEng] Finished " << iterations << " ticks in " << duration
              << "ms (" << std::round(khz) << " kHz, " << std::setprecision(2)
              << mips << " MIPS)" << std::endl;
#if GDB_ENABLED
  }
#endif

// Print build metadata and core statistics in YAML format
// to facilitate parsing. Print "YAML-SEQ" to indicate beginning
// of YAML formatted data.
#ifdef YAML_OUTPUT

  ryml::Tree out;
  ryml::NodeRef ref = out.rootref();
  ref |= ryml::MAP;
  ref.append_child() << ryml::key("build metadata");
  ref["build metadata"] |= ryml::SEQ;
  ref["build metadata"].append_child();
  ref["build metadata"][0] << "Version: " SIMENG_VERSION;
  ref["build metadata"].append_child();
  ref["build metadata"][1] << "Compile Time - Date: " __TIME__ " - " __DATE__;
  ref["build metadata"].append_child();
  ref["build metadata"][2] << "Build type: " SIMENG_BUILD_TYPE;
  ref["build metadata"].append_child();
  ref["build metadata"][3] << "Compile options: " SIMENG_COMPILE_OPTIONS;
  ref["build metadata"].append_child();
  ref["build metadata"][4] << "Test suite: " SIMENG_ENABLE_TESTS;
  for (const auto& [key, value] : stats) {
    ref.append_child() << ryml::key(key);
    ref[ryml::to_csubstr(key)] << value;
  }
  ref.append_child() << ryml::key("duration");
  ref["duration"] << duration;
  ref.append_child() << ryml::key("mips");
  ref["mips"] << mips;
  ref.append_child() << ryml::key("cycles_per_sec");
  ref["cycles_per_sec"] << std::stod(stats["cycles"]) / (duration / 1000.0);

  std::cout << "YAML-SEQ\n";
  std::cout << "---\n";
  std::cout << ryml::emitrs_yaml<std::string>(out);
  std::cout << "...\n\n";

#endif

  return 0;
}