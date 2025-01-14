
#include <unistd.h>

#include "gtest/gtest.h"
#include "simeng/config/SimInfo.hh"
#include "simeng/gdb/GDBStub.hh"
#include "simeng/version.hh"

namespace {

void setup_config() {
  simeng::config::SimInfo::generateDefault(simeng::config::ISA::AArch64, true);

  simeng::config::SimInfo::addToConfig(R"YAML(
{
  Core:
    {
      Clock-Frequency-GHz: 2.5,
    },
  Register-Set:
    {
      GeneralPurpose-Count: 154,
      FloatingPoint/SVE-Count: 90,
      Predicate-Count: 17, 
      Conditional-Count: 128,
      Matrix-Count: 2,
    },
  L1-Data-Memory:
    {
      Interface-Type: Flat,
    },
  L1-Instruction-Memory:
    {
      Interface-Type: Flat,
    },
  Ports:
    {
      '0': { Portname: 0, Instruction-Group-Support: [INT, FP, SVE, PREDICATE, LOAD, STORE, BRANCH, SME] },
    },
}
)YAML");

  simeng::config::SimInfo::addToConfig("{Core: {Simulation-Mode: outoforder}}");

  simeng::config::SimInfo::reBuild();
}

TEST(GDBTest, Default) {
  setup_config();

  auto coreInstance = std::make_unique<simeng::CoreInstance>(
      std::string(SIMENG_SOURCE_DIR "/SimEngDefaultProgram"),
      std::vector<std::string>{});

  auto GDBStub = simeng::GDBStub(*coreInstance, false, 24689);

  // i am not entirely sure whether this is actually legal to do in googletest
  auto pid = fork();

  ASSERT_NE(pid, -1);

  switch (pid) {
    case 0: {  // child process
      const char* gdb = std::getenv("GDB");
      if (gdb == nullptr) {
        gdb = "gdb-multiarch";
      }

      execlp(gdb, "SimEngDefaultProgram", "-ex", "set width 0", "-ex",
             "set height 0", "-ex", "set verbose off", "-ex",
             "target remote localhost:24689", "-ex", "c", "-ex", "quit 0",
             nullptr);
      FAIL();  // execlp should never return
      break;
    }

    default: {  // original process
      GDBStub.run();

      kill(pid, SIGTERM);

      // check conditions here

      break;
    }
  }
}

}  // namespace