#pragma once

#include "gmock/gmock.h"
#include "simeng/Core.hh"

namespace simeng {

/** Mock implementation of the `Core` interface. */
class MockCore : public Core {
 public:
  MockCore(memory::MemoryInterface& dataMemory, const arch::Architecture& isa,
           const std::vector<RegisterFileStructure>& regFileStructure)
      : Core(dataMemory, isa, regFileStructure) {}
  MOCK_METHOD0(tick, void());
  MOCK_CONST_METHOD0(hasHalted, bool());
  MOCK_CONST_METHOD0(getArchitecturalRegisterFileSet,
                     const ArchitecturalRegisterFileSet&());
  MOCK_CONST_METHOD0(getInstructionsRetiredCount, uint64_t());
  MOCK_CONST_METHOD0(getSystemTimer, uint64_t());
  MOCK_CONST_METHOD0(getStats, std::map<std::string, std::string>());
  MOCK_CONST_METHOD0(getProgramCounter, const uint64_t());
  MOCK_METHOD1(setProgramCounter, void(uint64_t pc));
  MOCK_CONST_METHOD0(getBreakReason,
                     const std::optional<simeng::BreakReason>());
};

}  // namespace simeng
