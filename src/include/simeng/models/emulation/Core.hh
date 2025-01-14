#pragma once

#include <map>
#include <queue>
#include <string>

#include "simeng/ArchitecturalRegisterFileSet.hh"
#include "simeng/Core.hh"
#include "simeng/arch/Architecture.hh"
#include "simeng/span.hh"

namespace simeng {
namespace models {
namespace emulation {

/** An emulation-style core model. Executes each instruction in turn. */
class Core : public simeng::Core {
 public:
  /** Construct an emulation-style core, providing memory interfaces for
   * instructions and data, along with the instruction entry point and an ISA to
   * use. */
  Core(memory::MemoryInterface& instructionMemory,
       memory::MemoryInterface& dataMemory, uint64_t entryPoint,
       uint64_t programByteLength, const arch::Architecture& isa);

  /** Tick the core. */
  void tick() override;

  /** Check whether the program has halted. */
  bool hasHalted() const override;

  /** Retrieve the architectural register file set. */
  const ArchitecturalRegisterFileSet& getArchitecturalRegisterFileSet()
      const override;

  /** Retrieve the number of instructions retired. */
  uint64_t getInstructionsRetiredCount() const override;

  /** Retrieve a map of statistics to report. */
  std::map<std::string, std::string> getStats() const override;

  /** Retrieve the program counter. */
  const uint64_t getProgramCounter() const override;

  /** Set the program counter. */
  void setProgramCounter(uint64_t pc) override;

  /** Prepare the necessary breakpoint state for the following run. */
  void prepareBreakpoints(
      const std::optional<uint64_t>* step_from = nullptr,
      const std::vector<uint64_t>* bp = nullptr,
      const std::vector<simeng::memory::MemoryAccessTarget>* wp = nullptr,
      const std::vector<simeng::memory::MemoryAccessTarget>* rp = nullptr,
      const std::vector<simeng::memory::MemoryAccessTarget>* ap = nullptr,
      const std::optional<std::vector<uint64_t>>* syscalls = nullptr) override;

  /** Retrieve the reason for a break, if any. */
  const std::optional<simeng::BreakReason> getBreakReason() const override;

  /** Retrieve the exit code. Result only valid after exit() syscall has been
   * entered. */
  uint64_t getExitCode() const override { return exit_code_; }

 private:
  /** Execute an instruction. */
  bool execute(std::shared_ptr<Instruction>& uop);

  /** Handle an encountered exception. */
  bool handleException(const std::shared_ptr<Instruction>& instruction);

  /** Process an active exception handler. */
  void processExceptionHandler();

  /** A memory interface to access instructions. */
  memory::MemoryInterface& instructionMemory_;

  /** An architectural register file set, serving as a simple wrapper around the
   * register file set. */
  ArchitecturalRegisterFileSet architecturalRegisterFileSet_;

  /** A reusable macro-op vector to fill with uops. */
  MacroOp macroOp_;

  /** The previously generated addresses. */
  std::vector<simeng::memory::MemoryAccessTarget> previousAddresses_;

  /** The current program counter. */
  uint64_t pc_ = 0;

  /** The length of the available instruction memory. */
  uint64_t programByteLength_ = 0;

  /** The number of instructions executed. */
  uint64_t instructionsExecuted_ = 0;

  /** The number of branches executed. */
  uint64_t branchesExecuted_ = 0;

  /** If present, break when the program counter doesn't match this value. */
  const std::optional<uint64_t>* step_from_ = nullptr;

  /** If present, break when the program counter matches any of these values. */
  const std::vector<uint64_t>* bp_ = nullptr;

  /** If present, break when writing to any of these addresses. */
  const std::vector<simeng::memory::MemoryAccessTarget>* wp_ = nullptr;

  /** If present, break when reading from any of these addresses. */
  const std::vector<simeng::memory::MemoryAccessTarget>* rp_ = nullptr;

  /** If present, break when accessing any of these addresses. */
  const std::vector<simeng::memory::MemoryAccessTarget>* ap_ = nullptr;

  /** If present, the syscalls to catch. */
  const std::optional<std::vector<uint64_t>>* syscalls_ = nullptr;

  /** The last reason for which a break occurred. */
  std::optional<simeng::BreakReason> br_ = std::nullopt;

  /** The next reason to break. */
  std::optional<simeng::BreakReason> brn_ = std::nullopt;

  /** If present, the syscall currently being caught. */
  std::optional<uint64_t> current_syscall_ = std::nullopt;

  /** Exit code. Only valid after exit() syscall has been entered. */
  uint64_t exit_code_;
};

}  // namespace emulation
}  // namespace models
}  // namespace simeng
