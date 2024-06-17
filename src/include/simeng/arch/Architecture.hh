#pragma once

#include <tuple>
#include <vector>

#include "simeng/BranchPredictor.hh"
#include "simeng/Core.hh"
#include "simeng/Instruction.hh"
#include "simeng/arch/ProcessStateChange.hh"
#include "simeng/kernel/Linux.hh"
#include "simeng/memory/MemoryInterface.hh"

namespace simeng {

using MacroOp = std::vector<std::shared_ptr<Instruction>>;

namespace arch {

/** The result from a handled exception. */
struct ExceptionResult {
  /** Whether execution should halt. */
  bool fatal;
  /** The address to resume execution from. */
  uint64_t instructionAddress;
  /** Any changes to apply to the process state. */
  ProcessStateChange stateChange;
};

/** An abstract multi-cycle exception handler interface. Should be ticked each
 * cycle until complete. */
class ExceptionHandler {
 public:
  virtual ~ExceptionHandler(){};
  /** Tick the exception handler to progress handling of the exception. Should
   * return `false` if the exception requires further handling, or `true` once
   * complete. */
  virtual bool tick() = 0;

  /** Retrieve the result of the exception. */
  virtual const ExceptionResult& getResult() const = 0;
};

/** An abstract Instruction Set Architecture (ISA) definition. Each supported
 * ISA should provide a derived implementation of this class. */
class Architecture {
 public:
  Architecture(kernel::Linux& kernel) : linux_(kernel) {}

  virtual ~Architecture(){};

  /** Attempt to pre-decode from `bytesAvailable` bytes of instruction memory.
   * Writes into the supplied macro-op vector, and returns the number of bytes
   * consumed to produce it; a value of 0 indicates too few bytes were present
   * for a valid decoding. */
  virtual uint8_t predecode(const uint8_t* ptr, uint16_t bytesAvailable,
                            uint64_t instructionAddress,
                            MacroOp& output) const = 0;

  /** Returns a zero-indexed register tag for a system register encoding. */
  virtual int32_t getSystemRegisterTag(uint16_t reg) const = 0;

  /** Create an exception handler for the exception generated by
   * `instruction`, providing the core model object and a reference to
   * process memory. Returns a smart pointer to an `ExceptionHandler` which
   * may be ticked until the exception is resolved, and results then
   * obtained. */
  virtual std::shared_ptr<ExceptionHandler> handleException(
      const std::shared_ptr<Instruction>& instruction, const Core& core,
      memory::MemoryInterface& memory) const = 0;

  /** Retrieve the initial process state. */
  virtual ProcessStateChange getInitialState() const = 0;

  /** Returns the maximum size of a valid instruction in bytes. */
  virtual uint8_t getMaxInstructionSize() const = 0;

  /** Returns the minimum size of a valid instruction in bytes. */
  virtual uint8_t getMinInstructionSize() const = 0;

  /** Updates System registers of any system-based timers. */
  virtual void updateSystemTimerRegisters(RegisterFileSet* regFile,
                                          const uint64_t iterations) const = 0;

  /** Get the architecture-specific vector size (currently only for (S)VL on
   * AArch64) */
  virtual const std::tuple<uint64_t, uint64_t> getVectorSize() const = 0;

 protected:
  /** A Capstone decoding library handle, for decoding instructions. */
  csh capstoneHandle_;

  /** A reference to a Linux kernel object to forward syscalls to. */
  kernel::Linux& linux_;

  /** A mapping from system register encoding to a zero-indexed tag. */
  std::unordered_map<uint16_t, uint16_t> systemRegisterMap_;

  /** A map to hold the relationship between instruction groups and
   * user-defined execution information. */
  std::unordered_map<uint16_t, ExecutionInfo> groupExecutionInfo_;

  /** A map to hold the relationship between instruction opcode and
   * user-defined execution information. */
  std::unordered_map<uint16_t, ExecutionInfo> opcodeExecutionInfo_;
};

}  // namespace arch
}  // namespace simeng
