#pragma once

#include <forward_list>
#include <queue>
#include <unordered_map>

#include "simeng/arch/Architecture.hh"
#include "simeng/arch/aarch64/ExceptionHandler.hh"
#include "simeng/arch/aarch64/MicroDecoder.hh"

using csh = size_t;

namespace simeng {
namespace arch {
namespace aarch64 {

/* A basic Armv9.2-a implementation of the `Architecture` interface. */
class Architecture : public arch::Architecture {
 public:
  Architecture(kernel::Linux& kernel,
               ryml::ConstNodeRef config = config::SimInfo::getConfig());

  ~Architecture();

  /** Pre-decode instruction memory into a macro-op of `Instruction`
   * instances. Returns the number of bytes consumed to produce it (always 4),
   * and writes into the supplied macro-op vector. */
  uint8_t predecode(const uint8_t* ptr, uint16_t bytesAvailable,
                    uint64_t instructionAddress,
                    MacroOp& output) const override;

  /** Returns a zero-indexed register tag for a system register encoding.
   * Returns -1 in the case that the system register has no mapping. */
  int32_t getSystemRegisterTag(uint16_t reg) const override;

  /** Create an exception handler for the exception generated by `instruction`,
   * providing the core model object and a reference to process memory.
   * Returns a smart pointer to an `ExceptionHandler` which may be ticked until
   * the exception is resolved, and results then obtained. */
  std::shared_ptr<arch::ExceptionHandler> handleException(
      const std::shared_ptr<simeng::Instruction>& instruction, const Core& core,
      memory::MemoryInterface& memory) const override;

  /** Retrieve the initial process state. */
  ProcessStateChange getInitialState() const override;

  /** Returns the maximum size of a valid instruction in bytes. */
  uint8_t getMaxInstructionSize() const override;

  /** Returns the minimum size of a valid instruction in bytes. */
  uint8_t getMinInstructionSize() const override;

  /** Updates System registers of any system-based timers. */
  void updateSystemTimerRegisters(RegisterFileSet* regFile,
                                  const uint64_t iterations) const override;

  /** Get the architecture-specific vector size (currently only for (S)VL on
   * AArch64) */
  const std::tuple<uint64_t, uint64_t> getVectorSize() const override {
    return std::make_tuple(getVectorLength(), getStreamingVectorLength());
  }

  /** Retrieve an ExecutionInfo object for the requested instruction. If a
   * opcode-based override has been defined for the latency and/or
   * port information, return that instead of the group-defined execution
   * information. */
  virtual ExecutionInfo getExecutionInfo(const Instruction& insn) const;

  /** Returns the current vector length set by the provided configuration. */
  uint64_t getVectorLength() const;

  /** Returns the current streaming vector length set by the provided
   * configuration. */
  uint64_t getStreamingVectorLength() const;

  /** Returns the current value of SVCRval_. */
  uint64_t getSVCRval() const;

  /** Update the value of SVCRval_. */
  void setSVCRval(const uint64_t newVal) const;

 private:
  /** A decoding cache, mapping an instruction word to a previously decoded
   * instruction. Instructions are added to the cache as they're decoded, to
   * reduce the overhead of future decoding. */
  mutable std::unordered_map<uint32_t, Instruction> decodeCache_;

  /** A decoding metadata cache, mapping an instruction word to a previously
   * decoded instruction metadata bundle. Metadata is added to the cache as it's
   * decoded, to reduce the overhead of future decoding. */
  mutable std::forward_list<InstructionMetadata> metadataCache_;

  /** A reference to a micro decoder object to split macro operations. */
  std::unique_ptr<MicroDecoder> microDecoder_;

  /** The vector length used by the SVE extension in bits. */
  uint64_t VL_;

  /** The streaming vector length used by the SME extension in bits. */
  uint64_t SVL_;

  /** A copy of the value of the SVCR system register. */
  mutable uint64_t SVCRval_ = 0;

  /** System Register of Virtual Counter Timer. */
  simeng::Register VCTreg_;

  /** System Register of Processor Cycle Counter. */
  simeng::Register PCCreg_;

  /** Modulo component used to define the frequency at which the VCT is updated.
   */
  double vctModulo_;
};

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
