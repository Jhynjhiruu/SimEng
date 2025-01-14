#pragma once

#include <deque>
#include <functional>
#include <optional>

#include "simeng/Core.hh"
#include "simeng/Instruction.hh"
#include "simeng/pipeline/LoadStoreQueue.hh"
#include "simeng/pipeline/RegisterAliasTable.hh"

namespace simeng {
namespace pipeline {

/** A branch prediction outcome with an associated instruction address. */
struct latestBranch {
  /** Branch instruction address. */
  uint64_t address;

  /** Outcome of the branch. */
  BranchPrediction outcome;

  /** The related instructionsCommitted_ value that this instruction was
   * committed on. */
  uint64_t commitNumber;
};

/** Check if the instruction ID is less/greater than a given value used by
 *  binary_search. */
struct idCompare {
  bool operator()(const std::shared_ptr<Instruction>& first,
                  const uint64_t second) {
    return first->getInstructionId() < second;
  }

  bool operator()(const uint64_t first,
                  const std::shared_ptr<Instruction>& second) {
    return first < second->getInstructionId();
  }
};

/** A Reorder Buffer (ROB) implementation. Contains an in-order queue of
 * in-flight instructions. */
class ReorderBuffer {
 public:
  /** Constructs a reorder buffer of maximum size `maxSize`, supplying a
   * reference to the register alias table. */
  ReorderBuffer(
      uint32_t maxSize, RegisterAliasTable& rat, LoadStoreQueue& lsq,
      std::function<void(const std::shared_ptr<Instruction>&)> raiseException,
      std::function<void(uint64_t branchAddress)> sendLoopBoundary,
      BranchPredictor& predictor, uint16_t loopBufSize,
      uint16_t loopDetectionThreshold);

  /** Add the provided instruction to the ROB. */
  void reserve(const std::shared_ptr<Instruction>& insn);

  void commitMicroOps(uint64_t insnId);

  /** Commit and remove up to `maxCommitSize` instructions. */
  unsigned int commit(uint64_t maxCommitSize);

  /** Flush all instructions with a sequence ID greater than `afterSeqId`. */
  void flush(uint64_t afterInsnId);

  /** Retrieve the current size of the ROB. */
  unsigned int size() const;

  /** Retrieve the current amount of free space in the ROB. */
  unsigned int getFreeSpace() const;

  /** Query whether a memory order violation was discovered in the most recent
   * cycle. */
  bool shouldFlush() const;

  /** Retrieve the instruction address associated with the most recently
   * discovered memory order violation. */
  uint64_t getFlushAddress() const;

  /** Retrieve the instruction ID associated with the most recently discovered
   * memory order violation. */
  uint64_t getFlushInsnId() const;

  /** Get the number of instructions the ROB has committed. */
  uint64_t getInstructionsCommittedCount() const;

  /** Get the number of speculated loads which violated load-store ordering. */
  uint64_t getViolatingLoadsCount() const;

  /** Clobber all instructions after a certain sequence ID. */
  void clobberAfter(uint64_t id, uint64_t pc);

  /** Prepare the necessary breakpoint state for the following run. */
  void prepareBreakpoints(
      const std::optional<uint64_t>* step_from, const std::vector<uint64_t>* bp,
      const std::vector<simeng::memory::MemoryAccessTarget>* wp,
      const std::vector<simeng::memory::MemoryAccessTarget>* rp,
      const std::vector<simeng::memory::MemoryAccessTarget>* ap);

  /** Retrieve the reason for a break, if any. */
  const std::optional<simeng::BreakReason> getBreakReason() const;

  /** Set the break reasons. */
  void setBreakReasons(std::optional<simeng::BreakReason> reason,
                      std::optional<simeng::BreakReason> next_reason);

  /** Retrieve the current program counter value. */
  const uint64_t getPC() const;

 private:
  /** A reference to the register alias table. */
  RegisterAliasTable& rat_;

  /** A reference to the load/store queue. */
  LoadStoreQueue& lsq_;

  /** The maximum size of the ROB. */
  uint32_t maxSize_;

  /** A function to call upon exception generation. */
  std::function<void(std::shared_ptr<Instruction>)> raiseException_;

  /** A function to send an instruction at a detected loop boundary. */
  std::function<void(uint64_t branchAddress)> sendLoopBoundary_;

  /** Whether or not a loop has been detected. */
  bool loopDetected_ = false;

  /** A reference to the current branch predictor. */
  BranchPredictor& predictor_;

  /** The buffer containing in-flight instructions. */
  std::deque<std::shared_ptr<Instruction>> buffer_;

  /** Whether the core should be flushed after the most recent commit. */
  bool shouldFlush_ = false;

  /** The target instruction address the PC should be reset to after the most
   * recent commit.
   */
  uint64_t pc_;

  /** The sequence ID of the youngest instruction that should remain after the
   * current flush. */
  uint64_t flushAfter_;

  /** Latest retired branch outcome with a counter. */
  std::pair<latestBranch, uint64_t> branchCounter_ = {{0, {false, 0}, 0}, 0};

  /** Loop buffer size. */
  uint16_t loopBufSize_;

  /** Amount of times a branch must be seen without interruption for it to be
   * considered a loop. */
  uint16_t loopDetectionThreshold_;

  /** The next available sequence ID. */
  uint64_t seqId_ = 0;

  /** The next available instruction ID. Used to identify in-order groups of
   * micro-operations. */
  uint64_t insnId_ = 0;

  /** The number of instructions committed. */
  uint64_t instructionsCommitted_ = 0;

  /** The number of speculative loads which violated load-store ordering. */
  uint64_t loadViolations_ = 0;

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

  /** The last reason for which a break occurred. */
  std::optional<simeng::BreakReason> br_ = std::nullopt;

  /** The next reason to break. */
  std::optional<simeng::BreakReason> brn_ = std::nullopt;
};

}  // namespace pipeline
}  // namespace simeng
