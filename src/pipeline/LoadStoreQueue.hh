#pragma once

#include <deque>
#include "../Instruction.hh"

namespace simeng {
namespace pipeline {

/** A load store queue (known as "load/store buffers" or "memory order buffer").
 * Holds in-flight memory access requests to ensure load/store consistency. */
class LoadStoreQueue {
 public:
  /** Constructs a combined load/store queue model, simulating a shared queue
   * for both load and store instructions. */
  LoadStoreQueue(unsigned int maxCombinedSpace, char* memory);

  /** Constructs a split load/store queue model, simulating discrete queues for
   * load and store instructions. */
  LoadStoreQueue(unsigned int maxLoadQueueSpace,
                 unsigned int maxStoreQueueSpace, char* memory);

  /** Retrieve the available space for load uops. For combined queue this is the
   * total remaining space. */
  unsigned int getLoadQueueSpace() const;

  /** Retrieve the available space for store uops. For a combined queue this is
   * the total remaining space. */
  unsigned int getStoreQueueSpace() const;

  /** Retrieve the available space for any memory uops. For a split queue this
   * is the sum of the space in both queues. */
  unsigned int getTotalSpace() const;

  /** Add a load uop to the queue. */
  void addLoad(const std::shared_ptr<Instruction>& insn);

  /** Add a store uop to the queue. */
  void addStore(const std::shared_ptr<Instruction>& insn);

  /** Initiate a memory read for the addresses generated by the provided
   * instruction. */
  void startLoad(const std::shared_ptr<Instruction>& insn);

  /** Commit and write the oldest store instruction to memory, removing it from
   * the store queue. Returns `true` if memory disambiguation has discovered a
   * memory order violation during the commit. */
  bool commitStore(const std::shared_ptr<Instruction>& uop);

  /** Remove the oldest load instruction from the load queue. */
  void commitLoad(const std::shared_ptr<Instruction>& uop);

  /** Remove all flushed instructions from the queues. */
  void purgeFlushed();

  /** Whether this is a combined load/store queue. */
  bool isCombined() const;

  /** Retrieve the load instruction associated with the most recently discovered
   * memory order violation. */
  std::shared_ptr<Instruction> getViolatingLoad() const;

 private:
  /** The load queue: holds in-flight load instructions. */
  std::deque<std::shared_ptr<Instruction>> loadQueue_;

  /** The store queue: holds in-flight store instructions. */
  std::deque<std::shared_ptr<Instruction>> storeQueue_;

  /** The maximum number of loads that can be in-flight. Undefined if this is a
   * combined queue. */
  unsigned int maxLoadQueueSpace_;

  /** The maximum number of stores that can be in-flight. Undefined if this is a
   * combined queue. */
  unsigned int maxStoreQueueSpace_;

  /** The maximum number of memory ops that can be in-flight. Undefined if this
   * is a split queue. */
  unsigned int maxCombinedSpace_;

  /** Whether this queue is combined or split. */
  bool combined_;

  /** Retrieve the load queue space for a split queue. */
  unsigned int getLoadQueueSplitSpace() const;

  /** Retrieve the store queue space for a split queue. */
  unsigned int getStoreQueueSplitSpace() const;

  /** Retrieve the total memory uop space available for a combined queue. */
  unsigned int getCombinedSpace() const;

  /** A pointer to process memory. */
  char* memory_;

  /** The load instruction associated with the most recently discovered memory
   * order violation. */
  std::shared_ptr<Instruction> violatingLoad_ = nullptr;
};

}  // namespace pipeline
}  // namespace simeng