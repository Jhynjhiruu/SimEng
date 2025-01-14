#include "simeng/pipeline/ReorderBuffer.hh"

#include <algorithm>
#include <cassert>
#include <iostream>

namespace simeng {
namespace pipeline {

ReorderBuffer::ReorderBuffer(
    uint32_t maxSize, RegisterAliasTable& rat, LoadStoreQueue& lsq,
    std::function<void(const std::shared_ptr<Instruction>&)> raiseException,
    std::function<void(uint64_t branchAddress)> sendLoopBoundary,
    BranchPredictor& predictor, uint16_t loopBufSize,
    uint16_t loopDetectionThreshold)
    : rat_(rat),
      lsq_(lsq),
      maxSize_(maxSize),
      raiseException_(raiseException),
      sendLoopBoundary_(sendLoopBoundary),
      predictor_(predictor),
      loopBufSize_(loopBufSize),
      loopDetectionThreshold_(loopDetectionThreshold) {}

void ReorderBuffer::reserve(const std::shared_ptr<Instruction>& insn) {
  assert(buffer_.size() < maxSize_ &&
         "Attempted to reserve entry in reorder buffer when already full");
  insn->setSequenceId(seqId_);
  seqId_++;
  insn->setInstructionId(insnId_);
  if (insn->isLastMicroOp()) insnId_++;

  buffer_.push_back(insn);
}

void ReorderBuffer::commitMicroOps(uint64_t insnId) {
  if (buffer_.size()) {
    size_t index = 0;
    uint64_t firstOp = UINT64_MAX;
    bool validForCommit = false;
    bool foundFirstInstance = false;

    // Find first instance of uop belonging to macro-op instruction
    for (; index < buffer_.size(); index++) {
      if (buffer_[index]->getInstructionId() == insnId) {
        firstOp = index;
        foundFirstInstance = true;
        break;
      }
    }

    if (foundFirstInstance) {
      // If found, see if all uops are committable
      for (; index < buffer_.size(); index++) {
        if (buffer_[index]->getInstructionId() != insnId) break;
        if (!buffer_[index]->isWaitingCommit()) {
          return;
        } else if (buffer_[index]->isLastMicroOp()) {
          // all microOps must be in ROB for the commit to be valid
          validForCommit = true;
        }
      }
      if (!validForCommit) return;

      assert(firstOp != UINT64_MAX && "firstOp hasn't been populated");
      // No early return thus all uops are committable
      for (; firstOp < buffer_.size(); firstOp++) {
        if (buffer_[firstOp]->getInstructionId() != insnId) break;
        buffer_[firstOp]->setCommitReady();
      }
    }
  }
  return;
}

unsigned int ReorderBuffer::commit(uint64_t maxCommitSize) {
  shouldFlush_ = false;
  size_t maxCommits =
      std::min(static_cast<size_t>(maxCommitSize), buffer_.size());

  unsigned int n;
  for (n = 0; (n < maxCommits) && (!br_); n++) {
    auto& uop = buffer_[0];
    if (!uop->canCommit()) {
      break;
    }

    // TODO: is it possible for putting this ↓ before uop->canCommit() to cause
    // problems?

    const auto pc = uop->getInstructionAddress();
    pc_ = pc;

    if (brn_) {
      br_ = brn_;
      brn_ = std::nullopt;
      break;
    }

    if ((step_from_ != nullptr) && (*step_from_)) {
      if (pc != **step_from_) {
        br_ = simeng::BreakReason{simeng::BreakReason::Break, 0, pc};
        // breakpoints hit before the instruction is executed
        break;
      }
    } else if (bp_ != nullptr) {
      if (std::any_of(bp_->cbegin(), bp_->cend(),
                      [&](const auto bp) { return pc == bp; })) {
        br_ = simeng::BreakReason{simeng::BreakReason::Break, 0, pc};
        // breakpoints hit before the instruction is executed
        break;
      }
    }

    if (uop->isLastMicroOp()) instructionsCommitted_++;

    if (uop->exceptionEncountered()) {
      raiseException_(uop);
      buffer_.pop_front();
      return n + 1;
    }

    const auto& destinations = uop->getDestinationRegisters();
    for (size_t i = 0; i < destinations.size(); i++) {
      rat_.commit(destinations[i]);
    }

    // If it's a memory op, commit the entry at the head of the respective queue
    if (uop->isLoad()) {
      const auto addresses = uop->getGeneratedAddresses();

      if (rp_) {
        for (const auto& rp : *rp_) {
          for (const auto& address : addresses) {
            if (rp.overlaps(address)) {
              br_ = {BreakReason::Read, address.address,
                     uop->getInstructionAddress()};
            }
          }
        }
      }

      if (ap_) {
        for (const auto& ap : *ap_) {
          for (const auto& address : addresses) {
            if (ap.overlaps(address)) {
              br_ = {BreakReason::Access, address.address,
                     uop->getInstructionAddress()};
            }
          }
        }
      }

      lsq_.commitLoad(uop);
    }
    if (uop->isStoreAddress()) {
      auto addresses = uop->generateAddresses();

      if (wp_) {
        for (const auto& wp : *wp_) {
          for (const auto& address : addresses) {
            if (wp.overlaps(address)) {
              br_ = {BreakReason::Write, address.address,
                     uop->getInstructionAddress()};
            }
          }
        }
      }

      if (ap_) {
        for (const auto& ap : *ap_) {
          for (const auto& address : addresses) {
            if (ap.overlaps(address)) {
              br_ = {BreakReason::Access, address.address,
                     uop->getInstructionAddress()};
            }
          }
        }
      }

      bool violationFound = lsq_.commitStore(uop);
      if (violationFound) {
        loadViolations_++;
        // Memory order violation found; aborting commits and flushing
        auto load = lsq_.getViolatingLoad();
        clobberAfter(load->getInstructionId() - 1,
                     load->getInstructionAddress());

        buffer_.pop_front();
        return n + 1;
      }
    }

    // Increment or swap out branch counter for loop detection
    if (uop->isBranch() && !loopDetected_) {
      bool increment = true;
      if (branchCounter_.first.address != uop->getInstructionAddress()) {
        // Mismatch on instruction address, reset
        increment = false;
      } else if (branchCounter_.first.outcome != uop->getBranchPrediction()) {
        // Mismatch on branch outcome, reset
        increment = false;
      } else if ((instructionsCommitted_ - branchCounter_.first.commitNumber) >
                 loopBufSize_) {
        // Loop too big to fit in loop buffer, reset
        increment = false;
      }

      if (increment) {
        // Reset commitNumber value
        branchCounter_.first.commitNumber = instructionsCommitted_;
        // Increment counter
        branchCounter_.second++;

        if (branchCounter_.second > loopDetectionThreshold_) {
          // If the same branch with the same outcome is sequentially retired
          // more times than the loopDetectionThreshold_ value, identify as a
          // loop boundary
          loopDetected_ = true;
          sendLoopBoundary_(uop->getInstructionAddress());
        }
      } else {
        // Swap out latest branch
        branchCounter_ = {{uop->getInstructionAddress(),
                           uop->getBranchPrediction(), instructionsCommitted_},
                          0};
      }
    }
    buffer_.pop_front();
  }

  return n;
}

void ReorderBuffer::flush(uint64_t afterInsnId) {
  // Iterate backwards from the tail of the queue to find and remove ops newer
  // than `afterInsnId`
  while (!buffer_.empty()) {
    auto& uop = buffer_.back();
    if (uop->getInstructionId() <= afterInsnId) {
      break;
    }

    // To rewind destination registers in correct history order, rewinding of
    // register renaming is done backwards
    auto destinations = uop->getDestinationRegisters();
    for (int i = destinations.size() - 1; i >= 0; i--) {
      const auto& reg = destinations[i];
      // Only rewind the register if it was renamed
      if (reg.renamed) rat_.rewind(reg);
    }
    uop->setFlushed();
    // If the instruction is a branch, supply address to branch flushing logic
    if (uop->isBranch()) {
      predictor_.flush(uop->getInstructionAddress());
    }
    buffer_.pop_back();
  }

  // Reset branch counter and loop detection
  branchCounter_ = {{0, {false, 0}, 0}, 0};
  loopDetected_ = false;
}

unsigned int ReorderBuffer::size() const { return buffer_.size(); }

unsigned int ReorderBuffer::getFreeSpace() const {
  return maxSize_ - buffer_.size();
}

bool ReorderBuffer::shouldFlush() const { return shouldFlush_; }
uint64_t ReorderBuffer::getFlushAddress() const { return pc_; }
uint64_t ReorderBuffer::getFlushInsnId() const { return flushAfter_; }

uint64_t ReorderBuffer::getInstructionsCommittedCount() const {
  return instructionsCommitted_;
}

uint64_t ReorderBuffer::getViolatingLoadsCount() const {
  return loadViolations_;
}

void ReorderBuffer::clobberAfter(uint64_t id, uint64_t pc) {
  shouldFlush_ = true;
  flushAfter_ = id;
  pc_ = pc;
}

void ReorderBuffer::prepareBreakpoints(
    const std::optional<uint64_t>* step_from, const std::vector<uint64_t>* bp,
    const std::vector<simeng::memory::MemoryAccessTarget>* wp,
    const std::vector<simeng::memory::MemoryAccessTarget>* rp,
    const std::vector<simeng::memory::MemoryAccessTarget>* ap) {
  br_ = std::nullopt;

  step_from_ = step_from;
  bp_ = bp;
  wp_ = wp;
  rp_ = rp;
  ap_ = ap;
}

const std::optional<simeng::BreakReason> ReorderBuffer::getBreakReason() const {
  return br_;
}

void ReorderBuffer::setBreakReasons(
    std::optional<simeng::BreakReason> reason,
    std::optional<simeng::BreakReason> next_reason) {
  br_ = reason;
  brn_ = next_reason;
}

const uint64_t ReorderBuffer::getPC() const { return pc_; }

}  // namespace pipeline
}  // namespace simeng
