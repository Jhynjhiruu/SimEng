#include "simeng/AlwaysNotTakenPredictor.hh"

namespace simeng {

BranchPrediction AlwaysNotTakenPredictor::predict(uint64_t address,
                                                  BranchType type,
                                                  uint64_t knownTarget) {
  return {false, 0};
}

void AlwaysNotTakenPredictor::update(uint64_t address, bool taken,
                                     uint64_t targetAddress, BranchType type) {}

void AlwaysNotTakenPredictor::flush(uint64_t address) {}

}  // namespace simeng