#pragma once

#include "gmock/gmock.h"
#include "simeng/memory/MemoryInterface.hh"

namespace simeng {

/** Mock implementation of memory::MemoryInterface */
class MockMemoryInterface : public memory::MemoryInterface {
 public:
  MOCK_METHOD2(requestRead, void(const memory::MemoryAccessTarget& target,
                                 uint64_t requestId));

  MOCK_METHOD2(requestWrite, void(const memory::MemoryAccessTarget& target,
                                  const RegisterValue& data));

  MOCK_CONST_METHOD0(getCompletedReads, const span<memory::MemoryReadResult>());

  MOCK_METHOD0(clearCompletedReads, void());

  MOCK_CONST_METHOD0(hasPendingRequests, bool());

  MOCK_CONST_METHOD3(rawRead, void(void* dest, uint64_t src, uint16_t len));

  MOCK_METHOD3(rawWrite, void(uint64_t dest, void* src, uint16_t len));

  MOCK_METHOD0(tick, void());
};

}  // namespace simeng
