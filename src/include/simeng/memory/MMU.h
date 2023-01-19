#pragma once
#include <functional>
#include <memory>

#include "simeng/memory/Mem.hh"

typedef std::function<uint64_t(uint64_t)> VAddrTranslator;

namespace simeng {
namespace memory {

class MMU {
 private:
  std::shared_ptr<Mem> memory_ = nullptr;
  VAddrTranslator translate_;

 public:
  MMU(std::shared_ptr<Mem> memory, VAddrTranslator fn);
  void bufferRequest(DataPacket* request,
                     std::function<void(DataPacket*)> callback);
  void setTranslator(VAddrTranslator translator);
};

}  // namespace memory
}  // namespace simeng
