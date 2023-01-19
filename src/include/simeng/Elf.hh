#pragma once

#include <string>
#include <vector>

#include "simeng/span.hh"

namespace simeng {

namespace ElfBitFormat {
const char Format32 = 1;
const char Format64 = 2;
}  // namespace ElfBitFormat

struct ElfHeader {
  uint32_t type;
  uint64_t offset;
  uint64_t virtualAddress;
  uint64_t physicalAddress;
  uint64_t fileSize;
  uint64_t memorySize;
  char* headerData = nullptr;
};

/** A processed Executable and Linkable Format (ELF) file. */
class Elf {
 public:
  Elf(std::string path);
  ~Elf();
  uint64_t getProcessImageSize() const;
  bool isValid() const;
  uint64_t getEntryPoint() const;
  std::vector<ElfHeader*>& getProcessedHeaders();
  uint64_t getMaxVirtAddr();

 private:
  uint64_t entryPoint_;
  std::vector<ElfHeader*> headers_;
  bool isValid_ = false;
  uint64_t processImageSize_ = 0;
  std::vector<ElfHeader*> processedHeaders_;
  uint64_t maxVirtAddr_ = 0;
};

}  // namespace simeng
