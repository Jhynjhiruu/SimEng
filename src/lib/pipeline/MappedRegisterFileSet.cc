#include "simeng/pipeline/MappedRegisterFileSet.hh"

namespace simeng {
namespace pipeline {

MappedRegisterFileSet::MappedRegisterFileSet(
    RegisterFileSet& physicalRegisterFileSet, const RegisterAliasTable& rat)
    : ArchitecturalRegisterFileSet(physicalRegisterFileSet), rat_(rat) {}

const RegisterValue& MappedRegisterFileSet::get(Register reg) const {
  return ArchitecturalRegisterFileSet::get(rat_.getCommittedMapping(reg));
}

void MappedRegisterFileSet::set(Register reg, const RegisterValue& value) {
  return ArchitecturalRegisterFileSet::set(rat_.getCommittedMapping(reg), value);
}

}  // namespace pipeline
}  // namespace simeng
