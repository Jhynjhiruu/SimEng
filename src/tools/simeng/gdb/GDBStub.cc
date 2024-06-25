#include "simeng/GDBStub.hh"

#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iomanip>
#include <regex>

#include "simeng/arch/Architecture.hh"
#include "tinyxml2.h"

// read buffer size
#define BUF_SIZE (1000)

// number of requests to queue
#define NUM_REQUESTS (1)

// colour codes for pretty printing
#define RESET "\033[0m"
#define CYAN "\033[36m"
#define GREEN "\033[32m"
#define RED "\033[31m"

struct SupportedFeature {
  std::string name;
  std::optional<std::string> value;

  std::string format() const;
};

std::string SupportedFeature::format() const {
  if (value) {
    return name + '=' + *value;
  } else {
    return name + '+';
  }
}

template <typename T>
std::string int_to_hex(T i) {
  char* ptr;
  const auto bytesWritten =
      asprintf(&ptr, "%0*x", static_cast<int>(sizeof(T) * 2), i);
  const auto str = std::string{ptr, static_cast<size_t>(bytesWritten)};
  free(ptr);
  return str;
}

template <typename T>
std::string int_to_hex_ne(T i) {
  uint8_t bytes[sizeof(T)];
  memcpy(bytes, &i, sizeof(T));
  std::string rv;
  for (const auto byte : bytes) {
    rv += int_to_hex(byte);
  }
  return rv;
}

template <typename T>
std::optional<T> hex_to_int_ne(const std::string& str) {
  if (str.size() != sizeof(T) * 2) {
    return std::nullopt;
  }

  uint8_t bytes[sizeof(T)];
  try {
    for (size_t i = 0; i < sizeof(T); i++) {
      bytes[i] = std::stoi(str.substr(i * 2, 2), nullptr, 16);
    }
  } catch (const std::exception& e) {
    return std::nullopt;
  }

  T rv;

  memcpy(&rv, bytes, sizeof(T));

  return rv;
}

const SupportedFeature supported_features[] = {
    {
        "QStartNoAckMode",
        std::nullopt,
    },
    {"PacketSize", int_to_hex(BUF_SIZE - 10)},
    {"hwbreak", std::nullopt},
    {"qXfer:features:read", std::nullopt}};

template <typename T = uint16_t>
std::string formatSignal(
    uint8_t signal,
    const std::vector<std::tuple<std::variant<std::string, T>, std::string>>&
        values) {
  if (values.empty()) {
    return 'S' + int_to_hex(signal);
  } else {
    std::string rv;

    rv += 'T';
    rv += int_to_hex(signal);

    for (const auto& param : values) {
      const auto& type = std::get<0>(param);
      const auto& value = std::get<1>(param);

      switch (type.index()) {
        case 0: {
          // string
          rv += std::get<0>(type);
          break;
        }
        case 1: {
          // T
          rv += int_to_hex(std::get<1>(type));
          break;
        }
      }

      rv += ':';

      rv += value;

      rv += ';';
    }

    return rv;
  }
}

std::string formatError(const std::string& textual_error) {
  return "E." + textual_error;
}

std::string formatError(uint8_t error_num) {
  return "E" + int_to_hex(error_num);
}

std::string formatExit(uint8_t status) { return "W" + int_to_hex(status); }

std::vector<std::string> splitBy(const std::string& param_string,
                                 const char by) {
  std::vector<std::string> rv;
  std::string cur;

  for (const auto& c : param_string) {
    if (c == by) {
      rv.push_back(cur);
      cur = "";
    } else {
      cur += c;
    }
  }

  rv.push_back(cur);

  return rv;
}

std::tuple<std::shared_ptr<simeng::Instruction>, uint8_t> getCurrentInstruction(
    const simeng::CoreInstance& coreInstance) {
  const auto core = coreInstance.getCore();
  const auto instructionMemory = coreInstance.getInstructionMemory();
  const auto pc = core->getProgramCounter();
  const auto& isa = core->getISA();

  const auto ptr = instructionMemory->getMemoryPointer();
  const auto size = isa.getMaxInstructionSize();

  uint8_t buffer[size];
  memcpy(buffer, ptr + pc, size);

  simeng::MacroOp macroOp;
  auto bytesRead = isa.predecode(buffer, size, pc, macroOp);

  // TODO: is this always valid?
  return std::make_tuple(macroOp[0], bytesRead);
}

enum RegSize {
  Byte,
  Short,
  Word,
  ByteWord,
  Double,
  Vector,
  Predicate,
  PC,
  VG,
  SVG,
  ZA,
};

unsigned int getBitsize(RegSize size) {
  switch (size) {
    case Byte:
      return 8;
    case Short:
      return 16;
    case Word:
      return 32;
    case ByteWord:
      return 32;
    case Double:
      return 64;
    case Vector:
      return 2048;
    case Predicate:
      return 256;
    case PC:
      return 64;
    case VG:
      return 64;
    case SVG:
      return 64;
    case ZA:
      return 0;
    default:
      return 0;
  }
}

using RegList = std::vector<std::tuple<simeng::Register, RegSize>>;

struct TargetSpec {
  std::string spec;
  RegList regs;
};

RegList::value_type makeReg(uint8_t type, uint16_t tag, RegSize size) {
  return std::make_tuple((simeng::Register){type, tag}, size);
}

void addReg(
    tinyxml2::XMLPrinter& printer, RegList& regs, uint8_t type, uint16_t tag,
    const std::string& name, RegSize size,
    const std::optional<std::string>& data_type = std::nullopt,
    const std::optional<unsigned int>& override_bitsize = std::nullopt) {
  printer.OpenElement("reg", true);

  printer.PushAttribute("name", name.c_str());
  printer.PushAttribute(
      "bitsize", (override_bitsize) ? *override_bitsize : getBitsize(size));
  if (data_type) {
    printer.PushAttribute("type", data_type->c_str());
  }

  printer.CloseElement(true);

  regs.push_back(makeReg(type, tag, size));
}

struct FlagsField {
  std::string name;
  uint8_t start;
  uint8_t end;
};
void addFlags(tinyxml2::XMLPrinter& printer, const std::string& name,
              uint8_t size, const std::vector<FlagsField>& fields) {
  printer.OpenElement("flags");

  printer.PushAttribute("id", name.c_str());
  printer.PushAttribute("size", size);

  for (const auto& [name, start, end] : fields) {
    printer.OpenElement("field", true);

    printer.PushAttribute("name", name.c_str());
    printer.PushAttribute("start", start);
    printer.PushAttribute("end", end);

    printer.CloseElement(true);
  }

  printer.CloseElement();
}

struct UnionField {
  std::string name;
  std::string type;
};
void addUnion(tinyxml2::XMLPrinter& printer, const std::string& name,
              const std::vector<UnionField>& fields) {
  printer.OpenElement("union");

  printer.PushAttribute("id", name.c_str());

  for (const auto& [name, type] : fields) {
    printer.OpenElement("field", true);

    printer.PushAttribute("name", name.c_str());
    printer.PushAttribute("type", type.c_str());

    printer.CloseElement(true);
  }

  printer.CloseElement();
}

void addVector(tinyxml2::XMLPrinter& printer, const std::string& name,
               const std::string& type, uint16_t count) {
  printer.OpenElement("vector", true);

  printer.PushAttribute("id", name.c_str());
  printer.PushAttribute("type", type.c_str());
  printer.PushAttribute("count", count);

  printer.CloseElement(true);
}

void deriveCore(tinyxml2::XMLPrinter& printer, RegList& regs) {
  printer.OpenElement("feature");

  printer.PushAttribute("name", "org.gnu.gdb.aarch64.core");

  for (auto i = 0; i < 32; i++) {
    const auto name = "x" + std::to_string(i);

    addReg(printer, regs, 0, i, (i == 31) ? "sp" : ("x" + std::to_string(i)),
           Double, (i == 31) ? std::optional("data_ptr") : std::nullopt);
  }

  addReg(printer, regs, 0, 0, "pc", PC, "code_ptr");

  addFlags(
      printer, "cpsr_flags", 4,
      {
          {"SP", 0, 0},     {"EL", 2, 3},    {"nRW", 4, 4},   {"F", 6, 6},
          {"I", 7, 7},      {"A", 8, 8},     {"D", 9, 9},     {"BTYPE", 10, 11},
          {"SSBS", 12, 12}, {"IL", 20, 20},  {"SS", 21, 21},  {"PAN", 22, 22},
          {"UAO", 23, 23},  {"DIT", 24, 24}, {"TCO", 25, 25}, {"V", 28, 28},
          {"C", 29, 29},    {"Z", 30, 30},   {"N", 31, 31},
      });

  addReg(printer, regs, 3, 0, "cpsr", ByteWord, "cpsr_flags");

  printer.CloseElement();
}

void deriveSVE(tinyxml2::XMLPrinter& printer, RegList& regs) {
  printer.OpenElement("feature");

  printer.PushAttribute("name", "org.gnu.gdb.aarch64.sve");

  addVector(printer, "svevqu", "uint128", 16);
  addVector(printer, "svevqs", "int128", 16);
  addVector(printer, "svevdf", "ieee_double", 32);
  addVector(printer, "svevdu", "uint64", 32);
  addVector(printer, "svevds", "int64", 32);
  addVector(printer, "svevsf", "ieee_single", 64);
  addVector(printer, "svevsu", "uint32", 64);
  addVector(printer, "svevss", "int32", 64);
  addVector(printer, "svevhf", "ieee_half", 128);
  addVector(printer, "svevhu", "uint16", 128);
  addVector(printer, "svevhs", "int16", 128);
  addVector(printer, "svevbu", "uint8", 256);
  addVector(printer, "svevbs", "int8", 256);
  addVector(printer, "svep", "uint8", 32);

  addUnion(printer, "svevnq",
           {
               {"u", "svevqu"},
               {"s", "svevqs"},
           });
  addUnion(printer, "svevnd",
           {
               {"f", "svevdf"},
               {"u", "svevdu"},
               {"s", "svevds"},
           });
  addUnion(printer, "svevns",
           {
               {"f", "svevsf"},
               {"u", "svevsu"},
               {"s", "svevss"},
           });
  addUnion(printer, "svevnh",
           {
               {"f", "svevhf"},
               {"u", "svevhu"},
               {"s", "svevhs"},
           });
  addUnion(printer, "svevnb",
           {
               {"u", "svevbu"},
               {"s", "svevbs"},
           });
  addUnion(printer, "svev",
           {
               {"q", "svevnq"},
               {"d", "svevnd"},
               {"s", "svevns"},
               {"h", "svevnh"},
               {"b", "svevnb"},
           });

  addFlags(printer, "fpsr_flags", 4,
           {
               {"IOC", 0, 0},
               {"DZC", 1, 1},
               {"OFC", 2, 2},
               {"UFC", 3, 3},
               {"IXC", 4, 4},
               {"IDC", 7, 7},
               {"QC", 27, 27},
               {"V", 28, 28},
               {"C", 29, 29},
               {"Z", 30, 30},
               {"N", 31, 31},
           });
  addFlags(printer, "fpcr_flags", 4,
           {
               {"FIZ", 0, 0},
               {"AH", 1, 1},
               {"NEP", 2, 2},
               {"IOE", 8, 8},
               {"DZE", 9, 9},
               {"OFE", 10, 10},
               {"UFE", 11, 11},
               {"IXE", 12, 12},
               {"EBF", 13, 13},
               {"IDE", 15, 15},
               {"Len", 16, 18},
               {"FZ16", 19, 19},
               {"Stride", 20, 21},
               {"RMode", 22, 23},
               {"FZ", 24, 24},
               {"DN", 25, 25},
               {"AHP", 26, 26},
           });

  for (auto i = 0; i < 32; i++) {
    addReg(printer, regs, 1, i, "z" + std::to_string(i), Vector, "svev");
  }

  addReg(printer, regs, 4, 2, "fpsr", Word, "fpsr_flags");
  addReg(printer, regs, 4, 1, "fpcr", Word, "fpcr_flags");

  for (auto i = 0; i < 16; i++) {
    addReg(printer, regs, 2, i, "p" + std::to_string(i), Predicate, "svep");
  }

  addReg(printer, regs, 2, 16, "ffr", Predicate, "svep");
  addReg(printer, regs, 0, 0, "vg", VG, "int");

  printer.CloseElement();
}

void deriveSME(tinyxml2::XMLPrinter& printer, RegList& regs,
               unsigned int rows) {
  printer.OpenElement("feature");

  printer.PushAttribute("name", "org.gnu.gdb.aarch64.sme");

  addReg(printer, regs, 0, 0, "svg", SVG, "int");

  addFlags(printer, "svcr_flags", 8,
           {
               {"SM", 0, 0},
               {"ZA", 1, 1},
           });

  addReg(printer, regs, 4, 7, "svcr", Double, "svcr_flags");

  addVector(printer, "sme_bv", "uint8", 256);
  addVector(printer, "sme_bvv", "sme_bv", rows);

  addReg(printer, regs, 0, 0, "za", ZA, "sme_bvv", rows * 2048);

  printer.CloseElement();
}

TargetSpec deriveSpec() {
  TargetSpec rv;

  tinyxml2::XMLPrinter printer;

  printer.OpenElement("target");
  printer.PushAttribute("version", "1.0");

  printer.OpenElement("architecture");
  printer.PushText("aarch64");
  printer.CloseElement();

  deriveCore(printer, rv.regs);

  deriveSVE(printer, rv.regs);

  deriveSME(printer, rv.regs, 256);

  printer.CloseElement();

  rv.spec = std::string(printer.CStr(), printer.CStrSize() - 1);

  return rv;
}

TargetSpec target_spec;

void checkSpec(const simeng::CoreInstance& coreInstance) {
  if (target_spec.spec.empty()) {
    const auto core = coreInstance.getCore();
    const auto& isa = core->getISA();

    const auto [_, svl] = isa.getVectorSize();

    target_spec = deriveSpec();

    /*std::ofstream out("spec.xml");
    out << target_spec.spec;
    out.close();*/
  }
}

std::string readRegister(const RegList::value_type& which,
                         const simeng::ArchitecturalRegisterFileSet& registers,
                         uint64_t pc, uint64_t vl, uint64_t svl) {
  const auto& [reg, size] = which;

  std::string rv;

  switch (size) {
    case Byte: {
      rv += int_to_hex_ne(registers.get(reg).get<uint8_t>());
      break;
    }

    case Short: {
      rv += int_to_hex_ne(registers.get(reg).get<uint16_t>());
      break;
    }

    case Word: {
      rv += int_to_hex_ne(registers.get(reg).get<uint32_t>());
      break;
    }

    case ByteWord: {
      rv += int_to_hex_ne(registers.get(reg).zeroExtend(1, 4).get<uint32_t>());
      break;
    }

    case Double: {
      rv += int_to_hex_ne(registers.get(reg).get<uint64_t>());
      break;
    }

    case Vector: {
      const auto vect = registers.get(reg).getAsVector<uint8_t>();
      for (auto j = 0; j < 256; j++) {
        rv += int_to_hex(vect[j]);
      }
      break;
    }

    case Predicate: {
      const auto vect = registers.get(reg).getAsVector<uint8_t>();
      for (auto j = 0; j < 32; j++) {
        rv += int_to_hex(vect[j]);
      }
      break;
    }

    case PC: {
      rv += int_to_hex_ne(pc);
      break;
    }

    case VG: {
      rv += int_to_hex_ne(vl / 64);
      break;
    }

    case SVG: {
      rv += int_to_hex_ne(svl / 64);
      break;
    }

    case ZA: {
      for (uint16_t i = 0; i < 256; i++) {
        if (i < (svl / 8)) {
          const auto vect = registers.get({5, i}).getAsVector<uint8_t>();
          for (auto j = 0; j < 256; j++) {
            rv += int_to_hex(vect[j]);
          }
        } else {
          for (auto j = 0; j < 256; j++) {
            rv += "00";
          }
        }
      }
      break;
    }
  }

  return rv;
}

namespace simeng {
GDBStub::GDBStub(simeng::CoreInstance& coreInstance, bool verbose,
                 uint16_t port)
    : coreInstance_(coreInstance), verbose_(verbose), port_(port) {}

uint64_t GDBStub::run() {
  iterations = 0;

  connection = openSocket(port_);
  std::cout << "[SimEng:GDBStub] Connection to GDB client established, "
               "debugging in progress\n"
            << std::endl;

  char buffer[BUF_SIZE];

  auto running = true;

  while (running) {
    const ssize_t bytesRead = read(connection, buffer, sizeof(buffer));

    if (bytesRead == 0) {
      std::cout
          << "[SimEng:GDBStub] Client disconnected (read EOF from connection)."
          << std::endl;
      break;
    } else if (bytesRead < 0) {
      std::cerr << RED
                << "[SimEng:GDBStub] An error occurred while reading from the "
                   "connection. errno: "
                << errno << " (" << strerror(errno) << ")" << RESET
                << std::endl;
      exit(EXIT_FAILURE);
    }

    // safety: we've already checked whether bytesRead is less than 0, so we
    // know it's positive and less than SIZE_T_MAX
    auto bufferString = std::string{buffer, static_cast<size_t>(bytesRead)};

    if (verbose_) {
      std::cout << CYAN << "[SimEng:GDBStub] <- Raw packet: '" << bufferString
                << "' (" << bufferString.size() << ")" << RESET << std::endl;
    }

    if (bufferString[0] == '-') {
      sendResponse(lastResponse);
      continue;
    }

    // etx
    if (bufferString[0] == '\3') {
      sendResponse(encodePacket(formatSignal(SIGTRAP, {})));
      continue;
    }

    if (ack_mode != Disabled) {
      // '+' is an acknowledgement of successful receipt of message
      // '-' is a request for retransmission

      while (!bufferString.empty()) {
        if (bufferString[0] == '+') {
          if (verbose_) {
            std::cout << CYAN
                      << "[SimEng:GDBStub] <- Received message acknowledgement"
                      << RESET << std::endl;
          }
          bufferString = bufferString.substr(1);
          continue;
        }
        break;
      }

      if (ack_mode == Transition) {
        sendResponse("+");
        ack_mode = Disabled;
      }
    }

    // if the packet was just an acknowledgement and nothing else, bufferString
    // is now empty
    if (bufferString.empty()) {
      continue;
    }

    const auto packet = decodePacket(bufferString);

    if (packet) {
      const auto command = *packet;

      if (verbose_) {
        std::cout << GREEN << "[SimEng:GDBStub] <- " << command << RESET
                  << std::endl;
      }

      if (command.size() < 1) {
        sendResponse("-");
        continue;
      }

      std::string rawResponse;

      // safety: we've already checked whether the size was less than 1, so
      // there must be at least one character in the string
      const auto commandType = command[0];
      const auto commandParams = command.substr(1);

      if (verbose_) {
        std::cout << "[SimEng:GDBStub] <- Command " << commandType
                  << ", params " << commandParams << std::endl;
      }

      switch (command[0]) {
        case '?': {
          rawResponse = handleHaltReason();
          break;
        }

        case 'c': {
          rawResponse = handleContinue(commandParams);
          break;
        }

        case 'g': {
          rawResponse = handleReadRegisters();
          break;
        }

        case 'G': {
          rawResponse = handleWriteRegisters(commandParams);
          break;
        }

        case 'k': {
          if (verbose_) {
            std::cout << CYAN
                      << "[SimEng:GDBStub]    Received kill request from "
                         "client, exiting"
                      << RESET << std::endl;
          }
          running = false;
          continue;
        }

        case 'm': {
          rawResponse = handleReadMemory(commandParams);
          break;
        }

        case 'M': {
          rawResponse = handleWriteMemory(commandParams);
          break;
        }

        case 'p': {
          rawResponse = handleReadRegister(commandParams);
          break;
        }

        case 'P': {
          rawResponse = handleWriteRegister(commandParams);
          break;
        }

        case 'q': {
          rawResponse = handleQuery(commandParams);
          break;
        }

        case 'Q': {
          rawResponse = handleSet(commandParams);
          break;
        }

        case 's': {
          rawResponse = handleStep(commandParams);
          break;
        }

        case 'z': {
          rawResponse = handleRemoveBreakpoint(commandParams);
          break;
        }

        case 'Z': {
          rawResponse = handleAddBreakpoint(commandParams);
          break;
        }

        default: {
          // unsupported
          rawResponse = "";
          break;
        }
      }

      sendResponse(encodePacket(rawResponse));
    } else {
      sendResponse("-");
    }
  }

  return iterations;
}

std::string GDBStub::runUntilStop(const std::optional<uint64_t>& step_from) {
  const auto core = coreInstance_.getCore();
  const auto dataMemory = coreInstance_.getDataMemory();

  while (!core->hasHalted() || dataMemory->hasPendingRequests()) {
    iterations++;

    core->tick();
    dataMemory->tick();

    const auto pc = core->getProgramCounter();

    // only check breakpoints if we're not single-stepping
    if (step_from) {
      if (pc != *step_from) {
        return formatSignal(SIGTRAP, {std::make_tuple("hwbreak", "")});
      }
    } else {
      for (const auto [type, addr, kind] : breakpoints) {
        if (type == HardwareBP) {
          if (addr == pc) {
            return formatSignal(SIGTRAP, {std::make_tuple("hwbreak", "")});
          }
        }
      }
    }
  }

  // TODO: get real exit status
  return formatExit(0);
}

std::string GDBStub::handleHaltReason() {
  // for now, assume breakpoint
  return formatSignal(SIGTRAP, {std::make_tuple("hwbreak", "")});
}

std::string GDBStub::handleContinue(const std::string& addr) {
  return runUntilStop();
}

std::string GDBStub::handleReadRegister(const std::string& reg) {
  const auto core = coreInstance_.getCore();
  const auto& registers = core->getArchitecturalRegisterFileSet();
  const auto& isa = core->getISA();

  const auto pc = core->getProgramCounter();
  const auto [vl, svl] = isa.getVectorSize();

  int reg_num;
  try {
    reg_num = std::stoi(reg);
  } catch (const std::exception& e) {
    if (verbose_) {
      std::cerr << RED << "[SimEng:GDBStub] Invalid register number: " << reg
                << RESET << std::endl;
    }
    return formatError("invalid single register number");
  }

  if ((reg_num < 0) || (reg_num >= target_spec.regs.size())) {
    if (verbose_) {
      std::cerr << RED << "[SimEng:GDBStub] Reg num of range: " << reg_num
                << RESET << std::endl;
    }
    return formatError("single register number out of range");
  }

  return readRegister(target_spec.regs[reg_num], registers, pc, vl, svl);
}

std::string GDBStub::handleReadRegisters() {
  const auto core = coreInstance_.getCore();
  const auto& registers = core->getArchitecturalRegisterFileSet();
  const auto& isa = core->getISA();

  const auto pc = core->getProgramCounter();
  const auto [vl, svl] = isa.getVectorSize();

  checkSpec(coreInstance_);

  std::string rv;

  for (const auto& reg : target_spec.regs) {
    rv += readRegister(reg, registers, pc, vl, svl);
  }

  return rv;
}

std::string GDBStub::handleWriteRegister(
    const std::string& raw_register_value) {
  const auto register_value = splitBy(raw_register_value, '=');

  if (register_value.size() != 2) {
    if (verbose_) {
      std::cerr
          << RED
          << "[SimEng:GDBStub] Invalid number of parameters to a register write"
          << RESET << std::endl;
    }
    return formatError("invalid number of parameters for register write");
  }

  int reg_num;
  try {
    reg_num = std::stoi(register_value[0]);
  } catch (const std::exception& e) {
    if (verbose_) {
      std::cerr << RED << "[SimEng:GDBStub] Invalid register number: "
                << register_value[0] << RESET << std::endl;
    }
    return formatError("invalid single register number");
  }

  if ((reg_num < 0) || (reg_num >= target_spec.regs.size())) {
    if (verbose_) {
      std::cerr << RED << "[SimEng:GDBStub] Reg num of range: " << reg_num
                << RESET << std::endl;
    }
    return formatError("single register number out of range");
  }

  // TODO: actually do the register write

  return "OK";
}

std::string GDBStub::handleWriteRegisters(const std::string& register_values) {
  auto core = coreInstance_.getCore();
  auto& registers = core->getArchitecturalRegisterFileSet();
  const auto& isa = core->getISA();

  const auto& reg_layout = simeng::config::SimInfo::getPhysRegStruct();

  const auto error = [&] {
    if (verbose_) {
      std::cerr << RED << "[SimEng:GDBStub] Invalid register set write" << RESET
                << std::endl;
    }
    return formatError("invalid register set write");
  };

  // TODO: actually do the register write

  return "OK";
}

std::string GDBStub::handleReadMemory(const std::string& raw_params) {
  const auto params = splitBy(raw_params, ',');

  if (params.size() != 2) {
    if (verbose_) {
      std::cerr
          << RED
          << "[SimEng:GDBStub] Invalid number of parameters to a memory read"
          << RESET << std::endl;
    }
    return formatError(0);
  }

  unsigned long long startAddress;
  unsigned long long numberOfBytes;

  try {
    startAddress = std::stoull(params[0], nullptr, 16);
  } catch (const std::exception& e) {
    if (verbose_) {
      std::cerr << RED << "[SimEng:GDBStub] Memory read address invalid"
                << RESET << std::endl;
    }
    return formatError(1);
  };

  try {
    numberOfBytes = std::stoull(params[1], nullptr, 16);
  } catch (const std::exception& e) {
    if (verbose_) {
      std::cerr << RED << "[SimEng:GDBStub] Memory read length invalid" << RESET
                << std::endl;
    }
    return formatError(2);
  };

  const char* const memoryPointer =
      coreInstance_.getDataMemory()->getMemoryPointer() + startAddress;

  // TODO: stack overflow on large reads?
  uint8_t buffer[numberOfBytes];

  if (verbose_) {
    std::cout << "[SimEng:GDBStub]    Reading " << numberOfBytes
              << " bytes from memory address " << int_to_hex(startAddress)
              << std::endl;
  }

  memcpy(buffer, memoryPointer, numberOfBytes);

  std::string rv;
  for (const auto byte : buffer) {
    rv += int_to_hex(byte);
  }

  return rv;
}
std::string GDBStub::handleWriteMemory(const std::string& raw_params) {
  const auto data = splitBy(raw_params, ':');

  if (data.size() != 2) {
    if (verbose_) {
      std::cerr
          << RED
          << "[SimEng:GDBStub] Invalid number of parameters to a memory write"
          << RESET << std::endl;
    }
    return formatError(0);
  }

  const auto params = splitBy(data[0], ',');

  if (params.size() != 2) {
    if (verbose_) {
      std::cerr
          << RED
          << "[SimEng:GDBStub] Invalid number of parameters to a memory write"
          << RESET << std::endl;
    }
    return formatError(1);
  }

  unsigned long long startAddress;
  unsigned long long numberOfBytes;

  try {
    startAddress = std::stoull(params[0], nullptr, 16);
  } catch (const std::exception& e) {
    if (verbose_) {
      std::cerr << RED << "[SimEng:GDBStub] Memory write address invalid"
                << RESET << std::endl;
    }
    return formatError(2);
  };

  try {
    numberOfBytes = std::stoull(params[1], nullptr, 16);
  } catch (const std::exception& e) {
    if (verbose_) {
      std::cerr << RED << "[SimEng:GDBStub] Memory write length invalid"
                << RESET << std::endl;
    }
    return formatError(3);
  };

  if (data[1].size() != numberOfBytes * 2) {
    if (verbose_) {
      std::cerr << RED << "[SimEng:GDBStub] Memory write data length invalid"
                << RESET << std::endl;
    }
    return formatError(4);
  }

  char* const memoryPointer =
      coreInstance_.getDataMemory()->getMemoryPointer() + startAddress;

  // TODO: stack overflow on large writes?
  uint8_t buffer[numberOfBytes];

  try {
    for (size_t i = 0; i < numberOfBytes; i++) {
      buffer[i] = std::stoi(data[1].substr(i * 2, 2), nullptr, 16);
    }
  } catch (const std::exception& e) {
    if (verbose_) {
      std::cerr << RED << "[SimEng:GDBStub] Memory write data invalid" << RESET
                << std::endl;
    }
    return formatError(5);
  }

  if (verbose_) {
    std::cout << "[SimEng:GDBStub]    Writing " << numberOfBytes
              << " bytes to memory address " << int_to_hex(startAddress)
              << std::endl;
  }

  memcpy(memoryPointer, buffer, numberOfBytes);

  return "OK";
}

std::string GDBStub::handleQuery(const std::string& query) {
  // parse out the query
  // any number of any character except :, optionally followed by : and then any
  // number of any character
  const std::regex query_regex("^([^:]+)(?::(.*))?$");
  std::smatch query_match;

  if (regex_match(query, query_match, query_regex)) {
    // safety: we know that the match succeeded and the first capture group is
    // non-optional
    const auto query_type = query_match[1].str();
    const auto query_params = (query_match.size() == 3)
                                  ? std::optional{query_match[2].str()}
                                  : std::nullopt;

    if (query_type == "Supported") {
      if (query_params) {
        const auto params = splitBy(*query_params, ';');

        for (const auto& param : params) {
          // here's where we would handle the features GDB supports, if we cared
          // at all
          if (verbose_) {
            std::cout << param << std::endl;
          }
        }

        std::string features;
        for (const auto& feature : supported_features) {
          features += feature.format();
          features += ';';
        }

        if (features.back() == ';') {
          features.pop_back();
        }

        return features;
      } else {
        if (verbose_) {
          std::cerr << RED
                    << "[SimEng:GDBStub] 'Supported' query requires parameters"
                    << RESET << std::endl;
        }
        return "";
      }
    } else if (query_type == "Xfer") {
      if (query_params) {
        const auto params = splitBy(*query_params, ':');

        const auto transfer_type = params[0];

        if (transfer_type == "features") {
          return queryFeatures(params);
        }

        return "l";
      } else {
        if (verbose_) {
          std::cerr << RED
                    << "[SimEng:GDBStub] 'Supported' query requires parameters"
                    << RESET << std::endl;
        }
        return "";
      }
    } else {
      if (verbose_) {
        std::cerr << RED << "[SimEng:GDBStub] Unsupported query type '"
                  << query_type << "'" << RESET << std::endl;
      }
      return "";
    }
  } else {
    if (verbose_) {
      std::cerr << RED << "[SimEng:GDBStub] Invalid query '" << query << "'"
                << RESET << std::endl;
    }
    return "";
  }
}

std::string GDBStub::handleSet(const std::string& set) {
  // parse out the set
  // any number of any character except :, optionally followed by : and then any
  // number of any character
  const std::regex set_regex("^([^:]+)(?::(.*))?$");
  std::smatch set_match;

  if (regex_match(set, set_match, set_regex)) {
    // safety: we know that the match succeeded and the first capture group is
    // non-optional
    const auto set_type = set_match[1].str();
    const auto set_params = (set_match.size() == 3)
                                ? std::optional{set_match[2].str()}
                                : std::nullopt;

    if (set_type == "StartNoAckMode") {
      ack_mode = Transition;
      return "OK";
    } else {
      if (verbose_) {
        std::cerr << RED << "[SimEng:GDBStub] Unsupported set type '"
                  << set_type << "'" << RESET << std::endl;
      }
      return "";
    }
  } else {
    if (verbose_) {
      std::cerr << RED << "[SimEng:GDBStub] Invalid set '" << set << "'"
                << RESET << std::endl;
    }
    return "";
  }
}

std::string GDBStub::handleStep(const std::string& addr) {
  // auto [op, size] = getCurrentInstruction(coreInstance_);

  const auto core = coreInstance_.getCore();
  const auto pc = core->getProgramCounter();

  return runUntilStop(pc);
}

std::string GDBStub::handleRemoveBreakpoint(const std::string& raw_params) {
  const auto params = splitBy(raw_params, ',');

  if (params.size() != 3) {
    if (verbose_) {
      std::cerr << RED
                << "[SimEng:GDBStub] Invalid number of parameters to a "
                   "breakpoint remove"
                << RESET << std::endl;
    }
    return formatError("invalid number of parameters");
  }

  unsigned int type;
  unsigned long long address;
  unsigned int kind;

  try {
    type = std::stoi(params[0], nullptr, 16);
  } catch (const std::exception& e) {
    if (verbose_) {
      std::cerr << RED << "[SimEng:GDBStub] Breakpoint type invalid" << RESET
                << std::endl;
    }
    return formatError("invalid breakpoint type");
  };

  try {
    address = std::stoull(params[1], nullptr, 16);
  } catch (const std::exception& e) {
    if (verbose_) {
      std::cerr << RED << "[SimEng:GDBStub] Breakpoint address invalid" << RESET
                << std::endl;
    }
    return formatError("invalid breakpoint address");
  };

  try {
    kind = std::stoi(params[2], nullptr, 16);
  } catch (const std::exception& e) {
    if (verbose_) {
      std::cerr << RED << "[SimEng:GDBStub] Breakpoint kind invalid" << RESET
                << std::endl;
    }
    return formatError("invalid breakpoint kind");
  };

  if (type < SWStepBP) {
    if (type == SoftwareBP) {
      // TODO: convince GDB we really don't support software breakpoints
      type = HardwareBP;
    }

    bool found = false;
    for (auto it = breakpoints.begin(); it < breakpoints.end(); it++) {
      if (*it ==
          std::make_tuple(static_cast<BreakpointType>(type), address, kind)) {
        breakpoints.erase(it);

        found = true;

        // avoid deleting twice
        break;
      }
    }

    if (found) {
      return "OK";
    } else {
      return "";
    }
  } else {
    return "";
  }
}

std::string GDBStub::handleAddBreakpoint(const std::string& raw_params) {
  const auto params = splitBy(raw_params, ',');

  if (params.size() != 3) {
    if (verbose_) {
      std::cerr
          << RED
          << "[SimEng:GDBStub] Invalid number of parameters to a breakpoint set"
          << RESET << std::endl;
    }
    return formatError("invalid number of parameters");
  }

  unsigned int type;
  unsigned long long address;
  unsigned int kind;

  try {
    type = std::stoi(params[0], nullptr, 16);
  } catch (const std::exception& e) {
    if (verbose_) {
      std::cerr << RED << "[SimEng:GDBStub] Breakpoint type invalid" << RESET
                << std::endl;
    }
    return formatError("invalid breakpoint type");
  };

  try {
    address = std::stoull(params[1], nullptr, 16);
  } catch (const std::exception& e) {
    if (verbose_) {
      std::cerr << RED << "[SimEng:GDBStub] Breakpoint address invalid" << RESET
                << std::endl;
    }
    return formatError("invalid breakpoint address");
  };

  try {
    kind = std::stoi(params[2], nullptr, 16);
  } catch (const std::exception& e) {
    if (verbose_) {
      std::cerr << RED << "[SimEng:GDBStub] Breakpoint kind invalid" << RESET
                << std::endl;
    }
    return formatError("invalid breakpoint kind");
  };

  if (type < SWStepBP) {
    if (type == SoftwareBP) {
      // TODO: convince GDB we really don't support software breakpoints
      type = HardwareBP;
    }

    breakpoints.push_back(
        Breakpoint{static_cast<BreakpointType>(type), address, kind});

    return "OK";
  } else {
    return "";
  }
}

std::string GDBStub::queryFeatures(const std::vector<std::string>& params) {
  if (params.size() != 4) {
    if (verbose_) {
      std::cerr << RED
                << "[SimEng:GDBStub] Received transfer query with incorrect "
                   "number of parameters"
                << RESET << std::endl;
    }
    return formatError(
        "invalid number of parameters to features transfer query");
  }

  const auto& type = params[1];
  const auto& annex = params[2];
  const auto& where = splitBy(params[3], ',');
  if (where.size() != 2) {
    if (verbose_) {
      std::cerr << RED
                << "[SimEng:GDBStub] Received transfer query with incorrect "
                   "offset/length info"
                << RESET << std::endl;
    }
    return formatError(
        "invalid offset/length info in features transfer request");
  }
  int offset;
  int length;
  try {
    offset = std::stoi(where[0], nullptr, 16);
    length = std::stoi(where[1], nullptr, 16);

    // TODO: awful
    if ((offset < 0) || (length < 0)) {
      throw std::exception();
    }
  } catch (const std::exception& e) {
    if (verbose_) {
      std::cerr << RED
                << "[SimEng:GDBStub] Invalid offset or length parameters to "
                   "transfer query"
                << RESET << std::endl;
    }
    return formatError(
        "invalid offset or length parameters in transfer request");
  }

  checkSpec(coreInstance_);

  const auto max_len = target_spec.spec.size() - offset;
  if (length > max_len) {
    length = max_len;
  }

  if (type != "read") {
    if (verbose_) {
      std::cerr
          << RED
          << "[SimEng:GDBStub] Received unsupported non-read transfer query"
          << RESET << std::endl;
    }
    return formatError("invalid non-read features transfer query");
  }

  if (annex == "target.xml") {
    if (length > 1) {
      return "m" + target_spec.spec.substr(offset, length);
    } else {
      return "l";
    }
  } else {
    if (verbose_) {
      std::cerr << RED
                << "[SimEng:GDBStub] Received unsupported read transfer query "
                   "of file '"
                << annex << "'" << RESET << std::endl;
    }
    return formatError("invalid file for features transfer query");
  }
}

std::optional<std::string> GDBStub::decodePacket(
    const std::string& encodedPacket) {
  enum ParseState {
    ExpectStart,
    Packet,
    Escape,
    Checksum,
    Done,
    ExtraData,
  };

  std::string rv;

  ParseState state = ExpectStart;

  uint8_t calculatedChecksum;
  uint8_t receivedChecksum;

  auto checksumRemaining = 2;

  for (const auto& c : encodedPacket) {
    switch (state) {
      case ExpectStart: {
        switch (c) {
          case '$': {
            state = Packet;
            break;
          }

          case '-':
          case '+': {
            if (verbose_) {
              std::cerr << RED
                        << "[SimEng:GDBStub] Unexpected acknowledgement in "
                           "packet (should have been handled already)"
                        << RESET << std::endl;
            }
            break;
          }

          default: {
            if (verbose_) {
              std::cerr << RED << "[SimEng:GDBStub] Unexpected character '" << c
                        << "' in packet" << RESET << std::endl;
            }
            break;
          }
        }

        break;
      }
      case Packet: {
        switch (c) {
          case '}': {
            state = Escape;
            break;
          }

          case '#': {
            state = Checksum;

            // do not add the hash to the checksum
            continue;
          }

          case '$': {
            if (verbose_) {
              std::cerr << RED
                        << "[SimEng:GDBStub] Invalid character '$' in packet"
                        << RESET << std::endl;
            }

            // return error
            return std::nullopt;
          }

          default: {
            rv += c;
            break;
          }
        }

        calculatedChecksum += c;

        break;
      }
      case Escape: {
        rv += c ^ 0x20;
        calculatedChecksum += c;

        state = Packet;

        break;
      }
      case Checksum: {
        receivedChecksum <<= 4;
        switch (c) {
          case '0' ... '9': {
            receivedChecksum |= c - '0';
            break;
          }
          case 'A' ... 'F': {
            receivedChecksum |= c - 'A' + 10;
            break;
          }
          case 'a' ... 'f': {
            receivedChecksum |= c - 'a' + 10;
            break;
          }
          default: {
            if (verbose_) {
              std::cerr << RED << "[SimEng:GDBStub] Invalid character '" << c
                        << "' in checksum" << RESET << std::endl;
            }

            // return error
            return std::nullopt;
          }
        }

        checksumRemaining--;
        if (checksumRemaining <= 0) {
          state = Done;
        }

        break;
      }
      case Done: {
        if (verbose_) {
          std::cerr
              << RED
              << "[SimEng:GDBStub] More data follows after packet, ignoring"
              << RESET << std::endl;
        }
        state = ExtraData;

        break;
      }

      case ExtraData: {
        // do nothing
        break;
      }
    }
  }

  if ((state != Done) && (state != ExtraData)) {
    if (verbose_) {
      std::cerr << RED << "[SimEng:GDBStub] Invalid packet '" << encodedPacket
                << "' (unexpected end state)" << RESET << std::endl;
    }

    // return error
    return std::nullopt;
  }

  if (calculatedChecksum != receivedChecksum) {
    if (verbose_) {
      std::cerr << RED << std::hex
                << "[SimEng:GDBStub] Packet checksum does not match expected; "
                   "received "
                << int_to_hex(receivedChecksum) << ", calculated " << int_to_hex(calculatedChecksum)
                << std::dec << RESET << std::endl;
    }

    // return error
    return std::nullopt;
  }

  return rv;
}

std::string GDBStub::encodePacket(const std::string& response) {
  // naïve approach: don't handle run-length encoding

  uint8_t checksum;
  std::string rv;

  auto calcChar = [&](const auto c) {
    checksum += c;
    rv += c;
  };

  rv += '$';

  for (const auto& c : response) {
    switch (c) {
      case '#':
      case '$':
      case '}':
      case '*': {
        calcChar('}');
        calcChar(c ^ 0x20);
        break;
      }

      default: {
        calcChar(c);
      }
    }
  }

  rv += '#';

  rv += int_to_hex(checksum);

  return rv;
}

void GDBStub::sendResponse(const std::string& response) {
  if (verbose_) {
    std::cout << GREEN << "[SimEng:GDBStub] -> " << response << RESET
              << std::endl;
  }

  const auto bytesSent = send(connection, response.data(), response.size(), 0);
  if (bytesSent < 0) {
    std::cerr << RED << "[SimEng:GDBStub] Error retransmitting packet. errno: "
              << errno << " (" << strerror(errno) << ")" << RESET << std::endl;
    exit(EXIT_FAILURE);
  }
  lastResponse = response;
}

// this is a static function
int GDBStub::openSocket(const uint16_t port) {
  // Create an INET stream socket, picking the protocol automatically
  const auto sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd == -1) {
    std::cerr << RED
              << "[SimEng:GDBStub]    Failed to create socket. errno: " << errno
              << " (" << strerror(errno) << ")" << RESET << std::endl;
    exit(EXIT_FAILURE);
  }

  sockaddr_in sockaddr;
  sockaddr.sin_family = AF_INET;
  sockaddr.sin_addr.s_addr = INADDR_ANY;
  sockaddr.sin_port =
      htons(port);  // convert the native integer to network byte order

  const auto addrlen = sizeof(sockaddr);

  if (bind(sockfd, (struct sockaddr*)&sockaddr, addrlen) < 0) {
    std::cerr << RED << "[SimEng:GDBStub]    Failed to bind to port " << port
              << ". errno: " << errno << " (" << strerror(errno) << ")" << RESET
              << std::endl;
    exit(EXIT_FAILURE);
  } else {
    std::cout << "[SimEng:GDBStub] Started listening on port " << port
              << std::endl;
  }

  // Start listening
  if (listen(sockfd, NUM_REQUESTS) < 0) {
    std::cerr << RED
              << "[SimEng:GDBStub]    Failed to listen on socket. errno: "
              << errno << " (" << strerror(errno) << ")" << RESET << std::endl;
    exit(EXIT_FAILURE);
  }

  // safety assumption: addrlen fits into a socklen_t
  //   this should always hold, since sizeof(sockaddr) is pretty small (~16) in
  // all sane cases
  auto realAddrLen = (socklen_t)addrlen;

  // Grab a connection from the queue
  const auto connection =
      accept(sockfd, (struct sockaddr*)&sockaddr, &realAddrLen);
  if (connection < 0) {
    std::cerr << RED << "[SimEng:GDBStub]    Failed to grab connection. errno: "
              << errno << " (" << strerror(errno) << ")" << RESET << std::endl;
    exit(EXIT_FAILURE);
  }

  return connection;
}

}  // namespace simeng