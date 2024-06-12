#include "simeng/GDBStub.hh"

#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iomanip>
#include <regex>

#include "simeng/arch/Architecture.hh"

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

const SupportedFeature supported_features[] = {
    {
        "QStartNoAckMode",
        std::nullopt,
    },
    {"PacketSize", int_to_hex(BUF_SIZE - 10)},
    {"hwbreak", std::nullopt}};

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

  while (true) {
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

      sendResponse("+");

      if (ack_mode == Transition) {
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

        case 'm': {
          rawResponse = handleReadMemory(commandParams);
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

std::string GDBStub::runUntilStop() {
  const auto core = coreInstance_.getCore();
  const auto dataMemory = coreInstance_.getDataMemory();

  while (!core->hasHalted() || dataMemory->hasPendingRequests()) {
    iterations++;

    core->tick();
    dataMemory->tick();

    const auto pc = core->getProgramCounter();

    for (const auto [type, addr, kind] : step_breakpoints) {
      if (addr == pc) {
        // step breakpoints should only be hit once
        step_breakpoints.clear();

        return formatSignal(
            SIGTRAP,
            {std::make_tuple((type == SWStepBP) ? "swbreak" : "hwbreak", "")});
      }
    }

    for (const auto [type, addr, kind] : breakpoints) {
      if (type == HardwareBP) {
        if (addr == pc) {
          return formatSignal(SIGTRAP, {std::make_tuple("hwbreak", "")});
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

std::string GDBStub::handleReadRegisters() {
  const auto core = coreInstance_.getCore();
  const auto& registers = core->getArchitecturalRegisterFileSet();

  std::string rv;

  // TODO: support register configurations other than 32 64-bit GPRs
  for (auto i = 0; i < 32; i++) {
    const auto value = registers.get({0, i}).get<uint64_t>();
    rv += int_to_hex_ne(value);
  }

  // pc
  rv += int_to_hex_ne(core->getProgramCounter());

  // NZCV
  rv += int_to_hex_ne(registers.get({3, 0}).zeroExtend(1, 4).get<uint32_t>());

  return rv;
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
  auto [op, size] = getCurrentInstruction(coreInstance_);

  const auto core = coreInstance_.getCore();
  const auto pc = core->getProgramCounter();
  const auto& registerFileSet = core->getArchitecturalRegisterFileSet();

  if (op->isBranch()) {
    // Issue
    auto registers = op->getSourceRegisters();
    for (size_t i = 0; i < registers.size(); i++) {
      auto reg = registers[i];
      if (!op->isOperandReady(i)) {
        op->supplyOperand(i, registerFileSet.get(reg));
      }
    }

    // we could look at the branch type to determine whether to put breakpoints
    // at both targets (the branch target and the next instruction) or not, but
    // there's not much point
    // TODO: this will probably break with delay slots like in MIPS

    // is this necessary? we need the real branch address
    op->execute();

    step_breakpoints.push_back(Breakpoint{HWStepBP, op->getBranchAddress(), 0});
    step_breakpoints.push_back(Breakpoint{HWStepBP, pc + size, 0});
  } else {
    if (verbose_) {
      std::cout << GREEN
                << "[SimEng:GDBStub] Step breakpoint: " << int_to_hex(pc + size)
                << RESET << std::endl;
    }
    step_breakpoints.push_back(Breakpoint{HWStepBP, pc + size, 0});
  }

  return runUntilStop();
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
                << receivedChecksum << ", calculated " << calculatedChecksum
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