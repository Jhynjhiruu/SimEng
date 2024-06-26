#pragma once

#include <optional>

#include "simeng/CoreInstance.hh"

enum AckMode {
  Enabled,
  Transition,
  Disabled,
};

enum BreakpointType {
  SoftwareBP,
  HardwareBP,
  WriteWP,
  ReadWP,
  AccessWP,
  SWStepBP,
  HWStepBP
};

struct Breakpoint {
  BreakpointType type;
  uint64_t addr;
  unsigned int kind;
};

enum ParseState {
  ExpectStart,
  Packet,
  Escape,
  Checksum,
  Done,
  ExtraData,
};

struct ParseResult {
  ParseState state;
  std::string packet;
  uint8_t calculatedChecksum;
  uint8_t receivedChecksum;
  unsigned int checksumRemaining;

  bool done() const { return (state == Done) || (state == ExtraData); }

  bool valid() const { return calculatedChecksum == receivedChecksum; }
};

namespace simeng {
/** A GDB server stub, allowing for remote connections from a GDB client via
 * GDB's Remote Serial Protocol (RSP) in order to debug programs running on
 * the simulator. This class is only compiled when the GDB_ENABLED build
 * option is set. */
class GDBStub {
 public:
  /** Construct a GDBStub with a reference to a CoreInstance. */
  GDBStub(simeng::CoreInstance& coreInstance, bool verbose, uint16_t port);

  /** Run the GDBStub using the CoreInstance. This hands over execution to the
   * stub, allowing it to control the emulation core, ready for a GDB client
   * to send it commands via the provided port. */
  uint64_t run();

 private:
  /** The CoreInstance used for the simulation. */
  simeng::CoreInstance& coreInstance_;

  /** Whether to print verbose messages or not */
  bool verbose_;

  /** The port to listen on */
  uint16_t port_;

  /** Enum for whether to send and handle acknowledgements. */
  AckMode ack_mode = Enabled;

  /** The last response sent to the client, in case it needs retransmitting.
   */
  std::string lastResponse = "";

  /** File descriptor for the connection to the client. */
  int connection;

  /** Number of ticks executed */
  uint64_t iterations;

  /** Currently active breakpoints */
  std::vector<Breakpoint> breakpoints;

  /** Breakpoints for a step operation */
  std::vector<Breakpoint> step_breakpoints;

  /** Run until a breakpoint or end-of-program is reached */
  std::string runUntilStop(
      const std::optional<uint64_t>& step_from = std::nullopt);

  /** Handle a ? query */
  std::string handleHaltReason();

  /** Continue program */
  std::string handleContinue(const std::string& addr);

  /** Read single register */
  std::string handleReadRegister(const std::string& reg);

  /** Read all registers */
  std::string handleReadRegisters();

  /** Write single register */
  std::string handleWriteRegister(const std::string& register_value);

  /** Write all registers */
  std::string handleWriteRegisters(const std::string& register_values);

  /** Read memory */
  std::string handleReadMemory(const std::string& raw_params);

  /** Write memory */
  std::string handleWriteMemory(const std::string& raw_params);

  /** Handle general query packets, e.g. qSupported */
  std::string handleQuery(const std::string& query);

  /** Handle general set packets, e.g. QStartNoAckMode */
  std::string handleSet(const std::string& set);

  /** Single step */
  std::string handleStep(const std::string& addr);

  /** Handle removing a breakpoint */
  std::string handleRemoveBreakpoint(const std::string& raw_params);

  /** Handle adding a breakpoint */
  std::string handleAddBreakpoint(const std::string& raw_params);

  /** Handle Xfer:features query */
  std::string queryFeatures(const std::vector<std::string>& params);

  /** Decode a packet, handling escape sequences and verifying the checksum */
  std::optional<ParseResult> decodePacket(const std::string& encodedPacket,
                                          ParseResult result);

  /** Encode a packet, handling escape sequences and calculating the checksum */
  std::string encodePacket(const std::string& response);

  /** Send a response to the client, storing it in case it needs
   * retransmitting.
   */
  void sendResponse(const std::string& response);

  /** Create a socket and listen on the port number provided.
   * Socket handling code modified from:
   * https://ncona.com/2019/04/building-a-simple-server-with-cpp/. */
  static int openSocket(const uint16_t port);
};

}  // namespace simeng