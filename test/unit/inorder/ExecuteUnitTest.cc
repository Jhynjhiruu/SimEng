#include "../MockBranchPredictor.hh"
#include "../MockInstruction.hh"
#include "inorder/ExecuteUnit.hh"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace simeng {
namespace inorder {

using ::testing::AtLeast;
using ::testing::ElementsAre;
using ::testing::Invoke;
using ::testing::IsEmpty;
using ::testing::Property;
using ::testing::Return;

class MockExecutionHandlers {
 public:
  MOCK_METHOD2(forwardOperands,
               void(const span<Register>, const span<RegisterValue>));
  MOCK_METHOD1(raiseException, void(std::shared_ptr<Instruction> instruction));
};

class InOrderExecuteUnitTest : public testing::Test {
 public:
  InOrderExecuteUnitTest()
      : input(1, nullptr),
        output(1, nullptr),
        executeUnit(
            input, output,
            [this](auto regs, auto values) {
              executionHandlers.forwardOperands(regs, values);
            },
            predictor,
            [this](auto instruction) {
              executionHandlers.raiseException(instruction);
            },
            nullptr),
        uop(new MockInstruction),
        uopPtr(uop) {}

 protected:
  PipelineBuffer<std::shared_ptr<Instruction>> input;
  PipelineBuffer<std::shared_ptr<Instruction>> output;
  MockBranchPredictor predictor;
  MockExecutionHandlers executionHandlers;

  ExecuteUnit executeUnit;

  MockInstruction* uop;
  std::shared_ptr<Instruction> uopPtr;
};

// Tests that the execution unit processes nothing if no instruction is present
TEST_F(InOrderExecuteUnitTest, TickEmpty) {
  // Check that an empty operand forwarding call is made
  EXPECT_CALL(executionHandlers, forwardOperands(IsEmpty(), IsEmpty()))
      .Times(1);

  executeUnit.tick();

  EXPECT_EQ(output.getTailSlots()[0], nullptr);
}

// Tests that the execution unit executes an instruction and forwards the
// results
TEST_F(InOrderExecuteUnitTest, Execute) {
  input.getHeadSlots()[0] = uopPtr;

  EXPECT_CALL(*uop, execute()).Times(1);

  std::vector<Register> registers = {{0, 1}};
  std::vector<RegisterValue> values = {RegisterValue(1, 4)};
  // Check that the results/registers are retrieved
  EXPECT_CALL(*uop, getResults())
      .WillOnce(Return(span<RegisterValue>(values.data(), values.size())));
  EXPECT_CALL(*uop, getDestinationRegisters())
      .WillOnce(Return(span<Register>(registers.data(), registers.size())));

  // Check that the results/registers are forwarded
  EXPECT_CALL(
      executionHandlers,
      forwardOperands(ElementsAre(registers[0]),
                      ElementsAre(Property(&RegisterValue::get<uint32_t>, 1))))
      .Times(1);

  executeUnit.tick();

  EXPECT_EQ(output.getTailSlots()[0].get(), uop);
}

TEST_F(InOrderExecuteUnitTest, ExecuteBranch) {
  input.getHeadSlots()[0] = uopPtr;

  // Anticipate testing instruction type; return true for branch
  ON_CALL(*uop, isBranch()).WillByDefault(Return(true));

  const bool taken = true;
  const uint64_t pc = 1;
  const uint64_t insnAddress = 2;

  uop->setInstructionAddress(insnAddress);
  uop->setBranchPrediction({taken, pc});

  EXPECT_CALL(*uop, execute()).WillOnce(Invoke([&]() {
    uop->setExecuted(true);
    uop->setBranchResults(taken, pc);
  }));

  // Check that the branch predictor was updated with the results
  EXPECT_CALL(predictor, update(insnAddress, taken, pc)).Times(1);

  // Check that empty forwarding call is made
  EXPECT_CALL(executionHandlers, forwardOperands(IsEmpty(), IsEmpty()))
      .Times(1);

  executeUnit.tick();

  EXPECT_EQ(executeUnit.shouldFlush(), false);
  EXPECT_EQ(output.getTailSlots()[0].get(), uop);
}

}  // namespace inorder
}  // namespace simeng