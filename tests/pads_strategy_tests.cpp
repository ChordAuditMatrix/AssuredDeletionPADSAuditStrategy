/* SPDX-License-Identifier: GPL-3.0-or-later */
/** @file pads_strategy_tests.cpp
 *  @brief CoreLib lifecycle smoke test for PADS secure deletion. */

#include "AssuredDeletionPADSAuditStrategy/strategy.h"

#include "ChordAuditMatrixLib/implementations/audit/data/memory_audit_block_source.h"
#include "ChordAuditMatrixLib/interfaces/audit/engine.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/audit_data_map.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/raw_input.h"
#include "ChordAuditMatrixLib/interfaces/audit/operation_context.h"

#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

#include <json/json.h>

namespace {
using CAMatrix::Audit::Core::AuditEngineFactory;
using CAMatrix::Audit::Core::AuditOperationContext;
using CAMatrix::Audit::Data::AuditBlockSourcePtr;
using CAMatrix::Audit::Data::MemoryAuditBlockSource;
using CAMatrix::Audit::Messages::AuditDataMap;
using CAMatrix::Audit::Messages::MaintenanceOpType;
using CAMatrix::Audit::Messages::RawInput;

RawInput jsonInput(const Json::Value &value) {
  return RawInput(std::make_shared<std::string>(Json::FastWriter().write(value)));
}

bool verify(CAMatrix::Audit::Core::AuditEngine &engine,
            AuditOperationContext &context, bool replay) {
  auto proofInput = std::make_shared<AuditDataMap>();
  proofInput->emplace("adversarialReplay", replay);
  engine.generateProofs(RawInput(proofInput), context);
  if (!context.generateProofsResult || !context.generateProofsResult->proves)
    return false;
  engine.verifyProofs(RawInput{}, context);
  return context.verifyProofsResult && context.verifyProofsResult->ok;
}
} // namespace

int main() {
  using Strategy = CAMatrix::Audit::Strategies::AssuredDeletionPADSAuditStrategy;
  try {
    auto engine = AuditEngineFactory::createInstance();
    engine->setStrategy(std::make_shared<Strategy>());
    AuditOperationContext context;
    engine->initializeAlgorithm(RawInput{}, context);
    engine->generateKeys(RawInput{}, context);

    auto blocks = std::make_shared<MemoryAuditBlockSource>(
        std::vector<std::vector<std::uint8_t>>{{1, 2, 3, 4}, {5, 6, 7, 8},
                                                {9, 10, 11, 12}, {13, 14, 15, 16}},
        4, 0);
    auto tagInput = std::make_shared<AuditDataMap>();
    tagInput->emplace("blocks", AuditBlockSourcePtr(blocks));
    tagInput->emplace("fileId", std::string("pads-test-file"));
    engine->generateTags(RawInput(tagInput), context);
    if (!context.generateTagsResult || !context.generateTagsResult->tags)
      return EXIT_FAILURE;

    Json::Value updateInput;
    updateInput["fileId"] = "pads-test-file";
    updateInput["opType"] = static_cast<unsigned>(MaintenanceOpType::Update);
    updateInput["deletionMode"] = true;
    updateInput["permutationKey"] = 20260930;
    updateInput["seed"] = "pads-test-seed";
    updateInput["targetBlockIndices"] = Json::Value(Json::arrayValue);
    updateInput["targetBlockIndices"].append(2);
    engine->maintain(jsonInput(updateInput), context);
    if (!context.maintainResult || !context.maintainResult->tags)
      return EXIT_FAILURE;

    Json::Value challengeInput;
    challengeInput["fileId"] = "pads-test-file";
    challengeInput["challengeCount"] = 4;
    challengeInput["seed"] = 20260930;
    engine->generateChallenges(jsonInput(challengeInput), context);
    if (!context.generateChallengesResult ||
        !context.generateChallengesResult->challenges)
      return EXIT_FAILURE;

    if (!verify(*engine, context, false))
      return EXIT_FAILURE;
    return verify(*engine, context, true) ? EXIT_FAILURE : EXIT_SUCCESS;
  } catch (...) {
    return EXIT_FAILURE;
  }
}
