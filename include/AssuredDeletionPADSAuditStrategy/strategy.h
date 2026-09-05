/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef CAMATRIX_ASSURED_DELETION_PADS_STRATEGY_H
#define CAMATRIX_ASSURED_DELETION_PADS_STRATEGY_H

#include "ChordAuditMatrixLib/interfaces/audit/dynamic_strategy.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/request_result.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace CAMatrix::Audit::Strategies {

/** Native lifecycle implementation of PADS: keyed-permutation overwrite,
 * hash authentication, deletion challenge, proof, and verification. */
class AssuredDeletionPADSAuditStrategy final
    : public CAMatrix::Audit::Core::DynamicAuditStrategy {
public:
  std::string algorithmType() const override { return "AssuredDeletionPADS"; }
  std::string version() const override { return "2.0.0"; }
  CAMatrix::Audit::Messages::Capabilities caps() const override;
  CAMatrix::Audit::Core::StateMaintenanceParty
  stateMaintenanceParty() const override;
  std::shared_ptr<CAMatrix::Audit::Core::DynamicPdpStateStore> createStateStore(
      CAMatrix::Audit::Core::BlockMetadataFactory) const override;
  void
  setAlgorithm(CAMatrix::Crypto::CryptoGeneralAlgorithmPtr algorithm) override;
  CAMatrix::Audit::Messages::InitializeAlgorithmResult initializeAlgorithm(
      const CAMatrix::Audit::Messages::InitializeAlgorithmRequest &) override;
  CAMatrix::Audit::Messages::GenerateKeysResult
  generateKeys(const CAMatrix::Audit::Messages::GenerateKeysRequest &) override;
  CAMatrix::Audit::Messages::GenerateTagsResult
  generateTags(const CAMatrix::Audit::Messages::GenerateTagsRequest &) override;
  CAMatrix::Audit::Messages::MaintainResult
  maintenance(const CAMatrix::Audit::Messages::MaintainRequest &) override;
  CAMatrix::Audit::Messages::GenerateChallengesResult generateChallenges(
      const CAMatrix::Audit::Messages::GenerateChallengesRequest &) override;
  CAMatrix::Audit::Messages::GenerateProofsResult generateProofs(
      const CAMatrix::Audit::Messages::GenerateProofsRequest &) override;
  CAMatrix::Audit::Messages::VerifyProofsResult
  verifyProofs(const CAMatrix::Audit::Messages::VerifyProofsRequest &) override;
  CAMatrix::Audit::Messages::AuditRequestVariantPtr
  createRequest(CAMatrix::Audit::Core::AuditOperation,
                const CAMatrix::Audit::Core::AuditOperationContext &,
                const CAMatrix::Audit::Messages::RawInput & = {}) override;

  // Compatibility utility only; the native workflow uses maintenance(Delete).
  static std::vector<std::vector<std::uint8_t>>
  overwriteBlocks(const std::vector<std::vector<std::uint8_t>> &blocks,
                  const std::vector<std::size_t> &oneBasedIndices,
                  const std::vector<std::uint8_t> &seed,
                  std::uint64_t permutationKey);
  static void
  overwriteBlocksInPlace(std::vector<std::vector<std::uint8_t>> &blocks,
                         const std::vector<std::size_t> &oneBasedIndices,
                         const std::vector<std::uint8_t> &seed,
                         std::uint64_t permutationKey);

protected:
  const CAMatrix::Audit::Core::AuditStrategyArtifactFactory &
  artifactFactory() const override;

private:
  CAMatrix::Crypto::CryptoGeneralAlgorithmPtr algorithm_;
};
} // namespace CAMatrix::Audit::Strategies

namespace CAMatrix::Audit::Core {
extern "C" AuditStrategy *create_audit_strategy() noexcept;
extern "C" void destroy_audit_strategy(AuditStrategy *) noexcept;
} // namespace CAMatrix::Audit::Core
#endif
