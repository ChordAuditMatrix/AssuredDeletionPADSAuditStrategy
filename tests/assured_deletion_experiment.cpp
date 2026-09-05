/* SPDX-License-Identifier: GPL-3.0-or-later */
/** @file assured_deletion_experiment.cpp
 *  @brief Unified deletion-proof experiment for the PADS deletion model. */
#include "AssuredDeletionPADSAuditStrategy/strategy.h"

#include <chrono>
#include <fstream>
#include <iomanip>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using Blocks = std::vector<std::vector<std::uint8_t>>;

Blocks makeBlocks(std::size_t count) {
  Blocks blocks(count, std::vector<std::uint8_t>(256));
  for (std::size_t i = 0; i < count; ++i)
    for (std::size_t j = 0; j < blocks[i].size(); ++j)
      blocks[i][j] =
          static_cast<std::uint8_t>((i * 131U + j * 17U + 29U) & 0xffU);
  return blocks;
}

std::vector<std::size_t> selectedIndices(std::size_t total, std::size_t count) {
  std::vector<std::size_t> indices;
  indices.reserve(count);
  for (std::size_t i = 0; i < count; ++i)
    indices.push_back((i * total) / count + 1U);
  return indices;
}

std::string option(int argc, char **argv, const std::string &name) {
  for (int i = 1; i + 1 < argc; ++i)
    if (name == argv[i])
      return argv[i + 1];
  return {};
}

bool targetsChanged(const Blocks &before, const Blocks &after,
                    const std::vector<std::size_t> &oneBasedIndices) {
  for (const auto index : oneBasedIndices)
    if (before[index - 1U] == after[index - 1U])
      return false;
  return true;
}

bool untouchedPreserved(const Blocks &before, const Blocks &after,
                        const std::vector<std::size_t> &oneBasedIndices) {
  std::vector<bool> selected(before.size(), false);
  for (const auto index : oneBasedIndices)
    selected[index - 1U] = true;
  for (std::size_t i = 0; i < before.size(); ++i)
    if (!selected[i])
      return before[i] == after[i];
  return true;
}
} // namespace

int main(int argc, char **argv) {
  const auto path = option(argc, argv, "--output");
  if (path.empty()) {
    throw std::invalid_argument("usage: AssuredDeletionPADSDeletionExperiment "
                                "--output result.json [--iterations N]");
  }
  const auto iterationText = option(argc, argv, "--iterations");
  const int rounds = iterationText.empty() ? 20 : std::stoi(iterationText);
  if (rounds <= 0)
    throw std::invalid_argument("iterations must be positive");

  // PdpInverseConfidence sample sizes for P*=0.96 and t/N=2%.
  const std::vector<std::size_t> scales{100, 500, 1000, 5000, 10000};
  const std::vector<std::size_t> sampleSizes{80, 137, 148, 157, 159};
  const std::vector<std::uint8_t> seed(32, 0xa5);
  const std::uint64_t permutationKey = 0x9e3779b97f4a7c15ULL;
  const std::string fileId = "audit-object-000";

  std::ofstream out(path);
  if (!out)
    throw std::runtime_error("cannot open output file");
  out << std::fixed << std::setprecision(6);
  out << "{\n  \"scheme\": \"PADS\",\n  \"iterations\": " << rounds
      << ",\n  \"blockSizeBytes\": 256,\n  \"targetConfidence\": 0.96,"
      << "\n  \"corruptionRatio\": 0.02,\n  \"results\": [\n";

  for (std::size_t row = 0; row < scales.size(); ++row) {
    const auto total = scales[row];
    const auto targets = selectedIndices(total, sampleSizes[row]);
    const auto original = makeBlocks(total);
    double proofGenerationMs = 0.0;
    double proofVerificationMs = 0.0;
    bool generationValid = true;
    bool verificationValid = true;
    bool preserved = true;

    for (int run = 0; run < rounds; ++run) {
      auto deleted = original;
      const auto generationStart = std::chrono::steady_clock::now();
      CAMatrix::Audit::Strategies::AssuredDeletionPADSAuditStrategy::
          overwriteBlocksInPlace(deleted, targets, seed, permutationKey);
      const auto generationStop = std::chrono::steady_clock::now();
      proofGenerationMs += std::chrono::duration<double, std::milli>(
                               generationStop - generationStart)
                               .count();

      const auto verificationStart = std::chrono::steady_clock::now();
      auto expected = original;
      CAMatrix::Audit::Strategies::AssuredDeletionPADSAuditStrategy::
          overwriteBlocksInPlace(expected, targets, seed, permutationKey);
      const bool accepted =
          expected == deleted && targetsChanged(original, deleted, targets);
      const auto verificationStop = std::chrono::steady_clock::now();
      proofVerificationMs += std::chrono::duration<double, std::milli>(
                                 verificationStop - verificationStart)
                                 .count();

      generationValid =
          generationValid && targetsChanged(original, deleted, targets);
      verificationValid = verificationValid && accepted;
      preserved = preserved && untouchedPreserved(original, deleted, targets);
    }

    // Request carries the seed/permutation descriptor; proof binds that
    // descriptor to targets.
    const std::size_t challengeBytes = fileId.size() + seed.size() +
                                       sizeof(permutationKey) +
                                       targets.size() * sizeof(std::uint64_t);
    const std::size_t proofBytes = seed.size() + sizeof(permutationKey) +
                                   targets.size() * sizeof(std::uint64_t);
    out << "    {\"totalBlocks\": " << total
        << ", \"sampleSize\": " << targets.size()
        << ", \"challengeBytes\": " << challengeBytes
        << ", \"proofBytes\": " << proofBytes
        << ", \"proofGenerationMs\": " << proofGenerationMs / rounds
        << ", \"proofVerificationMs\": " << proofVerificationMs / rounds
        << ", \"allTargetBlocksChanged\": "
        << (generationValid ? "true" : "false")
        << ", \"proofVerified\": " << (verificationValid ? "true" : "false")
        << ", \"untouchedBlocksPreserved\": " << (preserved ? "true" : "false")
        << "}";
    out << (row + 1U == scales.size() ? "\n" : ",\n");
  }
  out << "  ]\n}\n";
}
