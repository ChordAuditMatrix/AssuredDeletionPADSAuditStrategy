/* SPDX-License-Identifier: GPL-3.0-or-later */
/** @file pads_strategy_tests.cpp @brief PADS plugin scaffold smoke test. */

#include "AssuredDeletionPADSAuditStrategy/strategy.h"

#include <cstdlib>

int main() {
  CAMatrix::Audit::Strategies::AssuredDeletionPADSAuditStrategy strategy;
  const auto deleted = strategy.overwriteBlocks({{1, 2, 3, 4}}, {1}, {9, 8}, 7);
  return strategy.algorithmType() == "AssuredDeletionPADS" &&
                 deleted[0] != std::vector<std::uint8_t>({1, 2, 3, 4})
             ? EXIT_SUCCESS
             : EXIT_FAILURE;
}
