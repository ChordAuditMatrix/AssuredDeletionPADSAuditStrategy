/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Native PADS: Alg. 1 authentication plus Alg. 2 keyed-permutation deletion. */
#include "AssuredDeletionPADSAuditStrategy/strategy.h"
#include "AssuredDeletionPADSAuditStrategy/deletion_state_store.h"
#include "ChordAuditMatrixLib/interfaces/audit/artifact_factory.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/audit_data_map.h"
#include "ChordAuditMatrixLib/interfaces/audit/messages/in_memory_tags.h"
#include <algorithm>
#include <json/json.h>
#include <map>
#include <random>
#include <stdexcept>
#include <utility>

namespace CAMatrix::Audit::Strategies {
namespace {
using namespace CAMatrix::Audit::Core;
using namespace CAMatrix::Audit::Messages;
std::uint64_t hash64(const std::string &s) {
  std::uint64_t h = 1469598103934665603ULL;
  for (auto c : s)
    h = (h ^ static_cast<unsigned char>(c)) * 1099511628211ULL;
  return h;
}
std::string bytes(const std::vector<std::uint8_t> &v) {
  return {reinterpret_cast<const char *>(v.data()), v.size()};
}
std::uint8_t prpByte(const std::vector<std::uint8_t> &seed, std::uint64_t key,
                     std::size_t block, std::size_t pos) {
  return static_cast<std::uint8_t>(
      hash64("PADS:" + std::to_string(key) + ":" + std::to_string(block) + ":" +
             std::to_string(pos) + ":" + bytes(seed)) &
      0xffU);
}
std::uint64_t authenticator(const std::string &fid, std::size_t index,
                            const std::vector<std::uint8_t> &value) {
  return hash64("PADS:auth:" + fid + ":" + std::to_string(index) + ":" +
                bytes(value));
}
class HashTag final : public Tag {
public:
  std::uint64_t value = 0;
  HashTag() = default;
  explicit HashTag(std::uint64_t x) : value(x) {}
  void assign(const Tag &x) override {
    value = dynamic_cast<const HashTag &>(x).value;
  }
  std::shared_ptr<Tag> operator+(const Tag &x) const override {
    return std::make_shared<HashTag>(
        hash64(std::to_string(value) + ":" +
               std::to_string(dynamic_cast<const HashTag &>(x).value)));
  }
  bool operator==(const Tag &x) const override {
    return value == dynamic_cast<const HashTag &>(x).value;
  }

protected:
  void do_serialize(cereal::BinaryOutputArchive &ar) const override {
    ar(value);
  }
  void do_deserialize(cereal::BinaryInputArchive &ar) override { ar(value); }
};
class PADSChallenges final : public Challenges {
public:
  std::vector<std::size_t> indices;
  std::uint64_t nonce = 0;

protected:
  void do_serialize(cereal::BinaryOutputArchive &ar) const override {
    ar(indices, nonce);
  }
  void do_deserialize(cereal::BinaryInputArchive &ar) override {
    ar(indices, nonce);
  }
};
class PADSProof final : public Proves {
public:
  std::uint64_t digest = 0;

protected:
  void do_serialize(cereal::BinaryOutputArchive &ar) const override {
    ar(digest);
  }
  void do_deserialize(cereal::BinaryInputArchive &ar) override { ar(digest); }
};
class Params final : public AlgoPublicParams {
protected:
  void do_serialize(cereal::BinaryOutputArchive &) const override {}
  void do_deserialize(cereal::BinaryInputArchive &) override {}
};
struct TagsExt final : StageExtBase {
  std::string fid;
};
struct MaintExt final : StageExtBase {
  std::string fid;
  std::vector<std::size_t> indices;
  std::uint64_t key = 0;
  std::vector<std::uint8_t> seed;
};
struct ChallengeExt final : StageExtBase {
  std::string fid;
  std::size_t count = 0;
  std::uint64_t nonce = 0;
};
struct ProofExt final : StageExtBase {
  bool replay = false;
};
struct File {
  std::vector<std::vector<std::uint8_t>> blocks, preBlocks;
  std::vector<std::uint64_t> tags, preTags;
  std::vector<std::size_t> deleted;
  std::vector<std::uint8_t> seed;
  std::uint64_t key = 0;
};
std::map<std::string, File> files;
std::string active;
std::vector<std::size_t> indices(const Json::Value &v) {
  const auto &x = v.isMember("targetBlockIndices") ? v["targetBlockIndices"]
                                                   : v["blockIndices"];
  std::vector<std::size_t> out;
  if (x.isArray())
    for (auto const &i : x) {
      auto n = static_cast<std::size_t>(i.asUInt64());
      out.push_back(n == 0 ? 1 : n);
    }
  return out;
}
std::uint64_t proofDigest(const std::string &fid,
                          const std::vector<std::size_t> &picked,
                          const File &f) {
  std::string s = "PADS:proof:" + fid;
  for (auto i : picked)
    s += ":" + std::to_string(i) + ":" + std::to_string(f.tags[i - 1]);
  return hash64(s);
}
class Factory final : public AuditStrategyArtifactFactory {
public:
  AuditArtifactVariant createArtifact(AuditArtifactKind k) const override {
    if (k == AuditArtifactKind::AlgorithmPublicParams ||
        k == AuditArtifactKind::UserPublicParams)
      return std::static_pointer_cast<AlgoPublicParams>(
          std::make_shared<Params>());
    if (k == AuditArtifactKind::Tag)
      return std::static_pointer_cast<Tag>(std::make_shared<HashTag>());
    if (k == AuditArtifactKind::Challenges)
      return std::static_pointer_cast<Challenges>(
          std::make_shared<PADSChallenges>());
    if (k == AuditArtifactKind::Proves)
      return std::static_pointer_cast<Proves>(std::make_shared<PADSProof>());
    if (k == AuditArtifactKind::DynamicBlockMetadata)
      return std::static_pointer_cast<BlockMetadata>(
          std::make_shared<PADSDeletion::DeletionBlockMetadata>());
    throw std::runtime_error("PADS artifact unavailable");
  }
};
} // namespace
Capabilities AssuredDeletionPADSAuditStrategy::caps() const {
  return Capabilities::DynamicUpdate;
}
StateMaintenanceParty
AssuredDeletionPADSAuditStrategy::stateMaintenanceParty() const {
  return StateMaintenanceParty::Public;
}
std::shared_ptr<DynamicPdpStateStore>
AssuredDeletionPADSAuditStrategy::createStateStore(
    BlockMetadataFactory factory) const {
  return std::make_shared<PADSDeletion::DeletionStateStore>(std::move(factory));
}
void AssuredDeletionPADSAuditStrategy::setAlgorithm(
    CAMatrix::Crypto::CryptoGeneralAlgorithmPtr x) {
  algorithm_ = std::move(x);
}
const AuditStrategyArtifactFactory &
AssuredDeletionPADSAuditStrategy::artifactFactory() const {
  static Factory f;
  return f;
}
InitializeAlgorithmResult AssuredDeletionPADSAuditStrategy::initializeAlgorithm(
    const InitializeAlgorithmRequest &) {
  InitializeAlgorithmResult r;
  r.ok = true;
  r.publicParams = std::make_shared<Params>();
  return r;
}
GenerateKeysResult
AssuredDeletionPADSAuditStrategy::generateKeys(const GenerateKeysRequest &) {
  GenerateKeysResult r;
  r.ok = true;
  r.publicParams = std::make_shared<Params>();
  return r;
}
GenerateTagsResult
AssuredDeletionPADSAuditStrategy::generateTags(const GenerateTagsRequest &in) {
  GenerateTagsResult r;
  auto e = std::dynamic_pointer_cast<TagsExt>(in.ext);
  if (!e || !in.blocks)
    return r;
  auto out = std::make_shared<InMemoryTags>(
      [] { return std::make_shared<HashTag>(); });
  File f;
  for (std::size_t i = 0; i < in.blocks->availableBlockCount(); ++i) {
    auto v = in.blocks->block(i);
    f.blocks.push_back(v);
    f.tags.push_back(authenticator(e->fid, i + 1, v));
    out->set(i, std::make_shared<HashTag>(f.tags.back()));
  }
  files[e->fid] = f;
  active = e->fid;
  r.tags = out;
  r.ext = e;
  return r;
}
MaintainResult
AssuredDeletionPADSAuditStrategy::maintenance(const MaintainRequest &in) {
  MaintainResult r;
  auto e = std::dynamic_pointer_cast<MaintExt>(in.ext);
  auto it = files.find(e ? e->fid : "");
  if (!e || in.type != MaintenanceOpType::Delete || it == files.end())
    return r;
  auto &f = it->second;
  if (e->indices.empty()) {
    e->indices.resize(f.blocks.size());
    for (std::size_t i = 0; i < f.blocks.size(); ++i)
      e->indices[i] = i + 1;
  }
  if (e->seed.empty())
    e->seed = {0x50, 0x41, 0x44, 0x53};
  f.preBlocks = f.blocks;
  f.preTags = f.tags;
  f.key = e->key;
  f.seed = e->seed;
  for (auto index : e->indices) {
    if (!index || index > f.blocks.size())
      throw std::out_of_range("PADS deletion index");
    auto &block = f.blocks[index - 1];
    for (std::size_t pos = 0; pos < block.size(); ++pos)
      block[pos] = prpByte(f.seed, f.key, index, pos);
    f.tags[index - 1] = authenticator(e->fid, index, block);
    f.deleted.push_back(index);
  }
  auto out = std::make_shared<InMemoryTags>(
      [] { return std::make_shared<HashTag>(); });
  for (std::size_t i = 0; i < f.tags.size(); ++i)
    out->set(i, std::make_shared<HashTag>(f.tags[i]));
  active = e->fid;
  r.tags = out;
  r.ext = e;
  return r;
}
GenerateChallengesResult AssuredDeletionPADSAuditStrategy::generateChallenges(
    const GenerateChallengesRequest &in) {
  GenerateChallengesResult r;
  auto e = std::dynamic_pointer_cast<ChallengeExt>(in.ext);
  auto it = files.find(e ? e->fid : "");
  if (!e || it == files.end() || it->second.deleted.empty())
    return r;
  std::vector<std::size_t> picked(it->second.blocks.size());
  std::iota(picked.begin(), picked.end(), 1);
  std::mt19937_64 gen(e->nonce);
  std::shuffle(picked.begin(), picked.end(), gen);
  picked.resize(std::min(picked.size(), e->count ? e->count : picked.size()));
  auto c = std::make_shared<PADSChallenges>();
  c->indices = std::move(picked);
  c->nonce = e->nonce;
  r.challenges = c;
  r.ext = e;
  return r;
}
GenerateProofsResult AssuredDeletionPADSAuditStrategy::generateProofs(
    const GenerateProofsRequest &in) {
  GenerateProofsResult r;
  auto c = std::dynamic_pointer_cast<PADSChallenges>(in.challenges);
  auto e = std::dynamic_pointer_cast<ProofExt>(in.ext);
  auto it = files.find(active);
  if (!c || it == files.end())
    return r;
  auto p = std::make_shared<PADSProof>();
  if (e && e->replay) {
    auto replay = it->second;
    for (auto i : c->indices)
      if (std::find(replay.deleted.begin(), replay.deleted.end(), i) !=
          replay.deleted.end())
        replay.tags[i - 1] = replay.preTags[i - 1];
    p->digest = proofDigest(active, c->indices, replay);
  } else
    p->digest = proofDigest(active, c->indices, it->second);
  r.proves = p;
  return r;
}
VerifyProofsResult
AssuredDeletionPADSAuditStrategy::verifyProofs(const VerifyProofsRequest &in) {
  VerifyProofsResult r;
  if (in.challenges.empty() || in.proves.empty())
    return r;
  auto c = std::dynamic_pointer_cast<PADSChallenges>(in.challenges.front());
  auto p = std::dynamic_pointer_cast<PADSProof>(in.proves.front());
  auto it = files.find(active);
  if (!c || !p || it == files.end())
    return r;
  for (auto i : c->indices)
    if (i == 0 || i > it->second.blocks.size()) {
      r.reason = "PADS invalid challenge index";
      return r;
    }
  r.ok = p->digest == proofDigest(active, c->indices, it->second);
  r.reason = r.ok ? "" : "PADS hash authentication rejected";
  return r;
}
AuditRequestVariantPtr AssuredDeletionPADSAuditStrategy::createRequest(
    AuditOperation op, const AuditOperationContext &ctx, const RawInput &in) {
  switch (op) {
  case AuditOperation::AlgorithmInit: {
    auto r = std::make_shared<InitializeAlgorithmRequest>();
    r->ext = std::make_shared<StageExtBase>();
    return std::make_shared<AuditRequestVariant>(r);
  }
  case AuditOperation::KeyGeneration: {
    auto r = std::make_shared<GenerateKeysRequest>();
    r->ext = std::make_shared<StageExtBase>();
    return std::make_shared<AuditRequestVariant>(r);
  }
  case AuditOperation::GenerateTags: {
    auto r = std::make_shared<GenerateTagsRequest>();
    auto d = in.requireCustom<AuditDataMap>(op);
    auto e = std::make_shared<TagsExt>();
    e->fid = d->getRequired<std::string>("fileId");
    r->blocks = d->getRequired<
        std::shared_ptr<CAMatrix::Audit::Data::AuditBlockSource>>("blocks");
    r->ext = e;
    return std::make_shared<AuditRequestVariant>(r);
  }
  case AuditOperation::Maintenance: {
    auto x = in.requireJson(op);
    auto r = std::make_shared<MaintainRequest>();
    r->type = MaintenanceOpType::Delete;
    r->tags = ctx.generateTagsResult->tags;
    auto e = std::make_shared<MaintExt>();
    e->fid = x.get("fileId", active).asString();
    e->indices = indices(x);
    e->key = x.get("permutationKey", 42).asUInt64();
    auto s = x.get("seed", "").asString();
    e->seed = std::vector<std::uint8_t>(s.begin(), s.end());
    r->ext = e;
    return std::make_shared<AuditRequestVariant>(r);
  }
  case AuditOperation::ChallengeGen: {
    auto x = in.requireJson(op);
    auto r = std::make_shared<GenerateChallengesRequest>();
    auto e = std::make_shared<ChallengeExt>();
    e->fid = x.get("fileId", active).asString();
    e->count = x.get("challengeCount", 0).asUInt64();
    e->nonce = x.get("seed", 42).asUInt64();
    r->ext = e;
    return std::make_shared<AuditRequestVariant>(r);
  }
  case AuditOperation::ProofGen: {
    auto r = std::make_shared<GenerateProofsRequest>();
    r->challenges = ctx.generateChallengesResult->challenges;
    auto d = in.requireCustom<AuditDataMap>(op);
    auto e = std::make_shared<ProofExt>();
    e->replay = d->getOptional<bool>("adversarialReplay").value_or(false);
    r->ext = e;
    return std::make_shared<AuditRequestVariant>(r);
  }
  case AuditOperation::ProofVerify: {
    auto r = std::make_shared<VerifyProofsRequest>();
    r->challenges = {ctx.generateChallengesResult->challenges};
    r->proves = {ctx.generateProofsResult->proves};
    r->ext = std::make_shared<StageExtBase>();
    return std::make_shared<AuditRequestVariant>(r);
  }
  }
  throw std::runtime_error("unsupported PADS operation");
}
std::vector<std::vector<std::uint8_t>>
AssuredDeletionPADSAuditStrategy::overwriteBlocks(
    const std::vector<std::vector<std::uint8_t>> &b,
    const std::vector<std::size_t> &i, const std::vector<std::uint8_t> &s,
    std::uint64_t k) {
  auto r = b;
  overwriteBlocksInPlace(r, i, s, k);
  return r;
}
void AssuredDeletionPADSAuditStrategy::overwriteBlocksInPlace(
    std::vector<std::vector<std::uint8_t>> &b,
    const std::vector<std::size_t> &i, const std::vector<std::uint8_t> &s,
    std::uint64_t k) {
  if (s.empty())
    throw std::invalid_argument("PADS seed");
  for (auto x : i) {
    if (!x || x > b.size())
      throw std::out_of_range("PADS target");
    for (std::size_t p = 0; p < b[x - 1].size(); ++p)
      b[x - 1][p] = prpByte(s, k, x, p);
  }
}
} // namespace CAMatrix::Audit::Strategies
namespace CAMatrix::Audit::Core {
extern "C" AuditStrategy *create_audit_strategy() noexcept {
  return new CAMatrix::Audit::Strategies::AssuredDeletionPADSAuditStrategy();
}
extern "C" void destroy_audit_strategy(AuditStrategy *s) noexcept { delete s; }
} // namespace CAMatrix::Audit::Core
