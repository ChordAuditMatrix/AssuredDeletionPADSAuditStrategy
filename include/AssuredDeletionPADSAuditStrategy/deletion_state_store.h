/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef CAMATRIX_PADS_DELETION_STATE_STORE_H
#define CAMATRIX_PADS_DELETION_STATE_STORE_H

#include "ChordAuditMatrixLib/implementations/audit/state_stores/dynamic_pdp_state_store.h"
#include "ChordAuditMatrixLib/implementations/audit/state_stores/in_memory_block_metadata_collection.h"

#include <cereal/archives/binary.hpp>

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace CAMatrix::Audit::Strategies::PADSDeletion {
using namespace CAMatrix::Audit::Core;

class DeletionBlockMetadata final : public BlockMetadata {
public:
  std::unique_ptr<BlockMetadata> clone() const override {
    return std::make_unique<DeletionBlockMetadata>(*this);
  }
  void bump() override { ++version_; }

protected:
  void do_serialize(cereal::BinaryOutputArchive &archive) const override {
    archive(version_);
  }
  void do_deserialize(cereal::BinaryInputArchive &archive) override {
    archive(version_);
  }

private:
  std::uint64_t version_ = 1;
};

/** Generic, strategy-owned in-memory state backend; deletion evidence is held
 * by PADS itself. */
class DeletionStateStore final : public DynamicPdpStateStore {
public:
  explicit DeletionStateStore(BlockMetadataFactory factory)
      : factory_(factory ? std::move(factory) : [] {
          return std::make_shared<DeletionBlockMetadata>();
        }) {}

  void addFile(const std::string &id) override {
    if (!files_.emplace(id, makeCollection()).second)
      throw std::runtime_error("file already exists: " + id);
  }
  void addFile(const std::string &id, std::size_t count) override {
    if (count == 0)
      throw std::invalid_argument("blockCount must be positive");
    addFile(id);
    for (std::size_t i = 0; i < count; ++i)
      files_.at(id)->set(i, factory_());
  }
  void removeFile(const std::string &id) override {
    if (files_.erase(id) == 0)
      throw std::runtime_error("file does not exist: " + id);
  }
  bool hasFile(const std::string &id) const override {
    return files_.count(id) != 0;
  }
  std::vector<std::string> listFiles() const override {
    std::vector<std::string> ids;
    ids.reserve(files_.size());
    for (const auto &[id, _] : files_)
      ids.push_back(id);
    return ids;
  }
  std::shared_ptr<BlockMetadata>
  getBlockMetadata(const std::string &id, std::size_t index) const override {
    auto collection = get(id);
    if (index == 0 || !collection->contains(index - 1))
      throw std::runtime_error("block does not exist");
    return collection->getByIndex(index - 1);
  }
  std::size_t getBlockCount(const std::string &id) const override {
    return get(id)->size();
  }
  BlockMetadataCollectionPtr
  getBlockMetadataCollection(const std::string &id) const override {
    return get(id);
  }
  void modifyBlock(const std::string &id, std::size_t index) override {
    getBlockMetadata(id, index)->bump();
  }
  void insertBlock(const std::string &id, std::size_t index) override {
    shift(get(id), index, true);
  }
  void deleteBlock(const std::string &id, std::size_t index) override {
    shift(get(id), index, false);
  }
  void
  setBlockMetadataCollection(const std::string &id,
                             BlockMetadataCollectionPtr collection) override {
    if (!collection)
      throw std::invalid_argument("metadata collection must not be null");
    files_.at(id) = std::move(collection);
  }

private:
  BlockMetadataCollectionPtr makeCollection() const {
    return std::make_shared<InMemoryBlockMetadataCollection>(factory_);
  }
  BlockMetadataCollectionPtr get(const std::string &id) const {
    const auto it = files_.find(id);
    if (it == files_.end())
      throw std::runtime_error("file does not exist: " + id);
    return it->second;
  }
  void shift(const BlockMetadataCollectionPtr &collection, std::size_t oneBased,
             bool insert) {
    if (oneBased == 0 || (insert ? oneBased > collection->maxIndex() + 1
                                 : !collection->contains(oneBased - 1))) {
      throw std::runtime_error("invalid block index");
    }
    const auto index = oneBased - 1;
    std::vector<std::pair<std::size_t, std::shared_ptr<BlockMetadata>>> entries;
    for (auto it = collection->begin(); it != collection->end(); ++it)
      entries.emplace_back(it->first, it->second);
    collection->clear();
    for (auto &[oldIndex, metadata] : entries) {
      if (!insert && oldIndex == index)
        continue;
      collection->set(
          insert && oldIndex >= index
              ? oldIndex + 1
              : (!insert && oldIndex > index ? oldIndex - 1 : oldIndex),
          std::move(metadata));
    }
    if (insert)
      collection->set(index, factory_());
  }

  std::unordered_map<std::string, BlockMetadataCollectionPtr> files_;
  BlockMetadataFactory factory_;
};
} // namespace CAMatrix::Audit::Strategies::PADSDeletion

#endif
