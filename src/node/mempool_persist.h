// Copyright (c) 2022-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_MEMPOOL_PERSIST_H
#define BITCOIN_NODE_MEMPOOL_PERSIST_H

#include <util/fs.h>

#include <cstdint>
#include <optional>

class Chainstate;
class CTxMemPool;

namespace node {

/** Dump the mempool to a file. */
bool DumpMempool(const CTxMemPool& pool, const fs::path& dump_path,
                 fsbridge::FopenFn mockable_fopen_function = fsbridge::fopen,
                 bool skip_file_commit = false);

struct ImportMempoolOptions {
    fsbridge::FopenFn mockable_fopen_function{fsbridge::fopen};
    bool use_current_time{false};
    bool apply_fee_delta_priority{true};
    bool apply_unbroadcast_set{true};
    //! Collect final restored transaction weight for startup health validation.
    bool collect_restore_stats{false};
};

struct MempoolRestoreStats {
    //! Total transaction weight in the persisted mempool snapshot.
    uint64_t total_tx_weight{0};
    //! Weight of snapshot transactions present after loading finishes.
    uint64_t restored_tx_weight{0};
};

struct MempoolLoadResult {
    //! Whether the mempool file was successfully deserialized.
    bool success{false};
    //! Populated only when restore statistics were requested.
    std::optional<MempoolRestoreStats> restore_stats;
};

/** Import the file and attempt to add its contents to the mempool. */
MempoolLoadResult LoadMempool(CTxMemPool& pool, const fs::path& load_path,
                              Chainstate& active_chainstate,
                              ImportMempoolOptions&& opts);

} // namespace node


#endif // BITCOIN_NODE_MEMPOOL_PERSIST_H
