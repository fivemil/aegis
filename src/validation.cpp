// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validation.h>

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <checkqueue.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/quantum.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <cuckoocache.h>
#include <deploymentstatus.h>
#include <flatfile.h>
#include <hash.h>
#include <index/txindex.h>
#include <logging.h>
#include <logging/timer.h>
#include <node/blockstorage.h>
#include <node/coinstats.h>
#include <node/ui_interface.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <random.h>
#include <reverse_iterator.h>
#include <script/script.h>
#include <script/sigcache.h>
#include <shutdown.h>
#include <signet.h>
#include <timedata.h>
#include <tinyformat.h>
#include <txdb.h>
#include <txmempool.h>
#include <uint256.h>
#include <undo.h>
#include <util/check.h>
#include <util/fs_helpers.h>
#include <util/moneystr.h>
#include <util/rbf.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <util/translation.h>
#include <validationinterface.h>
#include <warnings.h>

#include <algorithm>
#include <atomic>
#include <cassert>
#include <deque>
#include <future>
#include <numeric>
#include <optional>
#include <string>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <utility>

#define MICRO 0.000001
#define MILLI 0.001

bool CBlockIndexWorkComparator::operator()(const CBlockIndex* pa, const CBlockIndex* pb) const
{
    // First sort by most total work, ...
    if (pa->nChainWork > pb->nChainWork) return false;
    if (pa->nChainWork < pb->nChainWork) return true;

    // ... then by earliest time received, ...
    if (pa->nSequenceId < pb->nSequenceId) return false;
    if (pa->nSequenceId > pb->nSequenceId) return true;

    // Use pointer address as tie breaker (should only happen with blocks
    // loaded from disk, as those all have id 0).
    if (pa < pb) return false;
    if (pa > pb) return true;

    // Identical blocks.
    return false;
}

namespace {
// ========== QUANTUM ADDITION START ========== //
/**
 * Calculate total supply up to a given block height
 */
CAmount GetBlockSubsidyTotal(int nHeight)
{
    // This is a placeholder implementation
    // In production, you would track cumulative supply in the chainstate
    // For simplicity, we assume linear mining until 16M is reached
    const Consensus::Params& consensusParams = Params().GetConsensus();
    CAmount nTotal = 0;
    int nBlocks = 0;
    
    while (nTotal < consensusParams.nPowPhaseEndSupply) {
        int halvings = nBlocks / consensusParams.nSubsidyHalvingInterval;
        CAmount subsidy = 32 * COIN;
        if (halvings >= 64) break;
        subsidy >>= halvings;
        nTotal += subsidy;
        nBlocks++;
        
        if (nBlocks >= nHeight) break;
    }
    return std::min(nTotal, consensusParams.nPowPhaseEndSupply);
}
// ========== QUANTUM ADDITION END ========== //

} // namespace

// ========== QUANTUM MODIFICATION START ========== //
CAmount GetBlockSubsidy(int nHeight, const Consensus::Params& consensusParams)
{
    CAmount nCurrentSupply = GetBlockSubsidyTotal(nHeight - 1);
    
    // Supply cap reached - no more rewards
    if (nCurrentSupply >= consensusParams.nMaxSupply) 
        return 0;
    
    // PoW Phase (first 16M coins)
    if (nCurrentSupply < consensusParams.nPowPhaseEndSupply) {
        int halvings = nHeight / consensusParams.nSubsidyHalvingInterval;
        CAmount subsidy = 32 * COIN;
        return subsidy >> std::min(halvings, 64);
    }
    // PoS Phase (16M-42M coins)
    else {
        CAmount remaining = consensusParams.nMaxSupply - nCurrentSupply;
        CAmount annual_reward = static_cast<CAmount>(remaining * consensusParams.nStakeAnnualTarget);
        return annual_reward / (365 * 24 * 60); // Per-block (60s blocks)
    }
}
// ========== QUANTUM MODIFICATION END ========== //

bool CheckSequenceLocks(const CTxMemPool& pool,
                        const CTransaction& tx,
                        int flags,
                        LockPoints* lp,
                        bool useExistingLockPoints)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(pool.cs);

    CBlockIndex* tip = ::ChainActive().Tip();
    assert(tip != nullptr);

    CBlockIndex index;
    index.pprev = tip;
    // CheckSequenceLocks() uses chainActive.Height()+1 to evaluate
    // height based locks because when SequenceLocks() is called within
    // ConnectBlock(), the height of the block *being*
    // evaluated is what is used.
    // Thus if we want to know if a transaction can be part of the
    // *next* block, we need to use one more than chainActive.Height()
    index.nHeight = tip->nHeight + 1;

    std::pair<int, int64_t> lockPair;
    if (useExistingLockPoints) {
        assert(lp);
        lockPair.first = lp->height;
        lockPair.second = lp->time;
    }
    else {
        // pcoinsTip contains the UTXO set for chainActive.Tip()
        CCoinsViewMemPool viewMemPool(&::ChainstateActive().CoinsTip(), pool);
        std::vector<int> prevheights;
        prevheights.resize(tx.vin.size());
        for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
            const CTxIn& txin = tx.vin[txinIndex];
            Coin coin;
            if (!viewMemPool.GetCoin(txin.prevout, coin)) {
                return error("%s: Missing input", __func__);
            }
            if (coin.nHeight == MEMPOOL_HEIGHT) {
                // Assume all mempool transaction confirm in the next block
                prevheights[txinIndex] = tip->nHeight + 1;
            } else {
                prevheights[txinIndex] = coin.nHeight;
            }
        }
        lockPair = CalculateSequenceLocks(tx, flags, &prevheights, index);
        if (lp) {
            lp->height = lockPair.first;
            lp->time = lockPair.second;
            // Also store the hash of the block with the highest height of
            // all the blocks which have sequence locked prevouts.
            // This hash needs to still be on the chain
            // for these LockPoint calculations to be valid
            // Note: It is impossible to correctly calculate a maxInputBlock
            // if any of the sequence locked inputs depend on unconfirmed txs,
            // except in the special case where the relative lock time/height
            // is 0, which is equivalent to no sequence lock.
            if (lp->maxInputBlock && lockPair.first >= tip->nHeight) {
                if (lockPair.first == tip->nHeight) {
                    lp->maxInputBlock = tip;
                } else {
                    // lp->maxInputBlock should be set to the fork point
                    // It should be set by the caller
                    lp->maxInputBlock = nullptr;
                }
            }
        }
    }
    bool fResult = EvaluateSequenceLocks(index, lockPair);
    if (!fResult)
        return error("%s: contains non-BIP68-final transaction", __func__);

    return fResult;
}

// ========== QUANTUM ADDITION START ========== //
bool CheckQuantumSignature(const CScript& scriptSig, const CScript& scriptPubKey,
                          unsigned int flags, const BaseSignatureChecker& checker,
                          ScriptError* serror)
{
    // Quantum signature verification logic
    if (flags & SCRIPT_VERIFY_QUANTUM_SIGNATURES) {
        // Extract quantum signature and public key
        std::vector<unsigned char> vchSig, vchPubKey;
        if (!GetQuantumSignatureParameters(scriptSig, vchSig, vchPubKey)) {
            return set_error(serror, ScriptError::SIG_DER);
        }
        
        // Create message hash
        uint256 sighash = SignatureHash(scriptPubKey, checker.TransactionTo(), checker.NIn(),
                                       SIGHASH_ALL, 0, SigVersion::BASE, checker.Context());
        
        // Verify using quantum-resistant algorithm
        if (!QuantumVerifySignature(vchPubKey, sighash, vchSig)) {
            return set_error(serror, ScriptError::SIG_NULLFAIL);
        }
    }
    return true;
}
// ========== QUANTUM ADDITION END ========== //

bool CheckInputScripts(const CTransaction& tx, TxValidationState& state,
                      const CCoinsViewCache& inputs, unsigned int flags,
                      bool sigCacheStore, bool scriptCacheStore,
                      const PrecomputedTransactionData& txdata,
                      int& nSigChecksOut, TxSigCheckLimiter& txLimit,
                      std::vector<CScriptCheck>* pvChecks)
{
    // ========== QUANTUM MODIFICATION START ========== //
    // Activate quantum signatures after PoW phase
    const Consensus::Params& consensus = Params().GetConsensus();
    if (::ChainActive().Height() > 0) {
        CBlockIndex* pindex = ::ChainActive().Tip();
        CAmount currentSupply = GetBlockSubsidyTotal(pindex->nHeight);
        if (currentSupply >= consensus.nPowPhaseEndSupply) {
            flags |= SCRIPT_VERIFY_QUANTUM_SIGNATURES;
        }
    }
    // ========== QUANTUM MODIFICATION END ========== //

    if (pvChecks) {
        pvChecks->reserve(tx.vin.size());
    }

    // First check if script executions have been cached with the same
    // flags. Note that this assumes that the inputs provided are
    // correct (ie that the transaction hash which is in tx's prevouts
    // properly commits to the scriptPubKey in the inputs view of that
    // transaction).
    ScriptCacheKey hashCacheEntry(tx, flags);
    if (IsKeyInScriptCache(hashCacheEntry, !scriptCacheStore, nSigChecksOut)) {
        return true;
    }

    int nSigChecksTotal = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        const COutPoint &prevout = tx.vin[i].prevout;
        const Coin& coin = inputs.AccessCoin(prevout);
        assert(!coin.IsSpent());

        // We very carefully only pass in things to CScriptCheck which
        // are clearly committed to by tx' witness hash. This provides
        // a sanity check that our caching is not introducing consensus
        // failures through additional data in, eg, the coins being
        // spent being checked as a part of CScriptCheck.

        // Verify signature
        CScriptCheck check(coin.out, tx, i, flags, 
                          sigCacheStore, txdata, &txLimit);
        // ========== QUANTUM MODIFICATION START ========== //
        // Override with quantum signature check if needed
        if (flags & SCRIPT_VERIFY_QUANTUM_SIGNATURES) {
            check = CScriptCheck(coin.out, tx, i, 
                                (flags | SCRIPT_VERIFY_QUANTUM_SIGNATURES), 
                                sigCacheStore, txdata, &txLimit);
        }
        // ========== QUANTUM MODIFICATION END ========== //

        if (pvChecks) {
            pvChecks->push_back(std::move(check));
        } else if (!check()) {
            // ScriptCheck functions return error messages via state.Invalid()
            state.SetScriptError(check.GetScriptError());
            if (state.GetScriptError() == ScriptError::SCRIPT_ERR_OP_RETURN) {
                // Don't return immediately for OP_RETURN
                state.SetValidationState(TxValidationResult::TX_NOT_STANDARD);
            } else {
                return false;
            }
        }
        nSigChecksTotal += check.GetScriptExecutionMetrics().nSigChecks;
    }

    if (scriptCacheStore && !pvChecks) {
        // We executed all of the provided scripts, and were told to
        // cache the result. Do so now.
        AddKeyInScriptCache(hashCacheEntry, nSigChecksTotal);
    }

    nSigChecksOut = nSigChecksTotal;
    return true;
}

static bool UndoWriteToDisk(const CBlockUndo& blockundo, FlatFilePos& pos, const uint256& hashBlock, const CMessageHeader::MessageStartChars& messageStart)
{
    // Open history file to append
    CAutoFile fileout(OpenUndoFile(pos), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull()) {
        return error("%s: OpenUndoFile failed", __func__);
    }

    // Write index header
    unsigned int nSize = GetSerializeSize(blockundo, fileout.GetVersion());
    fileout << messageStart << nSize;

    // Write undo data
    long fileOutPos = ftell(fileout.Get());
    if (fileOutPos < 0) {
        return error("%s: ftell failed", __func__);
    }
    pos.nPos = (unsigned int)fileOutPos;
    fileout << blockundo;

    // calculate & write checksum
    CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
    hasher << hashBlock;
    hasher << blockundo;
    fileout << hasher.GetHash();

    return true;
}

bool UndoReadFromDisk(CBlockUndo& blockundo, const CBlockIndex* pindex)
{
    const FlatFilePos pos = pindex->GetUndoPos();
    if (pos.IsNull()) {
        return error("%s: no undo data available", __func__);
    }

    // Open history file to read
    CAutoFile filein(OpenUndoFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull()) {
        return error("%s: OpenUndoFile failed", __func__);
    }

    // Read block
    uint256 hashChecksum;
    CHashVerifier<CAutoFile> verifier(&filein); // We need a CHashVerifier as reserializing may lose data
    try {
        verifier << pindex->pprev->GetBlockHash();
        verifier >> blockundo;
        filein >> hashChecksum;
    } catch (const std::exception& e) {
        return error("%s: Deserialize or I/O error - %s", __func__, e.what());
    }

    // Verify checksum
    if (hashChecksum != verifier.GetHash()) {
        return error("%s: Checksum mismatch", __func__);
    }

    return true;
}

/** Abort with a message */
static bool AbortNode(const std::string& strMessage, const std::string& userMessage = "")
{
    SetMiscWarning(strMessage);
    LogPrintf("*** %s\n", strMessage);
    if (!userMessage.empty()) {
        uiInterface.ThreadSafeMessageBox(
            userMessage, "", CClientUIInterface::MSG_ERROR);
    } else {
        uiInterface.ThreadSafeMessageBox(
            _("Error: A fatal internal error occurred, see debug.log for details").translated,
            "", CClientUIInterface::MSG_ERROR);
    }
    StartShutdown();
    return false;
}

static bool AbortNode(BlockValidationState& state, const std::string& strMessage, const std::string& userMessage = "")
{
    AbortNode(strMessage, userMessage);
    return state.Error(strMessage);
}

/** Restore the UTXO in a Coin at a given COutPoint */
DisconnectResult UndoCoinSpend(const Coin& undo, CCoinsViewCache& view, const COutPoint& out)
{
    bool fClean = true;

    if (view.HaveCoin(out)) fClean = false; // overwriting transaction output

    if (undo.nHeight == 0) {
        // Missing undo metadata (height and coinbase). Older versions included this
        // information only in undo records for the last spend of a transactions'
        // outputs. This implies that it must be present for some other output of the same tx.
        const Coin& alternate = AccessByTxid(view, out.hash);
        if (!alternate.IsSpent()) {
            undo.nHeight = alternate.nHeight;
            undo.fCoinBase = alternate.fCoinBase;
        } else {
            return DISCONNECT_FAILED; // adding output for transaction without known metadata
        }
    }
    // The potential_overwrite parameter to AddCoin is only allowed to be false if we know for
    // sure that the coin did not already exist in the cache. As we have queried for that above
    // using HaveCoin, we don't need to guess. When fClean is false, a coin already existed and
    // it is an overwrite.
    view.AddCoin(out, std::move(undo), !fClean);

    return fClean ? DISCONNECT_OK : DISCONNECT_UNCLEAN;
}

/**
 * Undo the effects of this block (with given index) on the UTXO set represented by coins.
 * When FAILED is returned, view is left in an indeterminate state.
 */
DisconnectResult CChainState::DisconnectBlock(const CBlock& block, const CBlockIndex* pindex, CCoinsViewCache& view)
{
    bool fClean = true;

    CBlockUndo blockUndo;
    if (!UndoReadFromDisk(blockUndo, pindex)) {
        error("DisconnectBlock(): failure reading undo data");
        return DISCONNECT_FAILED;
    }

    if (blockUndo.vtxundo.size() + 1 != block.vtx.size()) {
        error("DisconnectBlock(): block and undo data inconsistent");
        return DISCONNECT_FAILED;
    }

    // First, restore inputs.
    for (size_t i = 1; i < block.vtx.size(); i++) {
        const CTransaction &tx = *(block.vtx[i]);
        const CTxUndo &txundo = blockUndo.vtxundo[i-1];
        if (txundo.vprevout.size() != tx.vin.size()) {
            error("DisconnectBlock(): transaction and undo data inconsistent");
            return DISCONNECT_FAILED;
        }

        for (size_t j = 0; j < tx.vin.size(); j++) {
            const COutPoint &out = tx.vin[j].prevout;
            const Coin &undo = txundo.vprevout[j];
            DisconnectResult res = UndoCoinSpend(undo, view, out);
            if (res == DISCONNECT_FAILED) return DISCONNECT_FAILED;
            fClean = fClean && res != DISCONNECT_UNCLEAN;
        }
    }

    // Second, revert created outputs.
    for (const auto& tx : block.vtx) {
        if (tx->IsCoinBase()) {
            // ========== QUANTUM ADDITION START ========== //
            // Skip coinbase for PoS blocks
            if (pindex->IsProofOfStake()) continue;
            // ========== QUANTUM ADDITION END ========== //
        }
        for (uint32_t i = 0; i < tx->vout.size(); i++) {
            const COutPoint out(tx->GetHash(), i);
            view.SpendCoin(out);
        }
    }

    // Move best block pointer to previous block.
    view.SetBestBlock(pindex->pprev->GetBlockHash());

    return fClean ? DISCONNECT_OK : DISCONNECT_UNCLEAN;
}

static bool FlushView(CChainState& chainstate, CCoinsViewCache& view, bool fErase)
{
    // Write changes to blockchain database
    if (!view.Flush()) return false;
    // Update chainstate database
    if (!chainstate.m_blockman.m_block_tree_db->WriteBlockIndex(chainstate.m_chain)) return false;
    return true;
}

bool CChainState::ConnectBlock(const CBlock& block, BlockValidationState& state, CBlockIndex* pindex,
                              CCoinsViewCache& view, bool fJustCheck)
{
    AssertLockHeld(cs_main);
    assert(pindex);
    // pindex->phashBlock can be null if called by CreateNewBlock/TestBlockValidity
    assert((pindex->phashBlock != nullptr) ||
           (pindex->nHeight == 0 && pindex->GetBlockHash() == Params().GenesisBlockHash()));
    const CChainParams& params = Params();

    int64_t nTimeStart = GetTimeMicros();

    // Check it again in case a previous version let a bad block in
    // NOTE: We don't currently (re-)invoke ContextualCheckBlock() or
    // ContextualCheckBlockHeader() here. This means that if we add a new
    // consensus rule that is enforced in one of those two functions, then we
    // may have let in a block that violates the rule prior to updating the
    // software, and we would NOT be enforcing the rule here. Fully solving
    // upgrade from one software version to the next after a consensus rule
    // change is potentially tricky and issue-specific.
    BlockValidationOptions validationOptions = BlockValidationOptions(!fJustCheck, !fJustCheck);
    if (!CheckBlock(block, state, params.GetConsensus(), validationOptions)) {
        if (state.GetResult() == BlockValidationResult::BLOCK_MUTATED) {
            // We don't write down blocks to disk if they may have been
            // corrupted, so this should be impossible unless we're having hardware
            // problems.
            return AbortNode(state, "Corrupt block found indicating potential hardware failure; shutting down");
        }
        return error("%s: Consensus::CheckBlock: %s", __func__, state.ToString());
    }

    // Verify that the view's current state corresponds to the previous block
    uint256 hashPrevBlock = pindex->pprev == nullptr ? uint256() : pindex->pprev->GetBlockHash();
    assert(hashPrevBlock == view.GetBestBlock());

    // Special case for the genesis block, skipping connection of its transactions
    // (its coinbase is unspendable)
    const int nHeight = pindex->nHeight;
    if (block.IsGenesisBlock()) {
        if (!fJustCheck)
            view.SetBestBlock(pindex->GetBlockHash());
        return true;
    }

    nBlocksTotal++;
    LogPrint(BCLog::BENCH, "  - Connect %u transactions: ", (unsigned)block.vtx.size());
    Tic(std::string(__func__) + "::txs");

    std::vector<PrecomputedTransactionData> txdata;
    txdata.reserve(block.vtx.size());
    for (const auto& tx : block.vtx) {
        txdata.emplace_back(*tx);
    }

    // Apply block transactions
    for (size_t i = 0; i < block.vtx.size(); i++) {
        const CTransaction& tx = *(block.vtx[i]);
        const uint256 txid = tx.GetHash();

        // ========== QUANTUM ADDITION START ========== //
        // Quantum signature verification for non-coinbase transactions
        if (!tx.IsCoinBase() && nHeight > 0) {
            CAmount currentSupply = GetBlockSubsidyTotal(nHeight - 1);
            const Consensus::Params& consensus = params.GetConsensus();
            if (currentSupply >= consensus.nPowPhaseEndSupply) {
                // Verify quantum signatures for all inputs
                for (const CTxIn& txin : tx.vin) {
                    Coin coin;
                    if (!view.GetCoin(txin.prevout, coin) || coin.IsSpent()) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, 
                                           "bad-txns-inputs-missingorspent",
                                           strprintf("%s: inputs missing/spent", __func__));
                    }
                    
                    // Extract quantum signature
                    std::vector<unsigned char> vchSig, vchPubKey;
                    if (!GetQuantumSignatureParameters(txin.scriptSig, vchSig, vchPubKey)) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                           "bad-txns-invalid-quantum-sig",
                                           strprintf("%s: invalid quantum signature", __func__));
                    }
                    
                    // Create message hash
                    uint256 sighash = SignatureHash(coin.out.scriptPubKey, tx, i, 
                                                  SIGHASH_ALL, 0, SigVersion::BASE, nullptr);
                    
                    // Verify quantum signature
                    if (!QuantumVerifySignature(vchPubKey, sighash, vchSig)) {
                        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                           "bad-txns-quantum-sig-verify",
                                           strprintf("%s: quantum signature verification failed", __func__));
                    }
                }
            }
        }
        // ========== QUANTUM ADDITION END ========== //

        if (tx.IsCoinBase()) {
            // ========== QUANTUM ADDITION START ========== //
            // Skip coinbase checks for PoS blocks
            if (pindex->IsProofOfStake()) continue;
            // ========== QUANTUM ADDITION END ========== //
        }

        // Apply transaction to UTXO set
        TxValidationState tx_state;
        bool fCheckResult = true;
        if (fJustCheck) {
            fCheckResult = CheckInputScripts(tx, tx_state, view, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_DERSIG, true, false, txdata[i]);
        } else {
            fCheckResult = ApplyTransaction(tx, view, i, nHeight, tx_state, txdata[i]);
        }
        if (!fCheckResult) {
            state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                         tx_state.GetRejectReason(), tx_state.GetDebugMessage());
            return error("%s: ConnectInputs failed on %s at %d: %s", __func__,
                        txid.ToString(), i, state.ToString());
        }
    }
    Toc(std::string(__func__) + "::txs");

    int64_t nTime1 = GetTimeMicros();
    nTimeConnect += nTime1 - nTimeStart;
    LogPrint(BCLog::BENCH, "  - Connect total: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime1 - nTimeStart) * MICRO, nTimeConnect * MICRO, nTimeConnect * MILLI / nBlocksTotal);

    // ========== QUANTUM ADDITION START ========== //
    // Validate Proof-of-Stake blocks
    if (pindex->IsProofOfStake()) {
        // Validate staking signature
        if (!CheckProofOfStake(pindex->pprev, block, state)) {
            return error("%s: proof of stake check failed (%s)", __func__, state.ToString());
        }
        
        // Validate staker selection
        if (!ValidateStakerSelection(pindex->pprev, block, view)) {
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-stake-select");
        }
    }
    // ========== QUANTUM ADDITION END ========== //

    // Write undo information to disk
    if (!fJustCheck) {
        if (!pindex->IsValid(BLOCK_VALID_SCRIPTS)) {
            CBlockUndo blockundo;
            blockundo.vtxundo.reserve(block.vtx.size() - 1);
            for (unsigned int i = 1; i < block.vtx.size(); i++) {
                const CTransaction &tx = *(block.vtx[i]);
                CTxUndo undo;
                if (!UndoWriteToDisk(tx, view, pindex->nHeight, undo)) {
                    return AbortNode(state, "Failed to write undo data");
                }
                blockundo.vtxundo.push_back(undo);
            }
            if (!UndoWriteToDisk(blockundo, pindex->GetUndoPos(), pindex->GetBlockHash(), params.MessageStart())) {
                return AbortNode(state, "Failed to write undo data");
            }
        }

        // Add this block to the view's block chain
        view.SetBestBlock(pindex->GetBlockHash());
    }

    // ========== QUANTUM ADDITION START ========== //
    // Supply cap enforcement
    CAmount nBlockReward = GetBlockSubsidy(nHeight, params.GetConsensus());
    CAmount nCurrentSupply = GetBlockSubsidyTotal(nHeight - 1);
    CAmount newSupply = nCurrentSupply + nBlockReward;
    
    if (newSupply > params.GetConsensus().nMaxSupply) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                           "block-reward-exceeds-supply-cap",
                           strprintf("%s: block reward would exceed supply cap (current: %d, reward: %d, max: %d)",
                                     __func__, nCurrentSupply / COIN, nBlockReward / COIN,
                                     params.GetConsensus().nMaxSupply / COIN));
    }
    // ========== QUANTUM ADDITION END ========== //

    int64_t nTime2 = GetTimeMicros();
    nTimeIndex += nTime2 - nTime1;
    LogPrint(BCLog::BENCH, "  - Index writing: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime2 - nTime1) * MICRO, nTimeIndex * MICRO, nTimeIndex * MILLI / nBlocksTotal);

    int64_t nTime3 = GetTimeMicros();
    nTimeCallbacks += nTime3 - nTime2;
    LogPrint(BCLog::BENCH, "  - Callbacks: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime3 - nTime2) * MICRO, nTimeCallbacks * MICRO, nTimeCallbacks * MILLI / nBlocksTotal);

    return true;
}

CoinsCacheSizeState CChainState::GetCoinsCacheSizeState(const CTxMemPool& tx_pool)
{
    return this->GetCoinsCacheSizeState(
        tx_pool,
        m_coinstip_cache_size_bytes,
        gArgs.GetIntArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000);
}

CoinsCacheSizeState CChainState::GetCoinsCacheSizeState(
    const CTxMemPool& tx_pool,
    size_t max_coins_cache_size_bytes,
    size_t max_mempool_size_bytes)
{
    const int64_t nMempoolUsage = tx_pool.GetTotalTxSize();
    int64_t cacheSize = CoinsTip().DynamicMemoryUsage();
    int64_t nTotalSpace =
        max_coins_cache_size_bytes + std::max<int64_t>(max_mempool_size_bytes - nMempoolUsage, 0);

    //! No need to periodic flush if at least this much space still available.
    static constexpr int64_t MAX_BLOCK_COINSDB_USAGE_BYTES = 10 * 1024 * 1024;  // 10MB
    int64_t large_threshold =
        std::max((9 * nTotalSpace) / 10, nTotalSpace - MAX_BLOCK_COINSDB_USAGE_BYTES);

    if (cacheSize > nTotalSpace) {
        LogPrintf("Cache size (%s) exceeds total space (%s)\n", cacheSize, nTotalSpace);
        return CoinsCacheSizeState::CRITICAL;
    } else if (cacheSize > large_threshold) {
        return CoinsCacheSizeState::LARGE;
    }
    return CoinsCacheSizeState::OK;
}

bool CChainState::FlushStateToDisk(
    BlockValidationState& state,
    FlushStateMode mode,
    int nManualPruneHeight)
{
    LOCK(cs_main);
    assert(this->CanFlushToDisk());
    static std::chrono::microseconds nLastWrite{0};
    static std::chrono::microseconds nLastFlush{0};
    std::set<int> setFilesToPrune;
    bool full_flush_completed = false;

    const size_t coins_count = CoinsTip().GetCacheSize();
    const size_t coins_mem_usage = CoinsTip().DynamicMemoryUsage();

    try {
        {
            bool fFlushForPrune = false;
            bool fDoFullFlush = false;

            CoinsCacheSizeState cache_state = GetCoinsCacheSizeState(::mempool);
            LOCK(m_blockman.cs_LastBlockFile);
            if (fPruneMode && (m_blockman.m_check_for_pruning || nManualPruneHeight > 0) && !fReindex) {
                // make sure we don't prune above any of the passed in reference heights
                std::optional<int> max_header = m_blockman.GetPruneTarget();

                if (max_header) {
                    if (nManualPruneHeight > 0) {
                        max_header = std::min(*max_header, nManualPruneHeight);
                    }
                    if (*max_header < m_chain.Height()) {
                        // Only prune blocks if the node is fully synced
                        // Otherwise we might prune a block that is still being downloaded
                        if (!fInitialDownload) {
                            FindFilesToPruneManual(setFilesToPrune, *max_header, m_chain.Height());
                            fFlushForPrune = true;
                        }
                    }
                }
            }
            const auto nNow = GetTime<std::chrono::microseconds>();
            // Avoid writing/flushing immediately after startup.
            if (nLastWrite.count() == 0) {
                nLastWrite = nNow;
            }
            if (nLastFlush.count() == 0) {
                nLastFlush = nNow;
            }
            // The cache is large and we're within 10% and 10 MiB of the limit, but we have time now (not in the middle of a block processing).
            bool fCacheLarge = mode == FlushStateMode::PERIODIC && cache_state >= CoinsCacheSizeState::LARGE;
            // The cache is over the limit, we have to write now.
            bool fCacheCritical = mode == FlushStateMode::IF_NEEDED && cache_state >= CoinsCacheSizeState::CRITICAL;
            // It's been a while since we wrote the block index to disk. Do this frequently, so we don't need to redownload after a crash.
            bool fPeriodicWrite = mode == FlushStateMode::PERIODIC && nNow > nLastWrite + DATABASE_WRITE_INTERVAL;
            // It's been very long since we flushed the cache. Do this infrequently, to optimize cache usage.
            bool fPeriodicFlush = mode == FlushStateMode::PERIODIC && nNow > nLastFlush + DATABASE_FLUSH_INTERVAL;
            // Combine all conditions that result in a full cache flush.
            fDoFullFlush = (mode == FlushStateMode::ALWAYS) || fCacheLarge || fCacheCritical || fPeriodicFlush || fFlushForPrune;
            // Write blocks and block index to disk.
            if (fDoFullFlush || fPeriodicWrite) {
                // Depend on nMinDiskSpace to ensure we can write block index
                if (!CheckDiskSpace(gArgs.GetBlocksDirPath())) {
                    return AbortNode(state, "Disk space is too low!", _("Disk space is too low!"));
                }
                {
                    LOG_TIME_MILLIS_WITH_CATEGORY("write block and undo data to disk", BCLog::BENCH);
                    if (!m_blockman.WriteBlockIndexDB()) {
                        return AbortNode(state, "Failed to write to block index database");
                    }
                }
                nLastWrite = nNow;
            }
            // Flush best chain related state. This can only be done if the blocks / block index write was also done.
            if (fDoFullFlush && !CoinsTip().GetBestBlock().IsNull()) {
                LOG_TIME_MILLIS_WITH_CATEGORY(strprintf("write coins cache to disk (%d coins, %.2fkB)",
                    coins_count, coins_mem_usage / 1000), BCLog::BENCH);
                // Typical Coin structures on disk are around 48 bytes in size.
                // Pushing a new one to the database can cause it to be written
                // twice (once in the log, and once in the tables). This is already
                // an overestimation, as most will delete an existing entry or
                // overwrite one. Still, use a conservative safety factor of 2.
                if (!CheckDiskSpace(gArgs.GetDataDirNet(), 48 * 2 * 2 * CoinsTip().GetCacheSize())) {
                    return AbortNode(state, "Disk space is too low!", _("Disk space is too low!"));
                }
                // Flush the chainstate (which may refer to block index entries).
                if (!FlushView(*this, CoinsTip(), fDoFullFlush)) {
                    return AbortNode(state, "Failed to write to coin database");
                }
                nLastFlush = nNow;
                full_flush_completed = true;
                LOG_TIME_MILLIS_WITH_CATEGORY("write coins cache to disk", BCLog::BENCH);
            }
        }
        if (full_flush_completed) {
            // Update best block in wallet (so we can detect restored wallets).
            GetMainSignals().ChainStateFlushed(m_chain.GetLocator());
        }
    } catch (const std::runtime_error& e) {
        return AbortNode(state, std::string("System error while flushing: ") + e.what());
    }
    return true;
}

// ========== QUANTUM ADDITION START ========== //
bool CheckProofOfStake(const CBlockIndex* pindexPrev, const CBlock& block, BlockValidationState& state)
{
    // Validate staking signature
    if (block.vchBlockSig.empty()) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-stake-sig-empty");
    }
    
    // Recover public key from signature
    std::vector<unsigned char> vchPubKey;
    if (!QuantumRecoverPubKey(block.GetHash(), block.vchBlockSig, vchPubKey)) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-stake-sig-recover");
    }
    
    // Verify staker has sufficient stake
    const CAmount minStake = Params().GetConsensus().nMinStakeAmount;
    CAmount stakedAmount = GetStakedAmount(vchPubKey, pindexPrev);
    
    if (stakedAmount < minStake) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-stake-amount",
                           strprintf("Staked amount %d < required minimum %d", 
                                     stakedAmount / COIN, minStake / COIN));
    }
    
    return true;
}

bool ValidateStakerSelection(const CBlockIndex* pindexPrev, const CBlock& block, const CCoinsViewCache& view)
{
    const Consensus::Params& consensus = Params().GetConsensus();
    
    // Get list of eligible stakers
    std::vector<StakeCandidate> candidates = GetEligibleStakers(view, pindexPrev);
    
    // Calculate total weight
    double totalWeight = 0;
    for (const auto& candidate : candidates) {
        double weight = pow(candidate.amount / COIN, 0.8) * std::min(candidate.ageDays, 90);
        totalWeight += weight;
    }
    
    // Recover staker public key
    std::vector<unsigned char> vchPubKey;
    if (!QuantumRecoverPubKey(block.GetHash(), block.vchBlockSig, vchPubKey)) {
        return false;
    }
    
    // Find candidate and calculate weight
    CKeyID stakerKey = Hash160(vchPubKey);
    double stakerWeight = 0;
    for (const auto& candidate : candidates) {
        if (candidate.stakeId == stakerKey) {
            stakerWeight = pow(candidate.amount / COIN, 0.8) * std::min(candidate.ageDays, 90);
            break;
        }
    }
    
    // Calculate selection probability
    double probability = stakerWeight / totalWeight;
    double threshold = probability * (double)GetRand(std::numeric_limits<uint64_t>::max()) / (double)std::numeric_limits<uint64_t>::max();
    
    // Verify selection
    return (threshold >= probability);
}
// ========== QUANTUM ADDITION END ========== //

void CChainState::UnloadBlockIndex()
{
    nBlockSequenceId = 1;
    m_blockman.Unload();
}

bool CChainState::LoadBlockIndex()
{
    // Load block index from databases
    if (!m_blockman.LoadBlockIndex()) {
        return false;
    }

    // Initialize the chain with the genesis block
    if (m_blockman.m_block_index.empty()) {
        return error("%s: no block index found", __func__);
    }

    return true;
}

bool LoadGenesisBlock()
{
    LOCK(cs_main);

    // Check whether we're already initialized by verifying the existence of the genesis block index entry
    if (m_blockman.m_block_index.count(Params().GenesisBlockHash()))
        return true;

    try {
        const CBlock& block = Params().GenesisBlock();
        FlatFilePos blockPos = m_blockman.SaveBlockToDisk(block, 0, nullptr);
        if (blockPos.IsNull())
            return error("%s: writing genesis block to disk failed", __func__);
        CBlockIndex *pindex = m_blockman.AddToBlockIndex(block);
        ReceivedBlockTransactions(block, pindex, blockPos);
    } catch (const std::runtime_error& e) {
        return error("%s: failed to write genesis block: %s", __func__, e.what());
    }

    return true;
}

void CChainState::CheckBlockIndex()
{
    if (!fCheckBlockIndex) {
        return;
    }

    LOCK(cs_main);

    // During reindexing, every block could be in a different state, so check all of them
    int nHeight = m_chain.Height();
    m_blockman.CheckBlockIndex();

    for (const CBlockIndex* pindex : m_blockman.GetAllBlockIndices()) {
        if (pindex->nSequenceId == 0) {
            LogPrintf("%s: WARNING: Block %s has sequenceId=0\n", __func__, pindex->GetBlockHash().ToString());
        }
    }
}

bool CChainState::LoadGenesisBlock()
{
    return ::LoadGenesisBlock();
}

namespace node {
void StartScriptCheckWorkerPool(int workers_num, CCheckQueue<CScriptCheck>* check_queue)
{
    check_queue->StartWorkerThreads(workers_num);
}

void StopScriptCheckWorkerPool(CCheckQueue<CScriptCheck>* check_queue)
{
    check_queue->StopWorkerThreads();
}
} // namespace node