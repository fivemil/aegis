// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include <uint256.h>
#include <limits>
#include <map>
#include <vector>

namespace Consensus {

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    int nSubsidyHalvingInterval;
    /* Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    uint256 BIP34Hash;
    /* Block height at which BIP65 becomes active */
    int BIP65Height;
    /* Block height at which BIP66 becomes active */
    int BIP66Height;
    /* Block height at which CSV (BIP68, BIP112 and BIP113) becomes active */
    int CSVHeight;
    /* Block height at which Segwit (BIP141, BIP143 and BIP147) becomes active */
    int SegwitHeight;
    /* Don't warn about unknown BIPs activated after this block height */
    int MinBIP9WarningHeight;
    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    int64_t DifficultyAdjustmentInterval() const { return nPowTargetTimespan / nPowTargetSpacing; }
    uint256 nMinimumChainWork;
    uint256 defaultAssumeValid;
    int nMinerConfirmationWindow;

    // AEGIS-SPECIFIC PARAMETERS START

    /** Total maximum coin supply in base units (satoshis) */
    int64_t nMaxSupply;
    /** Block reward will switch from PoW to PoS when the total supply reaches this amount (base units) */
    int64_t nPowPhaseEndSupply;
    /** Annual target inflation rate for PoS (as a fraction, e.g., 0.05 for 5%) */
    double nStakeAnnualTarget;
    /** Minimum amount of coins required to stake (base units) */
    int64_t nMinStakeAmount;
    /** Bonding period for staked coins (number of blocks) */
    int nStakeBondingPeriod;
    /** Maximum age of coins for staking (in blocks) to prevent hoarding */
    int nStakeMaxAge;

    // AEGIS-SPECIFIC PARAMETERS END

    /** For the following parameters, their defaults are defined in chainparams.cpp */

    /**
     * Check whether the block associated with these parameters is subject to
     * BIP30. BIP30 requires that if there are duplicate coinbases for a given
     * height, the block is rejected, unless it is the duplicate coinbase that
     * is the one at height 91842 (which avoided being rejected due to BIP30).
     * Historically, this method has been used to avoid BIP30 for certain
     * networks. Setting this to true leaves the possibility open for duplicate
     * coinbases (and thus CVE-2012-1909) on the indicated network.
     */
    bool fStrictChainId;

    /**
     * If true, skip BIP30 check for duplicate coinbase transactions for CVE-2012-1909.
     * This is safe to set for chains that don't have duplicate coinbases in their
     * history and it is expensive to check.
     */
    bool fSkipBIP30Check;

    /**
     * If true, skip the BIP34 check when loading blocks. This is safe to set for
     * chains that don't care about enforcing BIP34.
     */
    bool fSkipBIP34Check;

    /**
     * If true, skip the script verification checks for taproot transactions
     * (BIP 342). This is safe to set for chains that don't care about enforcing
     * taproot script rules.
     */
    bool fSkipTaprootCheck;

    /** If true, use Assume Verify blocks. */
    bool fAssumeVerifyEnabled;

    /**
     * If true, witness commitments contain a payload equal to a Bitcoin Script solution
     * (see BIP 141). This is safe to set for chains that don't care about precise
     * implementation of the witness commitment.
     */
    bool enforceOpSuccess;

    /**
     * If true, the consensus rules for Genesis Transactions are enabled.
     * This is typically set to true for regtest and custom networks.
     */
    bool enableGenesisTransactions;
};
} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H