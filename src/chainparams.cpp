// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <hash.h>
#include <util/system.h>

#include <algorithm>
#include <cassert>
#include <memory>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 0 << OP_0 << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Quantum Shield Network launches to secure crypto against future threats - 2023";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = CBaseChainParams::MAIN;
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Height = 0;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 0; 
        consensus.BIP66Height = 0; 
        consensus.CSVHeight = 0; 
        consensus.SegwitHeight = 0; 
        consensus.MinBIP9WarningHeight = 0; 
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 60; // 1 minute blocks
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        
        // ===== QUANTUM-RESISTANT PARAMETERS =====
        consensus.nMaxSupply = 42000000 * COIN;
        consensus.nPowPhaseEndSupply = 16000000 * COIN;
        consensus.nStakeAnnualTarget = 0.05; // 5% annual inflation target
        consensus.nStakeMinAge = 17280;      // 3 days (at 60s blocks)
        consensus.nStakeBondingPeriod = 2000; // ~33 hours
        consensus.nMinStakeAmount = 1000 * COIN;
        
        // Quantum cryptography parameters
        consensus.nDilithiumPubKeySize = 1312; // Dilithium3 public key size
        consensus.nDilithiumSigSize = 3293;    // Dilithium3 signature size
        consensus.nArgonMemCost = 1 << 20;     // 1GB memory usage
        consensus.nArgonTimeCost = 4;          // 4 iterations
        consensus.nArgonLanes = 4;             // 4 parallel lanes
        
        // The best chain should have at least this much work
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid
        consensus.defaultAssumeValid = uint256S("0x00");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        pchMessageStart[0] = 0xae;
        pchMessageStart[1] = 0x61;
        pchMessageStart[2] = 0x50;
        pchMessageStart[3] = 0xec;
        nDefaultPort = 9143;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 40;
        m_assumed_chain_state_size = 2;

        genesis = CreateGenesisBlock(1690838400, 2083236893, 0x1e0ffff0, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x000007c2bc0a9d7b9f0e8f1b4e3c6f8a9d2b5c8e7f3a1d4e6b9c2a8f3e1d5b7"));
        assert(genesis.hashMerkleRoot == uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        vSeeds.emplace_back("seed1.quantumnetwork.io");
        vSeeds.emplace_back("seed2.quantumnetwork.io");
        vSeeds.emplace_back("seed3.quantumnetwork.io");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,58); // 'Q'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,50); // 'N'
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "qc";

        vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_main), std::end(chainparams_seed_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                { 0, uint256S("0x000007c2bc0a9d7b9f0e8f1b4e3c6f8a9d2b5c8e7f3a1d4e6b9c2a8f3e1d5b7")},
            }
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 0
            1690838400, // * UNIX timestamp of last known number of transactions
            0,          // * total number of transactions between genesis and that timestamp
                        //   (the tx=... number in the ChainStateFlushed debug.log lines)
            0.01        // * estimated number of transactions per second after that timestamp
        };
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = CBaseChainParams::TESTNET;
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Height = 0;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 0; 
        consensus.BIP66Height = 0; 
        consensus.CSVHeight = 0; 
        consensus.SegwitHeight = 0; 
        consensus.MinBIP9WarningHeight = 0; 
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 60; // 1 minute blocks
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        
        // ===== QUANTUM-RESISTANT PARAMETERS =====
        consensus.nMaxSupply = 42000000 * COIN;
        consensus.nPowPhaseEndSupply = 16000000 * COIN;
        consensus.nStakeAnnualTarget = 0.05;
        consensus.nStakeMinAge = 720; // 12 hours for testnet
        consensus.nStakeBondingPeriod = 100; // ~1.7 hours
        consensus.nMinStakeAmount = 100 * COIN;
        
        consensus.nDilithiumPubKeySize = 1312;
        consensus.nDilithiumSigSize = 3293;
        consensus.nArgonMemCost = 1 << 18; // 256KB for testnet
        consensus.nArgonTimeCost = 2;
        consensus.nArgonLanes = 2;
        
        consensus.nMinimumChainWork = uint256S("0x00");
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xae;
        pchMessageStart[1] = 0x61;
        pchMessageStart[2] = 0x50;
        pchMessageStart[3] = 0xed;
        nDefaultPort = 19143;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 4;
        m_assumed_chain_state_size = 1;

        genesis = CreateGenesisBlock(1690838400, 2083236893, 0x1e0ffff0, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x000007c2bc0a9d7b9f0e8f1b4e3c6f8a9d2b5c8e7f3a1d4e6b9c2a8f3e1d5b7"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("testnet-seed1.quantumnetwork.io");
        vSeeds.emplace_back("testnet-seed2.quantumnetwork.io");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111); // 't'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196); // '2'
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tq";

        vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_test), std::end(chainparams_seed_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        m_is_test_chain = true;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {0, uint256S("0x000007c2bc0a9d7b9f0e8f1b4e3c6f8a9d2b5c8e7f3a1d4e6b9c2a8f3e1d5b7")},
            }
        };

        chainTxData = ChainTxData{
            1690838400,
            0,
            0.01
        };
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    explicit CRegTestParams(const ArgsManager& args) {
        strNetworkID =  CBaseChainParams::REGTEST;
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP16Height = 0;
        consensus.BIP34Height = 1; // BIP34 activated on regtest (Used in functional tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1; // BIP65 activated on regtest
        consensus.BIP66Height = 1; // BIP66 activated on regtest
        consensus.CSVHeight = 1; // CSV activated on regtest
        consensus.SegwitHeight = 0; // SEGWIT is always activated on regtest unless overridden
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 60; // 1 minute blocks
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for regtest
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        
        // ===== QUANTUM-RESISTANT PARAMETERS =====
        consensus.nMaxSupply = 42000000 * COIN;
        consensus.nPowPhaseEndSupply = 16000000 * COIN;
        consensus.nStakeAnnualTarget = 0.05;
        consensus.nStakeMinAge = 10; // 10 blocks for regtest
        consensus.nStakeBondingPeriod = 5; // 5 blocks
        consensus.nMinStakeAmount = 10 * COIN;
        
        consensus.nDilithiumPubKeySize = 1312;
        consensus.nDilithiumSigSize = 3293;
        consensus.nArgonMemCost = 1 << 10; // 1KB for regtest
        consensus.nArgonTimeCost = 1;
        consensus.nArgonLanes = 1;
        
        consensus.nMinimumChainWork = uint256S("0x00");
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xae;
        pchMessageStart[1] = 0x61;
        pchMessageStart[2] = 0x50;
        pchMessageStart[3] = 0xee;
        nDefaultPort = 19444;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        UpdateActivationParametersFromArgs(args);

        genesis = CreateGenesisBlock(1690838400, 2, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x7b1e1f1c3c7e1f1e3c7e1f1e3c7e1f1e3c7e1f1e3c7e1f1e3c7e1f1e3c7e1f1e3c"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = true;
        m_is_test_chain = true;
        m_is_mockable_chain = true;

        checkpointData = {
            {
                {0, uint256S("0x7b1e1f1c3c7e1f1e3c7e1f1e3c7e1f1e3c7e1f1e3c7e1f1e3c7e1f1e3c7e1f1e3c")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111); // 't'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196); // '2'
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "qcrt";
    }

    /**
     * Allows modifying the Version Bits regtest parameters.
     */
    void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
    void UpdateActivationParametersFromArgs(const ArgsManager& args);
};

void CRegTestParams::UpdateActivationParametersFromArgs(const ArgsManager& args)
{
    if (gArgs.IsArgSet("-segwitheight")) {
        int64_t height = gArgs.GetArg("-segwitheight", consensus.SegwitHeight);
        if (height < -1 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Activation height %ld for segwit is out of valid range. Use -1 to disable segwit.", height));
        } else if (height == -1) {
            LogPrintf("Segwit disabled for testing\n");
            height = std::numeric_limits<int>::max();
        }
        consensus.SegwitHeight = static_cast<int>(height);
    }
}

static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const ArgsManager& args, const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN) {
        return std::unique_ptr<CChainParams>(new CMainParams());
    } else if (chain == CBaseChainParams::TESTNET) {
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    } else if (chain == CBaseChainParams::REGTEST) {
        return std::unique_ptr<CChainParams>(new CRegTestParams(args));
    }
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(gArgs, network);
}