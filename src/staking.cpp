#include "staking.h"
#include <math.h>

bool ValidateStakerSelection(const CBlockIndex* pindexPrev, const CBlock& block, const CCoinsViewCache& view) {
    // ... get candidates and calculate totalWeight ...
    
    // CORRECTED SELECTION LOGIC
    return (threshold <= probability);
    
    // DEBUG LOGGING
    LogPrint(BCLog::STAKE, "Selected %s with weight %.2f (prob %.4f)\n", 
             stakerKey.ToString(), stakerWeight, probability);
}