#include <key.h>
#include <oqs/oqs.h>

class QuantumSigner {
public:
    static const size_t PUBLIC_KEY_SIZE = 1312; // Dilithium3
    static const size_t SECRET_KEY_SIZE = 2528;
    static const size_t SIGNATURE_SIZE = 3293;

    bool KeyGen(CPubKey& pubKey, CKey& privKey) {
        uint8_t public_key[PUBLIC_KEY_SIZE];
        uint8_t secret_key[SECRET_KEY_SIZE];
        
        if (OQS_SIG_dilithium_3_keypair(public_key, secret_key) != OQS_SUCCESS) {
            return false;
        }
        
        pubKey = CPubKey(std::vector<unsigned char>(public_key, public_key + PUBLIC_KEY_SIZE));
        privKey.Set(secret_key, secret_key + SECRET_KEY_SIZE, true);
        return true;
    }

    bool Sign(const CKey& privKey, const uint256& hash, std::vector<unsigned char>& vchSig) {
        const unsigned char* pkey = privKey.data();
        size_t sig_len;
        uint8_t signature[SIGNATURE_SIZE];
        
        if (OQS_SIG_dilithium_3_sign(signature, &sig_len, hash.begin(), 32, pkey) != OQS_SUCCESS) {
            return false;
        }
        
        vchSig.assign(signature, signature + sig_len);
        return true;
    }
};