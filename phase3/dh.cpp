#include "dh.h"
#include <openssl/rand.h>
#include <stdexcept>
#include <vector>

const char* MODP_GROUP14_PRIME_HEX =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD"
    "129024E088A67CC74020BBEA63B139B22514A08798E3404"
    "DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C"
    "245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406"
    "B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE"
    "45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD"
    "24CF5F83655D23DCA3AD961C62F356208552BB9ED529077"
    "096966D670C354E4ABC9804F1746C08CA18217C32905E46"
    "2E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF"
    "06F4C52C9DE2BCBF6955817183995497CEA956AE515D226"
    "1898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

DiffieHellman::DiffieHellman()
    : p_(nullptr), g_(BN_new()), priv_key_(BN_new()),
      pub_key_(BN_new()), ctx_(BN_CTX_new()) {

    if (!g_ || !priv_key_ || !pub_key_ || !ctx_) {
        throw std::runtime_error("Failed to allocate BIGNUM/BN_CTX");
    }

    BIGNUM* p_raw = nullptr;
    if (!BN_hex2bn(&p_raw, MODP_GROUP14_PRIME_HEX)) {
        throw std::runtime_error("Failed to parse MODP group prime");
    }
    p_.reset(p_raw);

    if (!BN_set_word(g_.get(), MODP_GROUP14_GENERATOR)) {
        throw std::runtime_error("Failed to set generator");
    }
}

void DiffieHellman::generate_keypair() {
    do {
        if (!BN_rand(priv_key_.get(), 2048, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY)) {
            throw std::runtime_error("BN_rand failed to generate private key");
        }
    } while (BN_cmp(priv_key_.get(), p_.get()) >= 0);

    if (!BN_mod_exp(pub_key_.get(), g_.get(), priv_key_.get(), p_.get(), ctx_.get())) {
        throw std::runtime_error("BN_mod_exp failed computing public key");
    }
}

std::string DiffieHellman::get_public_value_hex() const {
    char* hex = BN_bn2hex(pub_key_.get());
    if (!hex) throw std::runtime_error("BN_bn2hex failed");
    std::string result(hex);
    OPENSSL_free(hex);
    return result;
}

std::string DiffieHellman::compute_shared_secret(const std::string& peer_public_hex) const {
    BN_ptr peer_pub(nullptr);
    {
        BIGNUM* raw = nullptr;
        if (!BN_hex2bn(&raw, peer_public_hex.c_str())) {
            throw std::runtime_error("Invalid peer public value");
        }
        peer_pub.reset(raw);
    }

    // Reject trivial/small-subgroup values (0, 1, p-1) that would force
    // a predictable shared secret regardless of either side's private key —
    // e.g. peer_pub = 1 always yields shared = 1, peer_pub = p-1 yields
    // shared in {1, p-1} depending on parity of our private key.
    BN_ptr one(BN_new());
    BN_ptr p_minus_one(BN_new());
    if (!one || !p_minus_one) {
        throw std::runtime_error("Allocation failure during peer key validation");
    }
    BN_one(one.get());
    if (!BN_sub(p_minus_one.get(), p_.get(), one.get())) {
        throw std::runtime_error("BN_sub failed during validation");
    }

    if (BN_cmp(peer_pub.get(), one.get()) <= 0 ||
        BN_cmp(peer_pub.get(), p_minus_one.get()) >= 0) {
        throw std::runtime_error("Rejected peer DH public value: outside valid range (1, p-1)");
    }

    BN_ptr shared(BN_new());
    if (!shared) throw std::runtime_error("Failed to allocate shared secret BIGNUM");

    if (!BN_mod_exp(shared.get(), peer_pub.get(), priv_key_.get(), p_.get(), ctx_.get())) {
        throw std::runtime_error("BN_mod_exp failed computing shared secret");
    }

    std::vector<unsigned char> buf(MODP_GROUP14_BYTE_LEN);
    if (BN_bn2binpad(shared.get(), buf.data(), MODP_GROUP14_BYTE_LEN) < 0) {
        throw std::runtime_error("BN_bn2binpad failed");
    }

    return std::string(reinterpret_cast<char*>(buf.data()), buf.size());
}