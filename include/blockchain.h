#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

namespace EcoRedact {

// ==================== 证明子块 ====================
struct ProofSubBlock {
    int index;
    std::string signature_on_prev;
    std::string manager_id;
    std::string merkle_root;
    std::string proof_challenge;
    double quality;
    uint64_t timestamp;
    
    std::string ToString() const;
    std::string ComputeHash() const;
};

// ==================== 签名子块 ====================
struct SignatureSubBlock {
    int index;
    std::string manager_id;
    std::string xor_signature;
    std::string signature_on_prev;
    std::string public_key;
    
    std::string ToString() const;
    std::string ComputeHash() const;
};

// ==================== 交易子块 ====================
struct TransactionSubBlock {
    std::string tx_id;
    std::string aid;
    std::string root_apk;
    std::string deri_info;
    uint64_t register_time;
    
    std::string ToString() const;
    std::string ComputeHash() const;
};

// ==================== 区块结构 ====================
struct Block {
    int height;
    ProofSubBlock proof;
    SignatureSubBlock signature;
    std::vector<TransactionSubBlock> transactions;
    std::string proof_hash;
    uint64_t timestamp;
    
    Block();
    
    std::string ComputeProofHash() const;
    
    std::string ComputeTransactionsHash() const;
    
    void Print() const;
    int FindTransactionIndex(const std::string& aid) const;
    
    bool PhysicalRevokeTransaction(const std::string& aid,
                                    const std::string& new_xor_signature);
};

// ==================== 区块链类 ====================
class Blockchain {
public:
    Blockchain();
    ~Blockchain();
    
    bool InitGenesisBlock();
    bool AddBlock(const Block& block);
    Block* GetBlock(int height);
    TransactionSubBlock* FindTransactionByAID(const std::string& aid);
    int GetLatestHeight() const;
    
    bool PhysicalRevokeTransaction(const std::string& aid,
                                    const std::string& new_xor_signature);
    
    bool SaveToFile();
    bool LoadFromFile();
    void PrintBlockchain() const;
    
    const std::vector<Block>& GetChain() const { return chain_; }
    
    std::string ComputeSHA256(const std::string& input);
    std::string XorStrings(const std::string& a, const std::string& b);

private:
    std::vector<Block> chain_;
    std::string storage_file_ = "./keys/blockchain/blockchain.dat";
    std::map<std::string, int> aid_to_height_;
    
    std::string GenerateTxID(const std::string& aid, const std::string& apk);
};

} // namespace EcoRedact

#endif // BLOCKCHAIN_H