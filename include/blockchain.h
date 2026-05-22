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

// 证明子块
struct ProofSubBlock {
    int index;                      // 区块序号 i
    std::string signature_on_prev;  // 对前一区块证明子块的签名
    std::string manager_id;         // 记账者ID
    std::string merkle_root;        // 交易Merkle树根
    std::string proof_challenge;    // 空间证明挑战
    double quality;                 // 空间证明质量
    uint64_t timestamp;             // 时间戳
    
    std::string ToString() const;
    std::string ComputeHash() const;
};

// 签名子块
struct SignatureSubBlock {
    int index;                      // 区块序号 i
    std::string manager_id;         // 记账者ID
    std::string xor_signature;      // 异或值的签名
    std::string signature_on_prev;  // 对前一区块签名子块的签名
    std::string public_key;         // 记账者公钥
    
    std::string ToString() const;
    std::string ComputeHash() const;
};

// 交易子块
struct TransactionSubBlock {
    std::string tx_id;              // 交易ID
    std::string aid;                // 匿名身份标识 AID_i
    std::string root_apk;           // 根匿名公钥 apk_i^r
    uint64_t register_time;         // 注册时间戳
    
    std::string ToString() const;
    std::string ComputeHash() const;
};

// 区块结构
struct Block {
    int height;
    ProofSubBlock proof;            // 证明子块
    SignatureSubBlock signature;    // 签名子块
    std::vector<TransactionSubBlock> transactions;  // 交易子块
    std::string proof_hash;         // 证明链哈希
    uint64_t timestamp;
    
    Block();
    
    std::string ComputeProofHash() const;
    std::string ComputeTransactionsHash() const;  // 计算 Hash
    
    void Print() const;
    int FindTransactionIndex(const std::string& aid) const;
    
    // 物理撤销交易（从交易子块中删除指定交易）
    bool PhysicalRevokeTransaction(const std::string& aid,
                                    const std::string& new_xor_signature);
};

// 修改记录交易
struct ModificationRecord {
    std::string tx_id;              // 交易号
    uint64_t timestamp;             // 生成时间
    int block_id;                   // 数据修改的区块号
    std::string reason;             // 修改原因
    std::vector<std::string> old_random_numbers;  // 修改前管理员专属随机数
    std::vector<std::string> new_random_numbers;  // 修改后管理员专属随机数
    std::vector<TransactionSubBlock> old_transactions;  // 修改前交易集合
    std::vector<TransactionSubBlock> new_transactions;  // 修改后交易集合
    
    std::string ToString() const;
    std::string ComputeHash() const;
};

// 区块链类
class Blockchain {
public:
    Blockchain();
    ~Blockchain();
    
    bool InitGenesisBlock();
    bool AddBlock(const Block& block);
    Block* GetBlock(int height);
    TransactionSubBlock* FindTransactionByAID(const std::string& aid);
    int GetLatestHeight() const;
    
    // 物理撤销交易
    bool PhysicalRevokeTransaction(const std::string& aid,
                                    const std::string& new_xor_signature);
    
    // 记录修改操作
    bool AddModificationRecord(const ModificationRecord& record);
    std::vector<ModificationRecord> GetModificationRecords(int block_id) const;
    
    bool SaveToFile();
    bool LoadFromFile();
    
    const std::vector<Block>& GetChain() const { return chain_; }
    const std::vector<ModificationRecord>& GetModificationHistory() const { return modification_history_; }
    
    std::string ComputeSHA256(const std::string& input);
    std::string XorStrings(const std::string& a, const std::string& b);

private:
    std::vector<Block> chain_;
    std::vector<ModificationRecord> modification_history_;  // 修改历史记录
    std::string storage_file_ = "./keys/blockchain/blockchain.dat";
    std::string modify_file_ = "./keys/blockchain/modifications.dat";
    std::map<std::string, int> aid_to_height_;
    
    std::string GenerateTxID(const std::string& aid, const std::string& apk);
    
    bool SerializeBlock(const Block& block, std::ofstream& file);
    bool DeserializeBlock(Block& block, std::ifstream& file);
    bool SerializeModificationRecord(const ModificationRecord& record, std::ofstream& file);
    bool DeserializeModificationRecord(ModificationRecord& record, std::ifstream& file);
};

} // namespace EcoRedact

#endif // BLOCKCHAIN_H
