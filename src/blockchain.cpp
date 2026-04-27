#include "blockchain.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <filesystem>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <cstring>
#include <algorithm>

namespace EcoRedact {

// ==================== 辅助函数 ====================

static std::string BytesToHexStringBlock(const unsigned char* bytes, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; i++) {
        ss << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return ss.str();
}

static std::string ComputeSHA256StringBlock(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), hash);
    return BytesToHexStringBlock(hash, SHA256_DIGEST_LENGTH);
}

static std::string XorStringsBlockHelper(const std::string& a, const std::string& b) {
    size_t max_len = std::max(a.size(), b.size());
    std::string result(max_len, 0);
    for (size_t i = 0; i < a.size(); i++) result[i] = result[i] ^ a[i];
    for (size_t i = 0; i < b.size(); i++) result[i] = result[i] ^ b[i];
    return result;
}


std::string ProofSubBlock::ToString() const {
    std::stringstream ss;
    ss << index << "|" << signature_on_prev << "|" << manager_id << "|" 
       << merkle_root << "|" << proof_challenge << "|" << quality << "|" << timestamp;
    return ss.str();
}

std::string ProofSubBlock::ComputeHash() const {
    return ComputeSHA256StringBlock(ToString());
}


std::string SignatureSubBlock::ToString() const {
    std::stringstream ss;
    ss << index << "|" << manager_id << "|" 
       << signature_on_prev << "|" << public_key;
    return ss.str();
}

std::string SignatureSubBlock::ComputeHash() const {
    return ComputeSHA256StringBlock(ToString());
}


std::string TransactionSubBlock::ToString() const {
    std::stringstream ss;
    ss << tx_id << "|" << aid << "|" << root_apk << "|" << deri_info << "|" << register_time;
    return ss.str();
}

std::string TransactionSubBlock::ComputeHash() const {
    return ComputeSHA256StringBlock(ToString());
}


Block::Block() : height(0), proof_hash(""), timestamp(0) {}

std::string Block::ComputeProofHash() const {
    return ComputeSHA256StringBlock(signature.ComputeHash());
}


std::string Block::ComputeTransactionsHash() const {
    if (transactions.empty()) return ComputeSHA256StringBlock("EMPTY");
    std::string combined;
    for (const auto& tx : transactions) combined += tx.ComputeHash();
    return ComputeSHA256StringBlock(combined);
}

void Block::Print() const {
    /*
    std::cout << "  ┌─────────────────────────────────────────" << std::endl;
    std::cout << "  │ 区块高度: " << height << std::endl;
    std::cout << "  │ 证明链哈希: " << proof_hash.substr(0, 32) << "..." << std::endl;
    std::cout << "  │ 时间戳: " << timestamp << std::endl;
    std::cout << "  │ 交易数量: " << transactions.size() << std::endl;
    std::cout << "  │ 记账管理员: " << signature.manager_id << std::endl;
    std::cout << "  └─────────────────────────────────────────" << std::endl;
    for (const auto& tx : transactions) {
        std::cout << "      ├─ AID: " << tx.aid.substr(0, 32) << "..." << std::endl;
    }
    */
}

int Block::FindTransactionIndex(const std::string& aid) const {
    for (size_t i = 0; i < transactions.size(); i++) {
        if (transactions[i].aid == aid) return static_cast<int>(i);
    }
    return -1;
}

// 物理撤销
bool Block::PhysicalRevokeTransaction(const std::string& aid,
                                       const std::string& new_xor_signature) {
    int tx_index = FindTransactionIndex(aid);
    if (tx_index == -1) {
        std::cerr << "错误: 未找到 AID: " << aid << std::endl;
        return false;
    }
    
    std::string old_proof_hash = proof_hash;
    std::string revoked_aid = transactions[tx_index].aid;

    transactions.erase(transactions.begin() + tx_index);
    std::cout << "    已删除恶意车辆的交易" << std::endl;
    
    signature.xor_signature = new_xor_signature;
    
    proof_hash = ComputeProofHash();

    
    std::cout << "  [物理撤销] 成功删除 AID: " << revoked_aid.substr(0, 32) << "..." << std::endl;
    
    return true;
}

// ==================== Blockchain ====================

Blockchain::Blockchain() {
    if (!std::filesystem::exists("./keys/blockchain")) {
        std::filesystem::create_directories("./keys/blockchain");
    }
}

Blockchain::~Blockchain() {}

std::string Blockchain::ComputeSHA256(const std::string& input) {
    return ComputeSHA256StringBlock(input);
}

std::string Blockchain::GenerateTxID(const std::string& aid, const std::string& apk) {
    std::string input = aid + "|" + apk + "|" + 
        std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
    return ComputeSHA256(input).substr(0, 16);
}

std::string Blockchain::XorStrings(const std::string& a, const std::string& b) {
    return XorStringsBlockHelper(a, b);
}

// 初始化创世区块
bool Blockchain::InitGenesisBlock() {
    std::cout << "\n  [创世区块] 初始化区块链..." << std::endl;
    
    Block genesis;
    genesis.height = 0;
    genesis.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    genesis.proof.index = 0;
    genesis.proof.signature_on_prev = "GENESIS_SIG";
    genesis.proof.manager_id = "GENESIS";
    genesis.proof.merkle_root = ComputeSHA256("GENESIS_MERKLE");
    genesis.proof.proof_challenge = "GENESIS_CHALLENGE";
    genesis.proof.quality = 0.0;
    genesis.proof.timestamp = genesis.timestamp;
    
    genesis.signature.index = 0;
    genesis.signature.manager_id = "GENESIS";
    genesis.signature.xor_signature = ComputeSHA256("GENESIS_XOR_VALUE");
    genesis.signature.signature_on_prev = "GENESIS_PREV_SIG";
    genesis.signature.public_key = "GENESIS_PK";
    
    genesis.proof_hash = genesis.ComputeProofHash();
    
    chain_.push_back(genesis);
    aid_to_height_.clear();
    
    std::cout << "  [创世区块] 创建成功，证明链哈希: " << genesis.proof_hash.substr(0, 32) << "..." << std::endl;
    return SaveToFile();
}

// 添加新区块
bool Blockchain::AddBlock(const Block& block) {
    if (block.height != static_cast<int>(chain_.size())) {
        std::cerr << "错误: 区块高度不匹配" << std::endl;
        return false;
    }
    
    if (!chain_.empty()) {
        if (block.proof.signature_on_prev.empty()) {
            std::cerr << "错误: 证明子块签名缺失" << std::endl;
            return false;
        }
        if (block.signature.signature_on_prev.empty()) {
            std::cerr << "错误: 签名子块前一签名缺失" << std::endl;
            return false;
        }
    }
    
    std::string computed_hash = block.ComputeProofHash();
    if (computed_hash != block.proof_hash) {
        std::cerr << "错误: 证明链哈希不匹配" << std::endl;
        return false;
    }
    
    chain_.push_back(block);
    
    for (const auto& tx : block.transactions) {
        aid_to_height_[tx.aid] = block.height;
    }
    
    std::cout << "  [区块链] 新区块已添加，高度: " << block.height 
              << "，交易数: " << block.transactions.size() << std::endl;
    return SaveToFile();
}

Block* Blockchain::GetBlock(int height) {
    if (height < 0 || height >= static_cast<int>(chain_.size())) return nullptr;
    return &chain_[height];
}

TransactionSubBlock* Blockchain::FindTransactionByAID(const std::string& aid) {
    auto it = aid_to_height_.find(aid);
    if (it == aid_to_height_.end()) return nullptr;
    int height = it->second;
    if (height >= static_cast<int>(chain_.size())) return nullptr;
    for (auto& tx : chain_[height].transactions) {
        if (tx.aid == aid) return &tx;
    }
    return nullptr;
}

int Blockchain::GetLatestHeight() const {
    return static_cast<int>(chain_.size()) - 1;
}

// 物理撤销
bool Blockchain::PhysicalRevokeTransaction(const std::string& aid,
                                            const std::string& new_xor_signature) {
    auto it = aid_to_height_.find(aid);
    if (it == aid_to_height_.end()) {
        std::cerr << "错误: 未找到 AID: " << aid << std::endl;
        return false;
    }
    
    int height = it->second;
    std::cout << "\n  [物理撤销] 开始处理 AID: " << aid.substr(0, 32) << "..." 
              << " (位于区块高度 " << height << ")" << std::endl;
    
    bool success = chain_[height].PhysicalRevokeTransaction(aid, new_xor_signature);
    
    if (success) {
        aid_to_height_.erase(aid);
        SaveToFile();
        std::cout << "  [物理撤销] 完成，AID 已从链上物理删除" << std::endl;
    }
    
    return success;
}

// 保存到文件
bool Blockchain::SaveToFile() {
    std::ofstream file(storage_file_, std::ios::binary);
    if (!file.is_open()) return false;
    size_t chain_size = chain_.size();
    file.write(reinterpret_cast<const char*>(&chain_size), sizeof(chain_size));
    file.close();
    return true;
}

// 从文件加载
bool Blockchain::LoadFromFile() {
    if (!std::filesystem::exists(storage_file_)) {
        std::cout << "  [区块链] 存储文件不存在，将创建新区块链" << std::endl;
        return InitGenesisBlock();
    }
    std::ifstream file(storage_file_, std::ios::binary);
    if (!file.is_open()) {
        std::cout << "  [区块链] 无法打开存储文件，将创建新区块链" << std::endl;
        return InitGenesisBlock();
    }
    
    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::cout << "  [区块链] 找到存储文件，大小: " << file_size << " 字节" << std::endl;
    
    file.close();

    return InitGenesisBlock();
}

// 打印区块链状态
void Blockchain::PrintBlockchain() const {
    /*
    std::cout << "\n========================================" << std::endl;
    std::cout << "  区块链状态" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "  区块总数: " << chain_.size() << std::endl;
    std::cout << "  活跃 AID 数量: " << aid_to_height_.size() << std::endl;
    for (const auto& block : chain_) block.Print();
    */
}

} // namespace EcoRedact