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

// 证明子块
std::string ProofSubBlock::ToString() const {
    std::stringstream ss;
    ss << index << "|" << signature_on_prev << "|" << manager_id << "|" 
       << merkle_root << "|" << proof_challenge << "|" << quality << "|" << timestamp;
    return ss.str();
}

std::string ProofSubBlock::ComputeHash() const {
    return ComputeSHA256StringBlock(ToString());
}

// 签名子块
std::string SignatureSubBlock::ToString() const {
    std::stringstream ss;
    ss << index << "|" << manager_id << "|" 
       << signature_on_prev << "|" << public_key << "|" << xor_signature;
    return ss.str();
}

std::string SignatureSubBlock::ComputeHash() const {
    return ComputeSHA256StringBlock(ToString());
}

// 交易子块
std::string TransactionSubBlock::ToString() const {
    std::stringstream ss;
    ss << tx_id << "|" << aid << "|" << root_apk << "|" << register_time;
    return ss.str();
}

std::string TransactionSubBlock::ComputeHash() const {
    return ComputeSHA256StringBlock(ToString());
}

// 修改记录
std::string ModificationRecord::ToString() const {
    std::stringstream ss;
    ss << "revise|" << tx_id << "|" << timestamp << "|" << block_id << "|" << reason << "|";
    
    // 旧随机数
    for (size_t i = 0; i < old_random_numbers.size(); i++) {
        if (i > 0) ss << ",";
        ss << old_random_numbers[i];
    }
    ss << "|";
    
    // 新随机数
    for (size_t i = 0; i < new_random_numbers.size(); i++) {
        if (i > 0) ss << ",";
        ss << new_random_numbers[i];
    }
    ss << "|";
    
    // 旧交易哈希
    std::string old_hash;
    for (const auto& tx : old_transactions) old_hash += tx.ComputeHash();
    ss << ComputeSHA256StringBlock(old_hash) << "|";
    
    // 新交易哈希
    std::string new_hash;
    for (const auto& tx : new_transactions) new_hash += tx.ComputeHash();
    ss << ComputeSHA256StringBlock(new_hash);
    
    return ss.str();
}

std::string ModificationRecord::ComputeHash() const {
    return ComputeSHA256StringBlock(ToString());
}

Block::Block() : height(0), proof_hash(""), timestamp(0) {}

std::string Block::ComputeProofHash() const {
    return ComputeSHA256StringBlock(signature.ComputeHash());
}

std::string Block::ComputeTransactionsHash() const {
    if (transactions.empty()) {
        return ComputeSHA256StringBlock("EMPTY");
    }
    std::string combined;
    for (const auto& tx : transactions) combined += tx.ComputeHash();
    return ComputeSHA256StringBlock(combined);
}

void Block::Print() const {
    std::cout << "Block " << height << ": proof_hash=" << proof_hash.substr(0, 16) << "...\n";
}

int Block::FindTransactionIndex(const std::string& aid) const {
    for (size_t i = 0; i < transactions.size(); i++) {
        if (transactions[i].aid == aid) return static_cast<int>(i);
    }
    return -1;
}

bool Block::PhysicalRevokeTransaction(const std::string& aid,
                                       const std::string& new_xor_signature) {
    int tx_index = FindTransactionIndex(aid);
    if (tx_index == -1) {
        std::cerr << "错误: 未找到 AID: " << aid << std::endl;
        return false;
    }
    
    transactions.erase(transactions.begin() + tx_index);
    signature.xor_signature = new_xor_signature;
    proof_hash = ComputeProofHash();
    
    return true;
}


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

bool Blockchain::SerializeBlock(const Block& block, std::ofstream& file) {
    if (!file.is_open()) return false;
    
    // 写入高度
    file.write(reinterpret_cast<const char*>(&block.height), sizeof(block.height));
    
    // 写入时间戳
    file.write(reinterpret_cast<const char*>(&block.timestamp), sizeof(block.timestamp));
    
    // 写入proof_hash
    size_t hash_len = block.proof_hash.length();
    file.write(reinterpret_cast<const char*>(&hash_len), sizeof(hash_len));
    file.write(block.proof_hash.c_str(), hash_len);
    
    // 序列化证明子块 - 使用字符串形式
    std::string proof_str = block.proof.ToString();
    size_t proof_len = proof_str.length();
    file.write(reinterpret_cast<const char*>(&proof_len), sizeof(proof_len));
    file.write(proof_str.c_str(), proof_len);
    
    // 序列化签名子块
    std::string sig_str = block.signature.ToString();
    size_t sig_len = sig_str.length();
    file.write(reinterpret_cast<const char*>(&sig_len), sizeof(sig_len));
    file.write(sig_str.c_str(), sig_len);
    
    // 写入交易数量
    size_t tx_count = block.transactions.size();
    file.write(reinterpret_cast<const char*>(&tx_count), sizeof(tx_count));
    
    // 序列化每个交易
    for (const auto& tx : block.transactions) {
        std::string tx_str = tx.ToString();
        size_t tx_len = tx_str.length();
        file.write(reinterpret_cast<const char*>(&tx_len), sizeof(tx_len));
        file.write(tx_str.c_str(), tx_len);
    }
    
    return file.good();
}

bool Blockchain::DeserializeBlock(Block& block, std::ifstream& file) {
    if (!file.is_open()) return false;
    
    // 读取高度
    file.read(reinterpret_cast<char*>(&block.height), sizeof(block.height));
    if (file.eof() || file.fail()) return false;
    
    // 读取时间戳
    file.read(reinterpret_cast<char*>(&block.timestamp), sizeof(block.timestamp));
    
    // 读取proof_hash
    size_t hash_len;
    file.read(reinterpret_cast<char*>(&hash_len), sizeof(hash_len));
    block.proof_hash.resize(hash_len);
    file.read(&block.proof_hash[0], hash_len);
    
    // 读取证明子块
    size_t proof_len;
    file.read(reinterpret_cast<char*>(&proof_len), sizeof(proof_len));
    std::string proof_str(proof_len, '\0');
    file.read(&proof_str[0], proof_len);
    
    // 解析proof_str - 按|分隔解析
    std::vector<std::string> proof_parts;
    std::stringstream proof_ss(proof_str);
    std::string part;
    while (std::getline(proof_ss, part, '|')) {
        proof_parts.push_back(part);
    }
    if (proof_parts.size() >= 7) {
        block.proof.index = std::stoi(proof_parts[0]);
        block.proof.signature_on_prev = proof_parts[1];
        block.proof.manager_id = proof_parts[2];
        block.proof.merkle_root = proof_parts[3];
        block.proof.proof_challenge = proof_parts[4];
        block.proof.quality = std::stod(proof_parts[5]);
        block.proof.timestamp = std::stoull(proof_parts[6]);
    }
    
    // 读取签名子块
    size_t sig_len;
    file.read(reinterpret_cast<char*>(&sig_len), sizeof(sig_len));
    std::string sig_str(sig_len, '\0');
    file.read(&sig_str[0], sig_len);
    
    // 解析sig_str
    std::vector<std::string> sig_parts;
    std::stringstream sig_ss(sig_str);
    while (std::getline(sig_ss, part, '|')) {
        sig_parts.push_back(part);
    }
    if (sig_parts.size() >= 5) {
        block.signature.index = std::stoi(sig_parts[0]);
        block.signature.manager_id = sig_parts[1];
        block.signature.signature_on_prev = sig_parts[2];
        block.signature.public_key = sig_parts[3];
        block.signature.xor_signature = sig_parts[4];
    }
    
    // 读取交易数量
    size_t tx_count;
    file.read(reinterpret_cast<char*>(&tx_count), sizeof(tx_count));
    
    // 读取每个交易
    block.transactions.clear();
    for (size_t i = 0; i < tx_count; i++) {
        size_t tx_len;
        file.read(reinterpret_cast<char*>(&tx_len), sizeof(tx_len));
        std::string tx_str(tx_len, '\0');
        file.read(&tx_str[0], tx_len);
        
        // 解析tx_str
        std::vector<std::string> tx_parts;
        std::stringstream tx_ss(tx_str);
        while (std::getline(tx_ss, part, '|')) {
            tx_parts.push_back(part);
        }
        if (tx_parts.size() >= 5) {
            TransactionSubBlock tx;
            tx.tx_id = tx_parts[0];
            tx.aid = tx_parts[1];
            tx.root_apk = tx_parts[2];
            tx.register_time = std::stoull(tx_parts[3]);
            block.transactions.push_back(tx);
        }
    }
    
    return file.good();
}

bool Blockchain::SerializeModificationRecord(const ModificationRecord& record, std::ofstream& file) {
    if (!file.is_open()) return false;
    
    std::string record_str = record.ToString();
    size_t len = record_str.length();
    file.write(reinterpret_cast<const char*>(&len), sizeof(len));
    file.write(record_str.c_str(), len);
    
    return file.good();
}

bool Blockchain::DeserializeModificationRecord(ModificationRecord& record, std::ifstream& file) {
    if (!file.is_open()) return false;
    
    size_t len;
    file.read(reinterpret_cast<char*>(&len), sizeof(len));
    if (file.eof() || file.fail() || len == 0) return false;
    
    std::string record_str(len, '\0');
    file.read(&record_str[0], len);
    
    // 解析记录: revise|tx_id|timestamp|block_id|reason|old_randoms|new_randoms|old_hash|new_hash
    std::vector<std::string> parts;
    std::stringstream ss(record_str);
    std::string part;
    while (std::getline(ss, part, '|')) {
        parts.push_back(part);
    }
    
    if (parts.size() >= 9 && parts[0] == "revise") {
        record.tx_id = parts[1];
        record.timestamp = std::stoull(parts[2]);
        record.block_id = std::stoi(parts[3]);
        record.reason = parts[4];
        
        // 解析旧随机数
        std::stringstream old_ss(parts[5]);
        record.old_random_numbers.clear();
        while (std::getline(old_ss, part, ',')) {
            if (!part.empty()) record.old_random_numbers.push_back(part);
        }
        
        // 解析新随机数
        std::stringstream new_ss(parts[6]);
        record.new_random_numbers.clear();
        while (std::getline(new_ss, part, ',')) {
            if (!part.empty()) record.new_random_numbers.push_back(part);
        }
        
        return true;
    }
    
    return false;
}

bool Blockchain::InitGenesisBlock() {
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
    
    return SaveToFile();
}

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
    
    return SaveToFile();
}

bool Blockchain::AddModificationRecord(const ModificationRecord& record) {
    modification_history_.push_back(record);
    
    // 保存到文件
    std::ofstream file(modify_file_, std::ios::binary | std::ios::app);
    if (!file.is_open()) return false;
    
    bool result = SerializeModificationRecord(record, file);
    file.close();
    return result;
}

std::vector<ModificationRecord> Blockchain::GetModificationRecords(int block_id) const {
    std::vector<ModificationRecord> result;
    for (const auto& record : modification_history_) {
        if (record.block_id == block_id) {
            result.push_back(record);
        }
    }
    return result;
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

bool Blockchain::PhysicalRevokeTransaction(const std::string& aid,
                                            const std::string& new_xor_signature) {
    auto it = aid_to_height_.find(aid);
    if (it == aid_to_height_.end()) {
        std::cerr << "错误: 未找到 AID: " << aid << std::endl;
        return false;
    }
    
    int height = it->second;
    bool success = chain_[height].PhysicalRevokeTransaction(aid, new_xor_signature);
    
    if (success) {
        aid_to_height_.erase(aid);
        SaveToFile();
    }
    
    return success;
}

bool Blockchain::SaveToFile() {
    std::ofstream file(storage_file_, std::ios::binary);
    if (!file.is_open()) return false;
    
    size_t chain_size = chain_.size();
    file.write(reinterpret_cast<const char*>(&chain_size), sizeof(chain_size));
    
    for (const auto& block : chain_) {
        if (!SerializeBlock(block, file)) {
            return false;
        }
    }
    
    file.close();
    return true;
}

bool Blockchain::LoadFromFile() {
    if (!std::filesystem::exists(storage_file_)) {
        return InitGenesisBlock();
    }
    
    std::ifstream file(storage_file_, std::ios::binary);
    if (!file.is_open()) {
        return InitGenesisBlock();
    }
    
    size_t chain_size;
    file.read(reinterpret_cast<char*>(&chain_size), sizeof(chain_size));
    
    chain_.clear();
    aid_to_height_.clear();
    
    for (size_t i = 0; i < chain_size; i++) {
        Block block;
        if (!DeserializeBlock(block, file)) {
            std::cerr << "警告: 读取区块失败" << std::endl;
            break;
        }
        chain_.push_back(block);
        for (const auto& tx : block.transactions) {
            aid_to_height_[tx.aid] = block.height;
        }
    }
    
    file.close();
    
    // 加载修改历史
    if (std::filesystem::exists(modify_file_)) {
        std::ifstream mod_file(modify_file_, std::ios::binary);
        if (mod_file.is_open()) {
            modification_history_.clear();
            while (true) {
                ModificationRecord record;
                if (!DeserializeModificationRecord(record, mod_file)) break;
                modification_history_.push_back(record);
            }
            mod_file.close();
        }
    }
    
    if (chain_.empty()) {
        return InitGenesisBlock();
    }
    
    return true;
}

} // namespace EcoRedact
