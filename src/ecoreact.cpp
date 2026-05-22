#include "ecoreact.h"
#include "blockchain.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <filesystem>
#include <random>
#include <cmath>
#include <cstring>
#include <ctime>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ecdh.h>
#include <openssl/aes.h>
#include <algorithm>

namespace EcoRedact {

static std::string XorStringsInternal(const std::string& a, const std::string& b) {
    size_t max_len = std::max(a.size(), b.size());
    std::string result(max_len, 0);
    for (size_t i = 0; i < a.size(); i++) result[i] = result[i] ^ a[i];
    for (size_t i = 0; i < b.size(); i++) result[i] = result[i] ^ b[i];
    return result;
}

static std::string BytesToHexStringStatic(const unsigned char* bytes, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; i++) {
        ss << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return ss.str();
}

static std::string ComputeSHA256StringStatic(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), hash);
    return BytesToHexStringStatic(hash, SHA256_DIGEST_LENGTH);
}

static std::string PointToHex(EC_GROUP* group, EC_POINT* point) {
    if (!point) return "";
    char* hex = EC_POINT_point2hex(group, point, POINT_CONVERSION_COMPRESSED, nullptr);
    if (!hex) return "";
    std::string result(hex);
    OPENSSL_free(hex);
    return result;
}

static std::vector<unsigned char> HexToBytesStatic(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i + 1 < hex.length(); i += 2) {
        std::string byte_str = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoi(byte_str, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// ECIES 加密/解密（陷门单向函数）
std::string EcoRedactSystem::ECIESEncrypt(const std::string& plaintext, EC_POINT* public_key) {
    if (!public_key || !current_params_ || !current_params_->group) {
        std::cerr << "错误: ECIES加密参数无效" << std::endl;
        return "";
    }
    
    // 将十六进制字符串转换为二进制数据
    std::vector<unsigned char> plaintext_bytes;
    for (size_t i = 0; i + 1 < plaintext.length(); i += 2) {
        std::string byte_str = plaintext.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoi(byte_str, nullptr, 16));
        plaintext_bytes.push_back(byte);
    }
    
    // 如果转换失败，尝试作为ASCII字符串处理
    if (plaintext_bytes.empty()) {
        plaintext_bytes.assign(plaintext.begin(), plaintext.end());
    }
    
    unsigned char hash[32];
    SHA256(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length(), hash);
    BIGNUM* ephemeral_sk = BN_new();
    BN_bin2bn(hash, 32, ephemeral_sk);
    BN_mod(ephemeral_sk, ephemeral_sk, current_params_->q, current_params_->ctx);
    
    EC_POINT* ephemeral_pk = EC_POINT_new(current_params_->group);
    EC_POINT_mul(current_params_->group, ephemeral_pk, ephemeral_sk, nullptr, nullptr, current_params_->ctx);
    
    EC_POINT* shared_point = EC_POINT_new(current_params_->group);
    EC_POINT_mul(current_params_->group, shared_point, nullptr, public_key, ephemeral_sk, current_params_->ctx);
    
    char* shared_hex = EC_POINT_point2hex(current_params_->group, shared_point, 
                                           POINT_CONVERSION_COMPRESSED, current_params_->ctx);
    std::vector<unsigned char> aes_key(32);
    SHA256(reinterpret_cast<const unsigned char*>(shared_hex), strlen(shared_hex), aes_key.data());
    OPENSSL_free(shared_hex);
    
    const int NONCE_LEN = 12;
    unsigned char nonce[NONCE_LEN];
    memset(nonce, 0, NONCE_LEN);
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, aes_key.data(), nonce);
    
    std::vector<unsigned char> ciphertext(plaintext_bytes.size());
    int len = 0;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext_bytes.data(), plaintext_bytes.size());
    EVP_CIPHER_CTX_free(ctx);
    
    char* ephemeral_pk_hex = EC_POINT_point2hex(current_params_->group, ephemeral_pk,
                                                 POINT_CONVERSION_COMPRESSED, current_params_->ctx);
    std::string result;
    result.append(ephemeral_pk_hex);
    result.append(reinterpret_cast<char*>(nonce), NONCE_LEN);
    result.append(reinterpret_cast<char*>(ciphertext.data()), len);
    
    OPENSSL_free(ephemeral_pk_hex);
    EC_POINT_free(ephemeral_pk);
    EC_POINT_free(shared_point);
    BN_free(ephemeral_sk);
    
    return result;
}

std::string EcoRedactSystem::ECIESDecrypt(const std::string& ciphertext, BIGNUM* private_key) {
    if (!private_key || !current_params_ || !current_params_->group) {
        std::cerr << "错误: ECIES解密参数无效" << std::endl;
        return "";
    }
    
    size_t ephemeral_pk_hex_len = 66;  // 压缩格式公钥的hex长度
    if (ciphertext.length() < ephemeral_pk_hex_len + 12) {
        std::cerr << "错误: 密文长度不足: " << ciphertext.length() << std::endl;
        return "";
    }
    
    std::string ephemeral_pk_hex = ciphertext.substr(0, ephemeral_pk_hex_len);
    const unsigned char* nonce = reinterpret_cast<const unsigned char*>(ciphertext.data() + ephemeral_pk_hex_len);
    size_t enc_len = ciphertext.length() - ephemeral_pk_hex_len - 12;
    const unsigned char* enc_data = reinterpret_cast<const unsigned char*>(ciphertext.data() + ephemeral_pk_hex_len + 12);
    
    EC_POINT* ephemeral_pk = EC_POINT_new(current_params_->group);
    EC_POINT* shared_point = EC_POINT_new(current_params_->group);
    EC_POINT_mul(current_params_->group, shared_point, nullptr, ephemeral_pk, private_key, current_params_->ctx);
    
    char* shared_hex = EC_POINT_point2hex(current_params_->group, shared_point,
                                           POINT_CONVERSION_COMPRESSED, current_params_->ctx);
    if (!shared_hex) {
        std::cerr << "错误: 无法计算共享密钥" << std::endl;
        EC_POINT_free(ephemeral_pk);
        EC_POINT_free(shared_point);
        return "";
    }
    
    std::vector<unsigned char> aes_key(32);
    SHA256(reinterpret_cast<const unsigned char*>(shared_hex), strlen(shared_hex), aes_key.data());
    OPENSSL_free(shared_hex);
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, aes_key.data(), nonce);
    
    std::vector<unsigned char> plaintext_bytes(enc_len);
    int len = 0;
    if (EVP_DecryptUpdate(ctx, plaintext_bytes.data(), &len, enc_data, enc_len) != 1) {
        std::cerr << "错误: AES解密失败" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        EC_POINT_free(ephemeral_pk);
        EC_POINT_free(shared_point);
        return "";
    }
    EVP_CIPHER_CTX_free(ctx);
    
    EC_POINT_free(ephemeral_pk);
    EC_POINT_free(shared_point);
    
    // 将解密后的二进制数据转换为十六进制字符串
    std::string result;
    for (int i = 0; i < len; i++) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02X", plaintext_bytes[i]);
        result += hex;
    }
    
    // 验证结果是否为有效的十六进制
    for (char c : result) {
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'))) {
            std::cerr << "错误: 解密结果包含非十六进制字符: " << c << std::endl;
            return "";
        }
    }
    
    return result;
}

// SystemParams 实现
SystemParams::SystemParams() : group(nullptr), P(nullptr), q(nullptr), ctx(nullptr) {}

SystemParams::~SystemParams() {
    if (P) EC_POINT_free(P);
    if (group) EC_GROUP_free(group);
    if (q) BN_free(q);
    if (ctx) BN_CTX_free(ctx);
}

// VehicleStorage 实现
VehicleStorage::VehicleStorage()
    : vsk(nullptr), vpk(nullptr), ask_root(nullptr), apk_root(nullptr), vapk_root(nullptr) {}

VehicleStorage::~VehicleStorage() { Clear(); }

void VehicleStorage::Clear() {
    if (vsk) { BN_free(vsk); vsk = nullptr; }
    if (vpk) { EC_POINT_free(vpk); vpk = nullptr; }
    if (ask_root) { BN_free(ask_root); ask_root = nullptr; }
    if (apk_root) { EC_POINT_free(apk_root); apk_root = nullptr; }
    if (vapk_root) { EC_POINT_free(vapk_root); vapk_root = nullptr; }
}

bool VehicleStorage::SaveToFile(const std::string& dir) const {
    std::filesystem::create_directories(dir);
    std::string filename = dir + "/vehicle_" + entity_id + ".key";
    std::ofstream file(filename);
    if (!file.is_open()) return false;
    
    char* vsk_hex = vsk ? BN_bn2hex(vsk) : strdup("0");
    char* ask_hex = ask_root ? BN_bn2hex(ask_root) : strdup("0");
    
    file << "# Vehicle Storage\n";
    file << "entity_id=" << entity_id << "\n";
    file << "vsk=" << vsk_hex << "\n";
    file << "certificate=" << certificate << "\n";
    file << "ask_root=" << ask_hex << "\n";
    file << "deri_root=" << deri_root << "\n";
    file << "aid=" << aid << "\n";
    
    OPENSSL_free(vsk_hex);
    OPENSSL_free(ask_hex);
    file.close();
    return true;
}

bool VehicleStorage::LoadFromFile(const std::string& dir, const std::string& id) {
    std::string filename = dir + "/vehicle_" + id + ".key";
    std::ifstream file(filename);
    if (!file.is_open()) return false;
    
    std::string line;
    while (std::getline(file, line)) {
        if (line.find("vsk=") == 0) {
            if (vsk) BN_free(vsk);
            BN_hex2bn(&vsk, line.substr(4).c_str());
        } else if (line.find("ask_root=") == 0) {
            if (ask_root) BN_free(ask_root);
            BN_hex2bn(&ask_root, line.substr(9).c_str());
        } else if (line.find("deri_root=") == 0) {
            deri_root = line.substr(10);
        } else if (line.find("aid=") == 0) {
            aid = line.substr(4);
        } else if (line.find("certificate=") == 0) {
            certificate = line.substr(12);
        } else if (line.find("entity_id=") == 0) {
            entity_id = line.substr(10);
        }
    }
    file.close();
    return true;
}

// ManagerStorage 实现
ManagerStorage::ManagerStorage()
    : msk(nullptr), mpk(nullptr), committed_space(0), last_quality(0.0), random_x(nullptr) {}

ManagerStorage::~ManagerStorage() { Clear(); }

void ManagerStorage::Clear() {
    if (msk) { BN_free(msk); msk = nullptr; }
    if (mpk) { EC_POINT_free(mpk); mpk = nullptr; }
    if (random_x) { BN_free(random_x); random_x = nullptr; }
}

bool ManagerStorage::SaveToFile(const std::string& dir) const {
    std::filesystem::create_directories(dir);
    std::string filename = dir + "/manager_" + entity_id + ".key";
    std::ofstream file(filename);
    if (!file.is_open()) return false;
    
    char* msk_hex = msk ? BN_bn2hex(msk) : strdup("0");
    char* random_hex = random_x ? BN_bn2hex(random_x) : strdup("0");
    
    file << "# Manager Storage\n";
    file << "entity_id=" << entity_id << "\n";
    file << "msk=" << msk_hex << "\n";
    file << "committed_space=" << committed_space << "\n";
    file << "random_x=" << random_hex << "\n";
    
    //std::cout << "    保存 " << entity_id << ": random_x=" << random_hex << std::endl;
    
    OPENSSL_free(msk_hex);
    OPENSSL_free(random_hex);
    file.close();
    return true;
}

bool ManagerStorage::LoadFromFile(const std::string& dir, const std::string& id) {
    std::string filename = dir + "/manager_" + id + ".key";
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cout << "  警告: 无法打开管理员文件 " << filename << std::endl;
        return false;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        if (line.find("msk=") == 0) {
            std::string hex_str = line.substr(4);
            if (msk) BN_free(msk);
            BN_hex2bn(&msk, hex_str.c_str());
        } else if (line.find("random_x=") == 0) {
            std::string hex_str = line.substr(9);
            if (random_x) BN_free(random_x);
            BN_hex2bn(&random_x, hex_str.c_str());
            // 调试输出
            std::cout << "    加载 " << id << ": random_x=" << hex_str << std::endl;
        } else if (line.find("committed_space=") == 0) {
            committed_space = std::stoi(line.substr(16));
        } else if (line.find("entity_id=") == 0) {
            entity_id = line.substr(10);
        }
    }
    file.close();
    return true;
}

// RSUStorage 实现
RSUStorage::RSUStorage() : rsk(nullptr), rpk(nullptr) {}

RSUStorage::~RSUStorage() { Clear(); }

void RSUStorage::Clear() {
    if (rsk) { BN_free(rsk); rsk = nullptr; }
    if (rpk) { EC_POINT_free(rpk); rpk = nullptr; }
}

bool RSUStorage::SaveToFile(const std::string& dir) const {
    std::filesystem::create_directories(dir);
    std::string filename = dir + "/rsu_" + entity_id + ".key";
    std::ofstream file(filename);
    if (!file.is_open()) return false;
    
    char* rsk_hex = rsk ? BN_bn2hex(rsk) : strdup("0");
    file << "# RSU Storage\n";
    file << "entity_id=" << entity_id << "\n";
    file << "rsk=" << rsk_hex << "\n";
    OPENSSL_free(rsk_hex);
    file.close();
    return true;
}

bool RSUStorage::LoadFromFile(const std::string& dir, const std::string& id) {
    std::string filename = dir + "/rsu_" + id + ".key";
    std::ifstream file(filename);
    if (!file.is_open()) return false;
    
    std::string line;
    while (std::getline(file, line)) {
        if (line.find("rsk=") == 0) {
            BN_hex2bn(&rsk, line.substr(4).c_str());
        } else if (line.find("entity_id=") == 0) {
            entity_id = line.substr(10);
        }
    }
    file.close();
    return true;
}

// RegisterRequest 实现
RegisterRequest::RegisterRequest() : apk_root(nullptr), vapk_root(nullptr) {}

RegisterRequest::~RegisterRequest() {
    if (apk_root) EC_POINT_free(apk_root);
    if (vapk_root) EC_POINT_free(vapk_root);
}

static bool VerifyVAPKEquation(EC_GROUP* group, BN_CTX* ctx,
                                EC_POINT* vpk, EC_POINT* apk, 
                                EC_POINT* vapk, BIGNUM* msk) {
    EC_POINT* msk_apk = EC_POINT_new(group);
    EC_POINT_mul(group, msk_apk, nullptr, apk, msk, ctx);
    EC_POINT* expected = EC_POINT_new(group);
    EC_POINT_add(group, expected, vpk, msk_apk, ctx);
    bool valid = (EC_POINT_cmp(group, expected, vapk, ctx) == 0);
    EC_POINT_free(msk_apk);
    EC_POINT_free(expected);
    return valid;
}

void RegisterRequest::BuildRequest(SystemParams* params, 
                                    EC_POINT* apk_root, 
                                    EC_POINT* vapk_root,
                                    const std::string& deri_root,
                                    const std::string& certificate,
                                    BIGNUM* vsk,
                                    const std::string& aid) {
    this->apk_root = EC_POINT_new(params->group);
    this->vapk_root = EC_POINT_new(params->group);
    EC_POINT_copy(this->apk_root, apk_root);
    EC_POINT_copy(this->vapk_root, vapk_root);
    this->deri_root = deri_root;
    this->certificate = certificate;
    this->aid = aid;
    
    std::string apk_hex = PointToHex(params->group, apk_root);
    std::string vapk_hex = PointToHex(params->group, vapk_root);
    std::string sign_data = apk_hex + "|" + vapk_hex + "|" + deri_root + "|" + aid;
    
    EC_KEY* eckey = EC_KEY_new();
    EC_KEY_set_group(eckey, params->group);
    EC_KEY_set_private_key(eckey, vsk);
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(sign_data.c_str()), sign_data.length(), hash);
    ECDSA_SIG* sig = ECDSA_do_sign(hash, SHA256_DIGEST_LENGTH, eckey);
    
    unsigned char* der = nullptr;
    int der_len = i2d_ECDSA_SIG(sig, &der);
    this->signature = BytesToHexStringStatic(der, der_len);
    
    OPENSSL_free(der);
    ECDSA_SIG_free(sig);
    EC_KEY_free(eckey);
}

bool RegisterRequest::Verify(SystemParams* params, EC_POINT* vpk, BIGNUM* msk) const {
    std::cout << "\n  ========== 验证注册请求 ==========" << std::endl;
    
    if (certificate.empty()) {
        std::cout << "  [验证1/3] 证书: 为空" << std::endl;
        return false;
    }
    std::cout << "  [验证1/3] 证书: 有效" << std::endl;
    
    std::string apk_hex = PointToHex(params->group, this->apk_root);
    std::string vapk_hex = PointToHex(params->group, this->vapk_root);
    std::string sign_data = apk_hex + "|" + vapk_hex + "|" + deri_root + "|" + aid;
    
    EC_KEY* eckey = EC_KEY_new();
    EC_KEY_set_group(eckey, params->group);
    EC_KEY_set_public_key(eckey, vpk);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(sign_data.c_str()), sign_data.length(), hash);
    std::vector<unsigned char> der_bytes = HexToBytesStatic(this->signature);
    const unsigned char* der_ptr = der_bytes.data();
    ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &der_ptr, der_bytes.size());
    int result = ECDSA_do_verify(hash, SHA256_DIGEST_LENGTH, sig, eckey);
    ECDSA_SIG_free(sig);
    EC_KEY_free(eckey);
    
    if (result != 1) {
        std::cout << "  [验证2/3] ECDSA签名: 无效" << std::endl;
        return false;
    }
    std::cout << "  [验证2/3] ECDSA签名: 有效" << std::endl;
    
    bool vapk_valid = VerifyVAPKEquation(params->group, params->ctx,
                                          vpk, this->apk_root, this->vapk_root, msk);
    if (!vapk_valid) {
        std::cout << "  [验证3/3] vapk等式: 不成立" << std::endl;
        return false;
    }
    std::cout << "  [验证3/3] vapk等式: 成立" << std::endl;
    std::cout << "   注册请求验证通过" << std::endl;
    return true;
}

std::string RegisterRequest::Serialize() const {
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    std::string apk_hex = PointToHex(group, apk_root);
    std::string vapk_hex = PointToHex(group, vapk_root);
    EC_GROUP_free(group);
    
    std::stringstream ss;
    ss << aid << "|" << deri_root << "|" << certificate << "|" 
       << signature << "|" << apk_hex << "|" << vapk_hex;
    return ss.str();
}

bool RegisterRequest::Deserialize(const std::string& data, SystemParams* params) {
    std::vector<std::string> parts;
    std::stringstream ss(data);
    std::string part;
    while (std::getline(ss, part, '|')) parts.push_back(part);
    if (parts.size() < 6) return false;
    
    aid = parts[0];
    deri_root = parts[1];
    certificate = parts[2];
    signature = parts[3];
    
    this->apk_root = EC_POINT_new(params->group);
    this->vapk_root = EC_POINT_new(params->group);
    EC_POINT_hex2point(params->group, parts[4].c_str(), this->apk_root, params->ctx);
    EC_POINT_hex2point(params->group, parts[5].c_str(), this->vapk_root, params->ctx);
    return true;
}

// SignatureOfKnowledge 实现
SignatureOfKnowledge::SignatureOfKnowledge() 
    : Pr1(nullptr), Pr2(nullptr), Ch(nullptr), Rp1(nullptr), Rp2(nullptr) {}

SignatureOfKnowledge::~SignatureOfKnowledge() {
    if (Pr1) EC_POINT_free(Pr1);
    if (Pr2) EC_POINT_free(Pr2);
    if (Ch) BN_free(Ch);
    if (Rp1) BN_free(Rp1);
    if (Rp2) BN_free(Rp2);
}

// PeriodProof 实现
std::string PeriodProof::ToString() const {
    std::stringstream ss;
    ss << h_commit << "|" << valid_until << "|" << rsu_signature;
    return ss.str();
}

// VehicleMessage 实现
VehicleMessage::VehicleMessage() : apk(nullptr), vapk(nullptr) {}

VehicleMessage::~VehicleMessage() {
    if (apk) EC_POINT_free(apk);
    if (vapk) EC_POINT_free(vapk);
}

// EcoRedactSystem 实现
EcoRedactSystem::EcoRedactSystem() : current_params_(nullptr), blockchain_(nullptr) {
    if (!std::filesystem::exists(key_dir_)) {
        std::filesystem::create_directories(key_dir_);
    }
    blockchain_ = new Blockchain();
    blockchain_->LoadFromFile();
}

EcoRedactSystem::~EcoRedactSystem() {
    if (blockchain_) {
        blockchain_->SaveToFile();
        delete blockchain_;
        blockchain_ = nullptr;
    }
    if (current_params_) {
        if (current_params_->ctx) BN_CTX_free(current_params_->ctx);
        if (current_params_->q) BN_free(current_params_->q);
        if (current_params_->group) EC_GROUP_free(current_params_->group);
        current_params_->P = nullptr;
        delete current_params_;
        current_params_ = nullptr;
    }
}

// 辅助函数
std::string EcoRedactSystem::BytesToHexString(const unsigned char* bytes, size_t len) {
    return BytesToHexStringStatic(bytes, len);
}

std::string EcoRedactSystem::ComputeSHA256String(const std::string& input) {
    return ComputeSHA256StringStatic(input);
}

std::string EcoRedactSystem::HMAC_SHA512(const std::string& key, const std::string& data) {
    unsigned char result[64];
    HMAC_CTX* ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key.c_str(), key.length(), EVP_sha512(), nullptr);
    HMAC_Update(ctx, reinterpret_cast<const unsigned char*>(data.c_str()), data.length());
    unsigned int len = 64;
    HMAC_Final(ctx, result, &len);
    HMAC_CTX_free(ctx);
    return BytesToHexString(result, 64);
}

std::vector<uint8_t> EcoRedactSystem::HexToBytes(const std::string& hex) {
    return HexToBytesStatic(hex);
}

void EcoRedactSystem::UpdateManagerRankings(const std::vector<std::pair<std::string, double>>& qualities) {
    for (size_t i = 0; i < qualities.size() && i < all_managers_.size(); i++) {
        for (auto* m : all_managers_) {
            if (m->entity_id == qualities[i].first) {
                m->last_quality = qualities[i].second;
                break;
            }
        }
    }
}

// 机动因子生成
std::string EcoRedactSystem::GenerateMobilityFactor(const std::vector<ManagerStorage*>& managers) {
    std::string F_encrypted;
    
    for (auto* manager : managers) {
        if (!manager->random_x) {
            std::cerr << "错误: 管理员 " << manager->entity_id << " 没有随机数" << std::endl;
            continue;
        }
        
        char* random_hex = BN_bn2hex(manager->random_x);
        std::string random_str(random_hex);
        OPENSSL_free(random_hex);
        
        // random_str 是十六进制字符串，ECIESEncrypt 会将其转换为二进制再加密
        std::string encrypted = ECIESEncrypt(random_str, manager->mpk);
        F_encrypted += encrypted;
    }
    
    return F_encrypted;
}

// 安全的密文更新
std::string EcoRedactSystem::UpdateAllManagersRandomNumbersSafe(
    const std::vector<ManagerStorage*>& managers,
    const std::string& old_txs_hash,
    const std::string& old_F_encrypted,
    const std::string& new_txs_hash) {
    
    size_t num_managers = managers.size();
    if (num_managers == 0) {
        std::cerr << "错误: 管理员列表为空" << std::endl;
        return "";
    }
    
    size_t total_enc_len = old_F_encrypted.length();
    size_t slice_len = total_enc_len / num_managers;
    if (slice_len == 0) {
        std::cerr << "错误: 分片长度为0" << std::endl;
        return "";
    }
    
    std::string old_hash_extended = ExtendHashToLength(old_txs_hash, slice_len);
    std::string new_hash_extended = ExtendHashToLength(new_txs_hash, slice_len);
    
    std::string new_F_encrypted;
    for (size_t i = 0; i < num_managers; i++) {
        std::string old_slice = old_F_encrypted.substr(i * slice_len, slice_len);
        std::string new_slice = XorStringsInternal(old_slice, old_hash_extended);
        new_slice = XorStringsInternal(new_slice, new_hash_extended);
        
        if (new_slice.length() < slice_len) new_slice.resize(slice_len, 0);
        else if (new_slice.length() > slice_len) new_slice = new_slice.substr(0, slice_len);
        
        new_F_encrypted += new_slice;
        
        // 解密获取新的随机数并更新
        std::string new_random = ECIESDecrypt(new_slice, managers[i]->msk);
        if (!new_random.empty() && new_random != "0") {
            BN_free(managers[i]->random_x);
            managers[i]->random_x = BN_new();
            
            if (BN_hex2bn(&managers[i]->random_x, new_random.c_str()) != 0) {
                // 验证更新后的随机数不为零
                if (BN_is_zero(managers[i]->random_x)) {
                    std::cerr << "  警告: 管理员 " << managers[i]->entity_id << " 随机数无效，重新生成" << std::endl;
                    BN_rand_range(managers[i]->random_x, current_params_->q);
                    while (BN_is_zero(managers[i]->random_x)) {
                        BN_rand_range(managers[i]->random_x, current_params_->q);
                    }
                }
                managers[i]->SaveToFile(key_dir_);
            } else {
                std::cerr << "  警告: 管理员 " << managers[i]->entity_id << " BN_hex2bn 失败" << std::endl;
            }
        } else {
            std::cerr << "  警告: 管理员 " << managers[i]->entity_id << " 解密失败" << std::endl;
        }
    }
    
    std::string old_hash_verify = ExtendHashToLength(old_txs_hash, old_F_encrypted.length());
    std::string new_hash_verify = ExtendHashToLength(new_txs_hash, new_F_encrypted.length());
    
    std::string old_xor = XorStringsInternal(old_hash_verify, old_F_encrypted);
    std::string new_xor = XorStringsInternal(new_hash_verify, new_F_encrypted);
    
    if (ComputeSHA256String(old_xor) != ComputeSHA256String(new_xor)) {
        std::cerr << "错误: 核心不变性验证失败!" << std::endl;
        return "";
    }
    
    std::cout << "正确：核心不变性验证通过！" << std::endl;
    return new_F_encrypted;
}

// 阶段一: 系统初始化
SystemParams* EcoRedactSystem::Setup(int curve_nid) {
    // 初始化 OpenSSL 随机数生成器
    unsigned char seed[32];
    RAND_bytes(seed, sizeof(seed));
    RAND_seed(seed, sizeof(seed));

    std::cout << "\n========================================" << std::endl;
    std::cout << "  Setup - 初始化系统参数" << std::endl;
    std::cout << "========================================" << std::endl;
    
    current_params_ = new SystemParams();
    current_params_->ctx = BN_CTX_new();
    current_params_->group = EC_GROUP_new_by_curve_name(curve_nid);
    current_params_->P = EC_POINT_new(current_params_->group);
    EC_POINT_copy(current_params_->P, EC_GROUP_get0_generator(current_params_->group));
    current_params_->q = BN_new();
    EC_GROUP_get_order(current_params_->group, current_params_->q, current_params_->ctx);
    
    std::cout << "  曲线: secp256k1, 阶位数: " << BN_num_bits(current_params_->q) << std::endl;
    return current_params_;
}

// 实体创建
VehicleStorage* EcoRedactSystem::CreateVehicle(const std::string& vehicle_id) {
    std::cout << "  创建车辆: " << vehicle_id << std::endl;
    VehicleStorage* v = new VehicleStorage();
    v->entity_id = vehicle_id;
    v->vsk = BN_new();
    do { BN_rand_range(v->vsk, current_params_->q); } while (BN_is_zero(v->vsk));
    v->vpk = EC_POINT_new(current_params_->group);
    EC_POINT_mul(current_params_->group, v->vpk, v->vsk, nullptr, nullptr, current_params_->ctx);
    
    std::string pk_hex = PointToHex(current_params_->group, v->vpk);
    auto ts = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    v->certificate = vehicle_id + "|" + pk_hex + "|" + std::to_string(ts) + "|CA_SIG";
    v->SaveToFile(key_dir_);
    return v;
}

ManagerStorage* EcoRedactSystem::CreateManager(const std::string& manager_id, int committed_space) {
    std::cout << "  创建管理员: " << manager_id << ", 空间: " << committed_space << " MB" << std::endl;
    
    ManagerStorage* m = new ManagerStorage();
    m->entity_id = manager_id;
    m->committed_space = committed_space;
    
    // 生成管理员私钥
    m->msk = BN_new();
    do { 
        BN_rand_range(m->msk, current_params_->q); 
    } while (BN_is_zero(m->msk));
    
    m->mpk = EC_POINT_new(current_params_->group);
    EC_POINT_mul(current_params_->group, m->mpk, m->msk, nullptr, nullptr, current_params_->ctx);
    
    // 生成专属随机数 x_i
    m->random_x = BN_new();
    do {
        BN_rand_range(m->random_x, current_params_->q);
    } while (BN_is_zero(m->random_x));
    
    // 调试输出
    char* random_hex = BN_bn2hex(m->random_x);
    //std::cout << "    生成随机数: " << random_hex << std::endl;
    OPENSSL_free(random_hex);
    
    bool saved = m->SaveToFile(key_dir_);
    if (!saved) {
        std::cerr << "  警告: 保存管理员 " << manager_id << " 到文件失败" << std::endl;
    } else {
        //std::cout << "    已保存到文件" << std::endl;
    }
    
    all_managers_.push_back(m);
    return m;
}

RSUStorage* EcoRedactSystem::CreateRSU(const std::string& rsu_id) {
    std::cout << "  创建 RSU: " << rsu_id << std::endl;
    RSUStorage* r = new RSUStorage();
    r->entity_id = rsu_id;
    r->rsk = BN_new();
    do { BN_rand_range(r->rsk, current_params_->q); } while (BN_is_zero(r->rsk));
    r->rpk = EC_POINT_new(current_params_->group);
    EC_POINT_mul(current_params_->group, r->rpk, r->rsk, nullptr, nullptr, current_params_->ctx);
    r->SaveToFile(key_dir_);
    return r;
}

VehicleStorage* EcoRedactSystem::LoadVehicle(const std::string& vehicle_id) {
    VehicleStorage* v = new VehicleStorage();
    if (v->LoadFromFile(key_dir_, vehicle_id)) return v;
    delete v;
    return nullptr;
}

ManagerStorage* EcoRedactSystem::LoadManager(const std::string& manager_id) {
    ManagerStorage* m = new ManagerStorage();
    if (m->LoadFromFile(key_dir_, manager_id)) return m;
    delete m;
    return nullptr;
}

RSUStorage* EcoRedactSystem::LoadRSU(const std::string& rsu_id) {
    RSUStorage* r = new RSUStorage();
    if (r->LoadFromFile(key_dir_, rsu_id)) return r;
    delete r;
    return nullptr;
}

// 阶段二: 空间证明竞争
std::pair<ManagerStorage*, std::vector<std::pair<std::string, double>>> 
EcoRedactSystem::PoSpaceRacing(std::vector<ManagerStorage*>& managers) {
    std::cout << "\n========================================" << std::endl;
    std::cout << "  PoSpaceRacing - 空间证明竞争" << std::endl;
    std::cout << "========================================" << std::endl;

    std::vector<std::pair<std::string, double>> qualities;
    ManagerStorage* winner = nullptr;
    int max_space = 0;
    
    for (auto* m : managers) {
        double quality = static_cast<double>(m->committed_space) / 100.0;
        if (quality > 1.0) quality = 1.0;
        m->last_quality = quality;
        qualities.push_back({m->entity_id, quality});
        std::cout << "  管理员 " << m->entity_id << ": 空间 = " << m->committed_space << " MB " << std::endl;
        if (m->committed_space > max_space) {
            max_space = m->committed_space;
            winner = m;
        }
    }
    
    std::sort(qualities.begin(), qualities.end(),
              [](const std::pair<std::string, double>& a, const std::pair<std::string, double>& b) {
                  return a.second > b.second;
              });
    
    std::cout << "\n  获胜管理员: " << winner->entity_id 
              << " (空间: " << winner->committed_space << " MB " << ")" << std::endl;
    return {winner, qualities};
}

void EcoRedactSystem::GenerateRootKey(SystemParams* params, VehicleStorage* vehicle, EC_POINT* mpk) {
    std::string key = "VehicleAnonymousKey_" + vehicle->entity_id;
    unsigned char seed[32];
    RAND_bytes(seed, sizeof(seed));
    std::string pseed = BytesToHexStringStatic(seed, sizeof(seed));
    std::string hmac_result = HMAC_SHA512(key, pseed);
    
    std::string I_L_hex = hmac_result.substr(0, 64);
    std::string I_R_hex = hmac_result.substr(64, 64);
    
    vehicle->ask_root = BN_new();
    BN_hex2bn(&vehicle->ask_root, I_L_hex.c_str());
    BN_mod(vehicle->ask_root, vehicle->ask_root, params->q, params->ctx);
    
    BIGNUM* I_R = BN_new();
    BN_hex2bn(&I_R, I_R_hex.c_str());
    BN_mod(I_R, I_R, params->q, params->ctx);
    char* I_R_hex_mod = BN_bn2hex(I_R);
    vehicle->deri_root = I_R_hex_mod;
    OPENSSL_free(I_R_hex_mod);
    BN_free(I_R);
    
    vehicle->apk_root = EC_POINT_new(params->group);
    EC_POINT_mul(params->group, vehicle->apk_root, vehicle->ask_root, nullptr, nullptr, params->ctx);
    vehicle->vapk_root = ComputeVAPK(params, vehicle->vpk, vehicle->ask_root, mpk);
    
    std::string apk_hex = PointToHex(params->group, vehicle->apk_root);
    std::string aid_input = apk_hex + key;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(aid_input.c_str()), aid_input.length(), hash);
    vehicle->aid = BytesToHexString(hash, SHA256_DIGEST_LENGTH).substr(0, 32);
}

RegisterRequest EcoRedactSystem::BuildRegisterRequest(SystemParams* params, VehicleStorage* vehicle,
                                                       EC_POINT* mpk, const std::string& manager_id) {
    RegisterRequest req;
    req.BuildRequest(params, vehicle->apk_root, vehicle->vapk_root,
                     vehicle->deri_root, vehicle->certificate,
                     vehicle->vsk, vehicle->aid);
    return req;
}

std::string EcoRedactSystem::ExtendHashToLength(const std::string& hash, size_t target_len) {
    if (hash.length() >= target_len) return hash.substr(0, target_len);
    std::string result;
    while (result.length() < target_len) result += hash;
    return result.substr(0, target_len);
}

bool EcoRedactSystem::ProcessRegisterRequest(SystemParams* params, const RegisterRequest& req,
                                               ManagerStorage* manager) {
    std::cout << "\n  管理员 " << manager->entity_id << " 处理注册请求" << std::endl;
    
    size_t first_pipe = req.certificate.find('|');
    size_t second_pipe = req.certificate.find('|', first_pipe + 1);
    if (first_pipe == std::string::npos || second_pipe == std::string::npos) {
        std::cout << "  证书格式错误" << std::endl;
        return false;
    }
    
    std::string pk_hex = req.certificate.substr(first_pipe + 1, second_pipe - first_pipe - 1);
    EC_POINT* vpk = EC_POINT_new(params->group);
    EC_POINT_hex2point(params->group, pk_hex.c_str(), vpk, params->ctx);
    
    if (!req.Verify(params, vpk, manager->msk)) {
        std::cout << "  注册请求验证失败" << std::endl;
        EC_POINT_free(vpk);
        return false;
    }
    
    std::cout << "  注册请求验证通过" << std::endl;
    
    TransactionSubBlock tx;
    tx.tx_id = "TX_" + req.aid.substr(0, 16);
    tx.aid = req.aid;
    tx.root_apk = PointToHex(params->group, req.apk_root);
    tx.register_time = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    int new_height = blockchain_->GetLatestHeight() + 1;
    Block* prev_block = blockchain_->GetBlock(new_height - 1);
    std::vector<ManagerStorage*> all_managers = all_managers_;
    
    Block new_block;
    new_block.height = new_height;
    new_block.timestamp = tx.register_time;
    new_block.transactions.push_back(tx);
    
    new_block.proof.index = new_height;
    new_block.proof.signature_on_prev = prev_block ? prev_block->proof.ComputeHash() : "GENESIS";
    new_block.proof.manager_id = manager->entity_id;
    new_block.proof.merkle_root = ComputeSHA256String("MERKLE_" + req.aid.substr(0, 16));
    new_block.proof.proof_challenge = "CHALLENGE_" + req.aid.substr(0, 16);
    new_block.proof.quality = manager->last_quality;
    new_block.proof.timestamp = new_block.timestamp;
    
    std::string F_encrypted = GenerateMobilityFactor(all_managers);
    std::string txs_hash = new_block.ComputeTransactionsHash();
    std::string extended_hash = ExtendHashToLength(txs_hash, F_encrypted.length());
    std::string xor_value = XorStringsInternal(extended_hash, F_encrypted);
    std::string xor_signature = ComputeSHA256String(xor_value);
    
    new_block.signature.index = new_height;
    new_block.signature.manager_id = manager->entity_id;
    new_block.signature.xor_signature = xor_signature;
    new_block.signature.signature_on_prev = prev_block ? prev_block->signature.ComputeHash() : "GENESIS";
    new_block.signature.public_key = PointToHex(params->group, manager->mpk);
    new_block.proof_hash = new_block.ComputeProofHash();
    
    bool success = blockchain_->AddBlock(new_block);
    if (success) {
        std::cout << "  注册成功, AID: " << req.aid.substr(0, 32) << "..." << std::endl;
    } else {
        std::cout << "  区块添加失败" << std::endl;
    }
    
    EC_POINT_free(vpk);
    return success;
}

// 阶段三: 匿名通信
EC_POINT* EcoRedactSystem::GetRootAPKByAID(const std::string& aid) {
    TransactionSubBlock* tx = blockchain_->FindTransactionByAID(aid);
    if (!tx) return nullptr;
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    EC_POINT* apk = EC_POINT_new(group);
    EC_POINT_hex2point(group, tx->root_apk.c_str(), apk, nullptr);
    EC_GROUP_free(group);
    return apk;
}

EC_POINT* EcoRedactSystem::ComputeVAPK(SystemParams* params, EC_POINT* vpk, BIGNUM* ask, EC_POINT* mpk) {
    EC_POINT* temp = EC_POINT_new(params->group);
    EC_POINT* vapk = EC_POINT_new(params->group);
    EC_POINT_mul(params->group, temp, nullptr, mpk, ask, params->ctx);
    EC_POINT_add(params->group, vapk, vpk, temp, params->ctx);
    EC_POINT_free(temp);
    return vapk;
}

std::tuple<BIGNUM*, EC_POINT*, EC_POINT*, std::string> 
EcoRedactSystem::DeriveKey(SystemParams* params, BIGNUM* prev_ask, const std::string& prev_deri,
                            EC_POINT* prev_apk, int k, EC_POINT* vpk, EC_POINT* mpk) {
    BIGNUM* apk_x = BN_new();
    BIGNUM* apk_y = BN_new();
    EC_POINT_get_affine_coordinates(params->group, prev_apk, apk_x, apk_y, params->ctx);
    char* apk_x_hex = BN_bn2hex(apk_x);
    char* apk_y_hex = BN_bn2hex(apk_y);
    std::string apk_data = std::string(apk_x_hex) + "|" + std::string(apk_y_hex) + "|" + std::to_string(k);
    OPENSSL_free(apk_x_hex);
    OPENSSL_free(apk_y_hex);
    
    std::string hmac_result = HMAC_SHA512(prev_deri, apk_data);
    std::string I_L_hex = hmac_result.substr(0, 64);
    std::string I_R_hex = hmac_result.substr(64, 64);
    
    BIGNUM* I_L = BN_new();
    BN_hex2bn(&I_L, I_L_hex.c_str());
    BIGNUM* ask_new = BN_new();
    BN_mod_mul(ask_new, prev_ask, I_L, params->q, params->ctx);
    
    BIGNUM* I_R = BN_new();
    BN_hex2bn(&I_R, I_R_hex.c_str());
    BN_mod(I_R, I_R, params->q, params->ctx);
    char* I_R_hex_mod = BN_bn2hex(I_R);
    std::string deri_new = I_R_hex_mod;
    OPENSSL_free(I_R_hex_mod);
    
    EC_POINT* apk_new = EC_POINT_new(params->group);
    EC_POINT_mul(params->group, apk_new, ask_new, nullptr, nullptr, params->ctx);
    EC_POINT* vapk_new = ComputeVAPK(params, vpk, ask_new, mpk);
    
    BN_free(I_L);
    BN_free(I_R);
    BN_free(apk_x);
    BN_free(apk_y);
    return {ask_new, apk_new, vapk_new, deri_new};
}

std::tuple<BIGNUM*, EC_POINT*, EC_POINT*, std::string> 
EcoRedactSystem::DeriveKeyFromRoot(SystemParams* params, VehicleStorage* vehicle, int k, EC_POINT* mpk) {
    BIGNUM* current_ask = BN_new();
    BN_copy(current_ask, vehicle->ask_root);
    std::string current_deri = vehicle->deri_root;
    EC_POINT* current_apk = EC_POINT_new(params->group);
    EC_POINT_copy(current_apk, vehicle->apk_root);
    
    BIGNUM* final_ask = nullptr;
    EC_POINT* final_apk = nullptr;
    EC_POINT* final_vapk = nullptr;
    std::string final_deri;
    
    for (int i = 1; i <= k; i++) {
        auto [new_ask, new_apk, new_vapk, new_deri] = DeriveKey(
            params, current_ask, current_deri, current_apk, i, vehicle->vpk, mpk);
        BN_free(current_ask);
        EC_POINT_free(current_apk);
        current_ask = new_ask;
        current_apk = new_apk;
        current_deri = new_deri;
        if (i == k) {
            final_ask = new_ask;
            final_apk = new_apk;
            final_vapk = new_vapk;
            final_deri = new_deri;
        } else if (new_vapk) {
            EC_POINT_free(new_vapk);
        }
    }
    return {final_ask, final_apk, final_vapk, final_deri};
}

PeriodProof EcoRedactSystem::PeriodProofGen(RSUStorage* rsu, const std::string& aid,
                                             EC_POINT* apk, int key_index, int duration) {
    PeriodProof proof;
    std::string apk_hex = PointToHex(current_params_->group, apk);
    std::string commit_data = apk_hex + "|" + std::to_string(key_index) + "|" + aid;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(commit_data.c_str()), commit_data.length(), hash);
    proof.h_commit = BytesToHexStringStatic(hash, SHA256_DIGEST_LENGTH);
    
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    proof.valid_until = now + duration;
    
    std::string sign_data = std::to_string(proof.valid_until) + "|" + proof.h_commit;
    SHA256(reinterpret_cast<const unsigned char*>(sign_data.c_str()), sign_data.length(), hash);
    
    EC_KEY* eckey = EC_KEY_new();
    if (!eckey) return proof;
    EC_KEY_set_group(eckey, current_params_->group);
    EC_KEY_set_private_key(eckey, rsu->rsk);
    ECDSA_SIG* sig = ECDSA_do_sign(hash, SHA256_DIGEST_LENGTH, eckey);
    
    if (sig) {
        unsigned char* der = nullptr;
        int der_len = i2d_ECDSA_SIG(sig, &der);
        if (der_len > 0 && der) {
            proof.rsu_signature = BytesToHexStringStatic(der, der_len);
            OPENSSL_free(der);
        }
        ECDSA_SIG_free(sig);
    }
    EC_KEY_free(eckey);
    return proof;
}

bool EcoRedactSystem::PeriodProofVerify(const PeriodProof& proof, EC_POINT* rsu_pk) {
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    if (static_cast<uint64_t>(now) > proof.valid_until) {
        std::cout << "  周期证明已过期" << std::endl;
        return false;
    }
    
    std::string sign_data = std::to_string(proof.valid_until) + "|" + proof.h_commit;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(sign_data.c_str()), sign_data.length(), hash);
    
    EC_KEY* eckey = EC_KEY_new();
    if (!eckey) return false;
    EC_KEY_set_group(eckey, current_params_->group);
    EC_KEY_set_public_key(eckey, rsu_pk);
    
    std::vector<unsigned char> der_bytes = HexToBytes(proof.rsu_signature);
    if (der_bytes.empty()) {
        EC_KEY_free(eckey);
        return false;
    }
    const unsigned char* der_ptr = der_bytes.data();
    ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &der_ptr, der_bytes.size());
    if (!sig) {
        EC_KEY_free(eckey);
        return false;
    }
    int result = ECDSA_do_verify(hash, SHA256_DIGEST_LENGTH, sig, eckey);
    ECDSA_SIG_free(sig);
    EC_KEY_free(eckey);
    return (result == 1);
}

SignatureOfKnowledge EcoRedactSystem::SoKGen(SystemParams* params, const std::string& msg,
                                              BIGNUM* ask, BIGNUM* vsk, EC_POINT* apk,
                                              EC_POINT* vpk, EC_POINT* mpk, 
                                              const PeriodProof& proof) {
    SignatureOfKnowledge sig;
    sig.Pr1 = EC_POINT_new(params->group);
    sig.Pr2 = EC_POINT_new(params->group);
    sig.Ch = BN_new();
    sig.Rp1 = BN_new();
    sig.Rp2 = BN_new();
    
    BIGNUM* r1 = BN_new();
    BIGNUM* r2 = BN_new();
    BN_rand_range(r1, params->q);
    BN_rand_range(r2, params->q);
    while (BN_is_zero(r1)) BN_rand_range(r1, params->q);
    while (BN_is_zero(r2)) BN_rand_range(r2, params->q);
    
    EC_POINT_mul(params->group, sig.Pr1, r1, nullptr, nullptr, params->ctx);
    
    EC_POINT* r2P = EC_POINT_new(params->group);
    EC_POINT_mul(params->group, r2P, r2, nullptr, nullptr, params->ctx);
    EC_POINT* r1Mpk = EC_POINT_new(params->group);
    EC_POINT_mul(params->group, r1Mpk, nullptr, mpk, r1, params->ctx);
    EC_POINT_add(params->group, sig.Pr2, r2P, r1Mpk, params->ctx);
    
    EC_POINT* vapk = ComputeVAPK(params, vpk, ask, mpk);
    
    std::string Pr1_hex = PointToHex(params->group, sig.Pr1);
    std::string Pr2_hex = PointToHex(params->group, sig.Pr2);
    std::string P_hex = PointToHex(params->group, params->P);
    std::string apk_hex = PointToHex(params->group, apk);
    std::string vapk_hex = PointToHex(params->group, vapk);
    std::string mpk_hex = PointToHex(params->group, mpk);
    std::string proof_str = proof.ToString();
    
    sig.timestamp = std::to_string(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    
    std::string challenge_data = msg + "|" + Pr1_hex + "|" + Pr2_hex + "|" + P_hex + "|" +
                                  apk_hex + "|" + vapk_hex + "|" + mpk_hex + "|" +
                                  sig.timestamp + "|" + proof_str;
    
    unsigned char challenge_hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(challenge_data.c_str()), 
           challenge_data.length(), challenge_hash);
    BN_hex2bn(&sig.Ch, BytesToHexStringStatic(challenge_hash, SHA256_DIGEST_LENGTH).c_str());
    BN_mod(sig.Ch, sig.Ch, params->q, params->ctx);
    
    BIGNUM* ask_Ch = BN_new();
    BN_mod_mul(ask_Ch, ask, sig.Ch, params->q, params->ctx);
    BN_mod_sub(sig.Rp1, r1, ask_Ch, params->q, params->ctx);
    
    BIGNUM* vsk_Ch = BN_new();
    BN_mod_mul(vsk_Ch, vsk, sig.Ch, params->q, params->ctx);
    BN_mod_sub(sig.Rp2, r2, vsk_Ch, params->q, params->ctx);
    
    BN_free(r1);
    BN_free(r2);
    BN_free(ask_Ch);
    BN_free(vsk_Ch);
    EC_POINT_free(r2P);
    EC_POINT_free(r1Mpk);
    EC_POINT_free(vapk);
    return sig;
}

bool EcoRedactSystem::SoKVerify(SystemParams* params, const std::string& msg,
                                 const SignatureOfKnowledge& sig, EC_POINT* apk,
                                 EC_POINT* vapk, EC_POINT* mpk, 
                                 const PeriodProof& proof, EC_POINT* rsu_pk) {
    long long now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    long long ts = std::stoll(sig.timestamp);
    
    if (std::abs(now - ts) > 60) {
        std::cout << "  时间戳超出允许范围" << std::endl;
        return false;
    }
    if (static_cast<uint64_t>(ts) > proof.valid_until) {
        std::cout << "  时间戳超过周期证明有效期" << std::endl;
        return false;
    }
    std::cout << "  时间戳有效" << std::endl;
    
    std::string sign_data = std::to_string(proof.valid_until) + "|" + proof.h_commit;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(sign_data.c_str()), sign_data.length(), hash);
    
    EC_KEY* eckey = EC_KEY_new();
    EC_KEY_set_group(eckey, params->group);
    EC_KEY_set_public_key(eckey, rsu_pk);
    std::vector<unsigned char> der_bytes = HexToBytes(proof.rsu_signature);
    if (der_bytes.empty()) {
        EC_KEY_free(eckey);
        return false;
    }
    const unsigned char* der_ptr = der_bytes.data();
    ECDSA_SIG* rsu_sig = d2i_ECDSA_SIG(nullptr, &der_ptr, der_bytes.size());
    if (!rsu_sig) {
        EC_KEY_free(eckey);
        return false;
    }
    int verify_result = ECDSA_do_verify(hash, SHA256_DIGEST_LENGTH, rsu_sig, eckey);
    ECDSA_SIG_free(rsu_sig);
    EC_KEY_free(eckey);
    if (verify_result != 1) {
        std::cout << "  周期证明RSU签名无效" << std::endl;
        return false;
    }
    std::cout << "  周期证明有效" << std::endl;
    
    std::string Pr1_hex = PointToHex(params->group, sig.Pr1);
    std::string Pr2_hex = PointToHex(params->group, sig.Pr2);
    std::string P_hex = PointToHex(params->group, params->P);
    std::string apk_hex = PointToHex(params->group, apk);
    std::string vapk_hex = PointToHex(params->group, vapk);
    std::string mpk_hex = PointToHex(params->group, mpk);
    std::string proof_str = proof.ToString();
    
    std::string challenge_data = msg + "|" + Pr1_hex + "|" + Pr2_hex + "|" + P_hex + "|" +
                                  apk_hex + "|" + vapk_hex + "|" + mpk_hex + "|" +
                                  sig.timestamp + "|" + proof_str;
    
    unsigned char challenge_hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(challenge_data.c_str()), 
           challenge_data.length(), challenge_hash);
    
    BIGNUM* expected_ch = BN_new();
    BN_hex2bn(&expected_ch, BytesToHexStringStatic(challenge_hash, SHA256_DIGEST_LENGTH).c_str());
    BN_mod(expected_ch, expected_ch, params->q, params->ctx);
    
    if (BN_cmp(sig.Ch, expected_ch) != 0) {
        BN_free(expected_ch);
        std::cout << "  挑战值不匹配" << std::endl;
        return false;
    }
    BN_free(expected_ch);
    std::cout << "  挑战值匹配" << std::endl;
    
    BIGNUM* rp1_plus_rp2 = BN_new();
    BN_add(rp1_plus_rp2, sig.Rp1, sig.Rp2);
    BN_mod(rp1_plus_rp2, rp1_plus_rp2, params->q, params->ctx);
    
    EC_POINT* left = EC_POINT_new(params->group);
    EC_POINT_add(params->group, left, sig.Pr1, sig.Pr2, params->ctx);
    
    EC_POINT* right = EC_POINT_new(params->group);
    EC_POINT* term1 = EC_POINT_new(params->group);
    EC_POINT_mul(params->group, term1, rp1_plus_rp2, nullptr, nullptr, params->ctx);
    EC_POINT* term2 = EC_POINT_new(params->group);
    EC_POINT_mul(params->group, term2, nullptr, mpk, sig.Rp1, params->ctx);
    EC_POINT* apk_plus_vapk = EC_POINT_new(params->group);
    EC_POINT_add(params->group, apk_plus_vapk, apk, vapk, params->ctx);
    EC_POINT* term3 = EC_POINT_new(params->group);
    EC_POINT_mul(params->group, term3, nullptr, apk_plus_vapk, sig.Ch, params->ctx);
    
    EC_POINT_add(params->group, right, term1, term2, params->ctx);
    EC_POINT_add(params->group, right, right, term3, params->ctx);
    
    bool eq_valid = (EC_POINT_cmp(params->group, left, right, params->ctx) == 0);
    
    BN_free(rp1_plus_rp2);
    EC_POINT_free(left);
    EC_POINT_free(right);
    EC_POINT_free(term1);
    EC_POINT_free(term2);
    EC_POINT_free(term3);
    EC_POINT_free(apk_plus_vapk);
    
    if (!eq_valid) {
        std::cout << "  知识签名等式验证失败" << std::endl;
        return false;
    }
    std::cout << "  知识签名等式验证通过" << std::endl;
    return true;
}

VehicleMessage EcoRedactSystem::SendMessage(SystemParams* params, const std::string& msg,
                                             const std::string& aid,
                                             EC_POINT* apk, EC_POINT* vapk,
                                             const SignatureOfKnowledge& sig,
                                             const PeriodProof& proof) {
    VehicleMessage vm;
    vm.msg = msg;
    vm.aid = aid;
    vm.timestamp = sig.timestamp;
    vm.signature = sig;
    vm.period_proof = proof;
    vm.apk = EC_POINT_new(params->group);
    vm.vapk = EC_POINT_new(params->group);
    EC_POINT_copy(vm.apk, apk);
    EC_POINT_copy(vm.vapk, vapk);
    return vm;
}

bool EcoRedactSystem::ReceiveAndVerify(SystemParams* params, const VehicleMessage& msg,
                                        EC_POINT* mpk, EC_POINT* rsu_pk) {
    std::cout << "\n========================================" << std::endl;
    std::cout << "  ReceiveAndVerify - 接收并验证消息" << std::endl;
    std::cout << "========================================" << std::endl;
    
    bool sig_valid = SoKVerify(params, msg.msg, msg.signature, 
                                msg.apk, msg.vapk, mpk, 
                                msg.period_proof, rsu_pk);
    if (!sig_valid) {
        std::cout << "  消息拒绝: 知识签名无效" << std::endl;
        return false;
    }
    std::cout << "  消息接受: 所有验证通过" << std::endl;
    return true;
}

bool EcoRedactSystem::TraceVerify(const std::string& aid, EC_POINT* vpk, BIGNUM* msk) {
    TransactionSubBlock* tx = blockchain_->FindTransactionByAID(aid);
    if (!tx) {
        std::cout << "  追溯失败: AID不存在或已被撤销" << std::endl;
        return false;
    }
    std::cout << "  AID存在，注册时间: " << tx->register_time << std::endl;
    
    EC_POINT* apk_root = EC_POINT_new(current_params_->group);
    if (EC_POINT_hex2point(current_params_->group, tx->root_apk.c_str(), 
                            apk_root, current_params_->ctx) == nullptr) {
        std::cout << "  追溯失败: 无法解析根匿名公钥" << std::endl;
        EC_POINT_free(apk_root);
        return false;
    }
    
    EC_POINT* msk_apk = EC_POINT_new(current_params_->group);
    EC_POINT_mul(current_params_->group, msk_apk, nullptr, apk_root, msk, current_params_->ctx);
    
    EC_POINT* computed_vapk = EC_POINT_new(current_params_->group);
    EC_POINT_add(current_params_->group, computed_vapk, vpk, msk_apk, current_params_->ctx);
    
    std::string computed_vapk_hex = PointToHex(current_params_->group, computed_vapk);
    
    EC_POINT_free(apk_root);
    EC_POINT_free(msk_apk);
    EC_POINT_free(computed_vapk);
    return true;
}

// 阶段四: 匿名公钥撤销
bool EcoRedactSystem::AnonKeyRevoke(const std::string& aid, const std::string& reason,
                                     const std::vector<ManagerStorage*>& managers) {
    std::cout << "\n========================================" << std::endl;
    std::cout << "  AnonKeyRevoke - 物理撤销" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "  撤销原因: " << reason << std::endl;
    
    int target_height = -1;
    const auto& chain = blockchain_->GetChain();
    for (size_t i = 0; i < chain.size(); i++) {
        if (chain[i].FindTransactionIndex(aid) != -1) {
            target_height = static_cast<int>(i);
            break;
        }
    }
    
    if (target_height == -1) {
        std::cout << "  撤销失败: 无法找到包含该AID的区块" << std::endl;
        return false;
    }
    
    Block* target_block = blockchain_->GetBlock(target_height);
    if (!target_block) return false;
    std::cout << "  目标区块高度: " << target_height << std::endl;
    
    std::vector<ManagerStorage*> all_managers = all_managers_;
    if (all_managers.empty()) all_managers = managers;
    
    // 计算旧交易哈希
    std::string old_txs_hash = target_block->ComputeTransactionsHash();
    
    // 生成当前机动因子 F
    std::string old_F = GenerateMobilityFactor(all_managers);
    
    // 验证当前 F 是否正确
    std::string extended_old_hash = ExtendHashToLength(old_txs_hash, old_F.length());
    std::string computed_xor = XorStringsInternal(extended_old_hash, old_F);
    std::string computed_sig = ComputeSHA256String(computed_xor);
    std::string stored_sig = target_block->signature.xor_signature;
    //std::cout << "  区块存储的签名: " << stored_sig << std::endl;
    //std::cout << "  当前计算的签名: " << computed_sig << std::endl;
    
    if (computed_sig != stored_sig) {
        std::cout << "  错误: 当前管理员的随机数与区块生成时不匹配！" << std::endl;
        return false;
    }
    
    // 创建新交易列表
    std::vector<TransactionSubBlock> new_transactions;
    for (const auto& tx : target_block->transactions) {
        if (tx.aid != aid) new_transactions.push_back(tx);
    }
    
    // 计算新交易哈希
    std::string new_txs_hash;
    if (new_transactions.empty()) {
        new_txs_hash = ComputeSHA256String("EMPTY");
    } else {
        std::string combined;
        for (const auto& tx : new_transactions) combined += tx.ComputeHash();
        new_txs_hash = ComputeSHA256String(combined);
    }
    
    std::string new_F = XorStringsInternal(old_F, extended_old_hash);
    new_F = XorStringsInternal(new_F, ExtendHashToLength(new_txs_hash, old_F.length()));
    
    // 验证核心不变性
    std::string new_extended_hash = ExtendHashToLength(new_txs_hash, new_F.length());
    std::string new_xor = XorStringsInternal(new_extended_hash, new_F);
    std::string new_sig = ComputeSHA256String(new_xor);
    
    //std::cout << "  新计算的签名: " << new_sig << std::endl;
    
    if (computed_sig != new_sig) {
        std::cerr << "错误: 核心不变性验证失败!" << std::endl;
        return false;
    }
    
    std::cout << "正确：核心不变性成立" << std::endl;
    
    // 更新每个管理员的随机数
    size_t num_managers = all_managers.size();
    size_t slice_len = new_F.length() / num_managers;
    std::string extended_old_hash_slice = ExtendHashToLength(old_txs_hash, slice_len);
    std::string extended_new_hash_slice = ExtendHashToLength(new_txs_hash, slice_len);
    
    for (size_t i = 0; i < num_managers; i++) {
        std::string new_slice = new_F.substr(i * slice_len, slice_len);
        
        // 解密得到新的随机数
        std::string new_random = ECIESDecrypt(new_slice, all_managers[i]->msk);
        if (!new_random.empty() && new_random != "0") {
            BN_free(all_managers[i]->random_x);
            all_managers[i]->random_x = BN_new();
            BN_hex2bn(&all_managers[i]->random_x, new_random.c_str());
            all_managers[i]->SaveToFile(key_dir_);
            std::cout << "  管理员 " << all_managers[i]->entity_id << " 随机数已更新" << std::endl;
        } else {
            // 如果解密失败，使用异或计算新随机数
            std::string old_slice = old_F.substr(i * slice_len, slice_len);
            std::string old_random = ECIESDecrypt(old_slice, all_managers[i]->msk);
            if (!old_random.empty()) {
                BIGNUM* old_bn = BN_new();
                BIGNUM* old_hash_bn = BN_new();
                BIGNUM* new_hash_bn = BN_new();
                BN_hex2bn(&old_bn, old_random.c_str());
                BN_hex2bn(&old_hash_bn, extended_old_hash_slice.c_str());
                BN_hex2bn(&new_hash_bn, extended_new_hash_slice.c_str());
                
                BIGNUM* new_bn = BN_new();
                BN_mod_add(new_bn, old_bn, old_hash_bn, current_params_->q, current_params_->ctx);
                BN_mod_sub(new_bn, new_bn, new_hash_bn, current_params_->q, current_params_->ctx);
                
                char* new_hex = BN_bn2hex(new_bn);
                BN_free(all_managers[i]->random_x);
                all_managers[i]->random_x = new_bn;
                all_managers[i]->SaveToFile(key_dir_);
                OPENSSL_free(new_hex);
                BN_free(old_bn);
                BN_free(old_hash_bn);
                BN_free(new_hash_bn);
                std::cout << "  管理员 " << all_managers[i]->entity_id << " 随机数已通过计算更新" << std::endl;
            }
        }
    }
    
    bool success = blockchain_->PhysicalRevokeTransaction(aid, new_sig);
    if (success) {
        revoke_history_.push_back({aid, reason});
        std::cout << "\n  物理撤销成功!" << std::endl;
    } else {
        std::cout << "\n  物理撤销失败" << std::endl;
    }
    
    return success;
}

bool EcoRedactSystem::IsAIDRevoked(const std::string& aid) {
    return blockchain_->FindTransactionByAID(aid) == nullptr;
}

std::vector<std::pair<std::string, std::string>> EcoRedactSystem::GetRevokeHistory() {
    return revoke_history_;
}

std::vector<ModificationRecord> EcoRedactSystem::GetModificationHistory() {
    return blockchain_->GetModificationHistory();
}

std::vector<uint8_t> EcoRedactSystem::ComputeSHA256(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), hash.data());
    return hash;
}

} // namespace EcoRedact
