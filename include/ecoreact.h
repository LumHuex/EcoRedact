#ifndef ECOREDACT_H
#define ECOREDACT_H

#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ecdh.h>
#include <string>
#include <vector>
#include <cstdint>
#include <utility>
#include <memory>
#include <tuple>
#include "blockchain.h"

namespace EcoRedact {

// 前向声明
class Blockchain;
struct TransactionSubBlock;
struct Block;
struct ModificationRecord;

// 实体类型枚举
enum class EntityType {
    VEHICLE,
    MANAGER,
    RSU
};

// 阶段一: 系统初始化相关结构
struct SystemParams {
    EC_GROUP* group;
    EC_POINT* P;
    BIGNUM* q;
    BN_CTX* ctx;
    
    SystemParams();
    ~SystemParams();
};

// 车辆存储结构
struct VehicleStorage {
    std::string entity_id;
    BIGNUM* vsk;
    EC_POINT* vpk;
    std::string certificate;
    
    BIGNUM* ask_root;
    EC_POINT* apk_root;
    EC_POINT* vapk_root;
    std::string deri_root;
    std::string aid;
    
    VehicleStorage();
    ~VehicleStorage();
    
    void Clear();
    bool SaveToFile(const std::string& dir) const;
    bool LoadFromFile(const std::string& dir, const std::string& id);
};

// 管理员存储结构
struct ManagerStorage {
    std::string entity_id;
    BIGNUM* msk;
    EC_POINT* mpk;
    
    int committed_space;
    double last_quality;
    BIGNUM* random_x;
    
    ManagerStorage();
    ~ManagerStorage();
    
    void Clear();
    bool SaveToFile(const std::string& dir) const;
    bool LoadFromFile(const std::string& dir, const std::string& id);
};

// RSU存储结构
struct RSUStorage {
    std::string entity_id;
    BIGNUM* rsk;
    EC_POINT* rpk;
    
    RSUStorage();
    ~RSUStorage();
    
    void Clear();
    bool SaveToFile(const std::string& dir) const;
    bool LoadFromFile(const std::string& dir, const std::string& id);
};

// 知识签名
struct SignatureOfKnowledge {
    EC_POINT* Pr1;
    EC_POINT* Pr2;
    BIGNUM* Ch;
    BIGNUM* Rp1;
    BIGNUM* Rp2;
    std::string timestamp;
    
    SignatureOfKnowledge();
    ~SignatureOfKnowledge();
};

// 周期证明
struct PeriodProof {
    std::string h_commit;
    uint64_t valid_until;
    std::string rsu_signature;
    
    std::string ToString() const;
};

// 车辆消息
struct VehicleMessage {
    std::string msg;
    std::string aid;
    EC_POINT* apk;
    EC_POINT* vapk;
    std::string timestamp;
    SignatureOfKnowledge signature;
    PeriodProof period_proof;
    
    VehicleMessage();
    ~VehicleMessage();
};

// 注册请求类
class RegisterRequest {
public:
    EC_POINT* apk_root;
    EC_POINT* vapk_root;
    std::string deri_root;
    std::string certificate;
    std::string signature;
    std::string aid;
    
    RegisterRequest();
    ~RegisterRequest();
    
    void BuildRequest(SystemParams* params, 
                      EC_POINT* apk_root, 
                      EC_POINT* vapk_root,
                      const std::string& deri_root,
                      const std::string& certificate,
                      BIGNUM* vsk,
                      const std::string& aid);
    
    bool Verify(SystemParams* params, EC_POINT* vpk, BIGNUM* msk) const;
    std::string Serialize() const;
    bool Deserialize(const std::string& data, SystemParams* params);
};

// EcoRedact 系统主类
class EcoRedactSystem {
public:
    EcoRedactSystem();
    ~EcoRedactSystem();

    // 系统初始化
    SystemParams* Setup(int curve_nid = NID_secp256k1);
    
    // 创建实体
    VehicleStorage* CreateVehicle(const std::string& vehicle_id);
    ManagerStorage* CreateManager(const std::string& manager_id, int committed_space);
    RSUStorage* CreateRSU(const std::string& rsu_id);
    
    VehicleStorage* LoadVehicle(const std::string& vehicle_id);
    ManagerStorage* LoadManager(const std::string& manager_id);
    RSUStorage* LoadRSU(const std::string& rsu_id);
    
    const std::vector<ManagerStorage*>& GetAllManagers() const { return all_managers_; }
    
    // 空间证明竞争
    std::pair<ManagerStorage*, std::vector<std::pair<std::string, double>>> 
    PoSpaceRacing(std::vector<ManagerStorage*>& managers);
    
    // 匿名公钥上链
    void GenerateRootKey(SystemParams* params, VehicleStorage* vehicle, EC_POINT* mpk);
    RegisterRequest BuildRegisterRequest(SystemParams* params, VehicleStorage* vehicle,
                                          EC_POINT* mpk, const std::string& manager_id);
    bool ProcessRegisterRequest(SystemParams* params, const RegisterRequest& req,
                                 ManagerStorage* manager);
    
    Blockchain* GetBlockchain() { return blockchain_; }
    
    // 机动因子管理
    std::string GenerateMobilityFactor(const std::vector<ManagerStorage*>& managers);
    std::string UpdateAllManagersRandomNumbersSafe(
        const std::vector<ManagerStorage*>& managers,
        const std::string& old_txs_hash,
        const std::string& old_F_encrypted,
        const std::string& new_txs_hash);
    
    void UpdateManagerRankings(const std::vector<std::pair<std::string, double>>& qualities);
    
    // 辅助函数
    std::string ExtendHashToLength(const std::string& hash, size_t target_len);
    
    // 匿名通信
    EC_POINT* GetRootAPKByAID(const std::string& aid);
    
    std::tuple<BIGNUM*, EC_POINT*, EC_POINT*, std::string> 
    DeriveKey(SystemParams* params, 
              BIGNUM* prev_ask, 
              const std::string& prev_deri,
              EC_POINT* prev_apk, 
              int k,
              EC_POINT* vpk,
              EC_POINT* mpk);
    
    std::tuple<BIGNUM*, EC_POINT*, EC_POINT*, std::string> 
    DeriveKeyFromRoot(SystemParams* params,
                      VehicleStorage* vehicle,
                      int k,
                      EC_POINT* mpk);
    
    EC_POINT* ComputeVAPK(SystemParams* params, EC_POINT* vpk, BIGNUM* ask, EC_POINT* mpk);
    
    PeriodProof PeriodProofGen(RSUStorage* rsu, const std::string& aid,
                                EC_POINT* apk, int key_index, int duration);
    bool PeriodProofVerify(const PeriodProof& proof, EC_POINT* rsu_pk);
    
    SignatureOfKnowledge SoKGen(SystemParams* params, const std::string& msg,
                                 BIGNUM* ask, BIGNUM* vsk,
                                 EC_POINT* apk, EC_POINT* vpk, EC_POINT* mpk,
                                 const PeriodProof& proof);
    
    bool SoKVerify(SystemParams* params, const std::string& msg,
                   const SignatureOfKnowledge& sig,
                   EC_POINT* apk, EC_POINT* vapk, EC_POINT* mpk,
                   const PeriodProof& proof, EC_POINT* rsu_pk);
    
    VehicleMessage SendMessage(SystemParams* params, const std::string& msg,
                                const std::string& aid,
                                EC_POINT* apk, EC_POINT* vapk,
                                const SignatureOfKnowledge& sig,
                                const PeriodProof& proof);
    
    bool ReceiveAndVerify(SystemParams* params, const VehicleMessage& msg,
                          EC_POINT* mpk, EC_POINT* rsu_pk);
    
    // 匿名公钥撤销
    bool AnonKeyRevoke(const std::string& aid, const std::string& reason,
                       const std::vector<ManagerStorage*>& managers);
    
    bool IsAIDRevoked(const std::string& aid);
    std::vector<std::pair<std::string, std::string>> GetRevokeHistory();
    std::vector<ModificationRecord> GetModificationHistory();

    // 追溯验证
    bool TraceVerify(const std::string& aid, EC_POINT* vpk, BIGNUM* msk);

private:
    std::string key_dir_ = "./keys/";
    SystemParams* current_params_;
    Blockchain* blockchain_;
    std::vector<ManagerStorage*> all_managers_;
    std::vector<TransactionSubBlock> pending_transactions_;
    std::vector<std::pair<std::string, std::string>> revoke_history_;
    
    // 辅助函数
    std::string HMAC_SHA512(const std::string& key, const std::string& data);
    std::string ComputeSHA256String(const std::string& input);
    std::string BytesToHexString(const unsigned char* bytes, size_t len);
    std::vector<uint8_t> HexToBytes(const std::string& hex);
    std::vector<uint8_t> ComputeSHA256(const std::vector<uint8_t>& data);
    
    // ECIES加密/解密（陷门单向函数）
    std::string ECIESEncrypt(const std::string& plaintext, EC_POINT* public_key);
    std::string ECIESDecrypt(const std::string& ciphertext, BIGNUM* private_key);
};

} // namespace EcoRedact

#endif // ECOREDACT_H
