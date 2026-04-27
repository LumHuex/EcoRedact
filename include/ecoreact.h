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

namespace EcoRedact {

class Blockchain;
struct TransactionSubBlock;

// ==================== 实体类型枚举 ====================

enum class EntityType {
    VEHICLE,    // 车辆 V
    MANAGER,    // 管理员群组 M
    RSU         // 路边单元 RSU
};

// ==================== 阶段一: 系统初始化相关结构 ====================

struct SystemParams {
    EC_GROUP* group;   // 加法循环群 G
    EC_POINT* P;       // 生成元 P
    BIGNUM* q;         // 群的阶 q
    BN_CTX* ctx;
    
    SystemParams();
    ~SystemParams();
};

// ==================== 车辆存储结构 ====================

struct VehicleStorage {
    std::string entity_id;           // 车辆标识符 V_i
    BIGNUM* vsk;                     // 真实私钥 vsk_i
    EC_POINT* vpk;                   // 真实公钥 vpk_i = vsk_i · P
    std::string certificate;         // 公钥证书 Cert_i
    
    BIGNUM* ask_root;                // 根匿名私钥 ask_i^r
    EC_POINT* apk_root;              // 根匿名公钥 apk_i^r = ask_root · P
    EC_POINT* vapk_root;             // 根条件验证公钥 vapk_i^r = vpk_i + ask_root · mpk_j
    std::string deri_root;           // 根派生信息 deri_i^r
    std::string aid;                 // 匿名身份标识 AID_i = H(apk_root || Key)
    
    VehicleStorage();
    ~VehicleStorage();
    
    void Clear();
    bool SaveToFile(const std::string& dir) const;
    bool LoadFromFile(const std::string& dir, const std::string& id);
};

// ==================== 管理员存储结构 ====================

struct ManagerStorage {
    std::string entity_id;           // 管理员标识符 M_j
    BIGNUM* msk;                     // 管理员私钥 msk_j
    EC_POINT* mpk;                   // 管理员公钥 mpk_j = msk_j · P
    
    int committed_space;             // 承诺空间大小 (MB)
    double last_quality;             // 最后一次证明质量 v
    BIGNUM* random_x;                // 专属随机数 x_i (用于机动因子生成)
    
    ManagerStorage();
    ~ManagerStorage();
    
    void Clear();
    bool SaveToFile(const std::string& dir) const;
    bool LoadFromFile(const std::string& dir, const std::string& id);
};

// ==================== RSU存储结构 ====================

struct RSUStorage {
    std::string entity_id;           // RSU标识符 R_l
    BIGNUM* rsk;                     // RSU私钥 rsk_l
    EC_POINT* rpk;                   // RSU公钥 rpk_l = rsk_l · P
    
    RSUStorage();
    ~RSUStorage();
    
    void Clear();
    bool SaveToFile(const std::string& dir) const;
    bool LoadFromFile(const std::string& dir, const std::string& id);
};

// ==================== 阶段三: 匿名通信相关结构 ====================

struct SignatureOfKnowledge {
    EC_POINT* Pr1;          // 承诺 Pr_{i,1} = r1 · P
    EC_POINT* Pr2;          // 承诺 Pr_{i,2} = r2 · P + r1 · mpk_j
    BIGNUM* Ch;             // 挑战值 Ch_i
    BIGNUM* Rp1;            // 响应 Rp_{i,1} = r1 - ask_i^k · Ch_i (mod q)
    BIGNUM* Rp2;            // 响应 Rp_{i,2} = r2 - vsk_i · Ch_i (mod q)
    std::string timestamp;  // 时间戳 t_s
    
    SignatureOfKnowledge();
    ~SignatureOfKnowledge();
};

struct PeriodProof {
    std::string h_commit;               // 承诺值 h_commit = H(apk || k)
    uint64_t valid_until;               // 有效期截止时间 T_end
    std::string rsu_signature;          // RSU签名 σ_RSU
    
    std::string ToString() const;
};

struct VehicleMessage {
    std::string msg;                    // 交通消息 msg
    EC_POINT* apk;                      // 匿名公钥 apk_i^k
    EC_POINT* vapk;                     // 条件验证公钥 vapk_i^k
    std::string timestamp;              // 时间戳 t_s
    SignatureOfKnowledge signature;     // 知识签名 σ
    PeriodProof period_proof;           // 周期证明
    VehicleMessage();
    ~VehicleMessage();
};

// ==================== 阶段二: 注册请求类 ====================

class RegisterRequest {
public:
    EC_POINT* apk_root;     // 根匿名公钥 apk_i^r
    EC_POINT* vapk_root;    // 根条件验证公钥 vapk_i^r
    std::string deri_root;  // 根派生信息 deri_i^r
    std::string certificate; // 车辆公钥证书 Cert_i
    std::string signature;   // 车辆签名 Sign_i
    std::string aid;         // 匿名身份标识 AID_i
    
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

// ==================== EcoRedact 系统主类 ====================

class EcoRedactSystem {
public:
    EcoRedactSystem();
    ~EcoRedactSystem();

    // ==================== 阶段一: 系统初始化 ====================
    SystemParams* Setup(int curve_nid = NID_secp256k1);
    
    VehicleStorage* CreateVehicle(const std::string& vehicle_id);
    ManagerStorage* CreateManager(const std::string& manager_id, int committed_space);
    RSUStorage* CreateRSU(const std::string& rsu_id);
    
    VehicleStorage* LoadVehicle(const std::string& vehicle_id);
    ManagerStorage* LoadManager(const std::string& manager_id);
    RSUStorage* LoadRSU(const std::string& rsu_id);
    
    // 获取所有管理员列表
    const std::vector<ManagerStorage*>& GetAllManagers() const { return all_managers_; }
    
    // ==================== 阶段二: 匿名公钥上链 ====================
    std::pair<ManagerStorage*, std::vector<std::pair<std::string, double>>> 
    PoSpaceRacing(std::vector<ManagerStorage*>& managers);
    
    void GenerateRootKey(SystemParams* params, VehicleStorage* vehicle, EC_POINT* mpk);
    
    RegisterRequest BuildRegisterRequest(SystemParams* params, VehicleStorage* vehicle,
                                          EC_POINT* mpk, const std::string& manager_id);
    
    bool ProcessRegisterRequest(SystemParams* params, const RegisterRequest& req,
                                 ManagerStorage* manager);
    
    Blockchain* GetBlockchain() { return blockchain_; }
    
    // ==================== 机动因子管理 (核心可编辑机制) ====================
    
    // 生成机动因子 G_i
    std::string GenerateMobilityFactor(const std::vector<ManagerStorage*>& managers);
    
    // 撤销时，所有管理员协作更新自己的随机数
    std::string UpdateAllManagersRandomNumbers(
    const std::vector<ManagerStorage*>& managers,
    const std::string& old_txs_hash,
    const std::string& old_G_encrypted,
    const std::string& new_txs_hash);
    
    // ==================== 阶段三: 匿名通信 ====================
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
                   const PeriodProof& proof);
    
    // ==================== 车辆间通信模拟 ====================
    VehicleMessage SendMessage(SystemParams* params, const std::string& msg,
                                EC_POINT* apk, EC_POINT* vapk,
                                const SignatureOfKnowledge& sig,
                                const PeriodProof& proof);
    
    bool ReceiveAndVerify(SystemParams* params, const VehicleMessage& msg,
                          EC_POINT* mpk, EC_POINT* rsu_pk);
    
    // ==================== 阶段四: 匿名公钥撤销 ====================
    bool AnonKeyRevoke(const std::string& aid, const std::string& reason,
                       const std::vector<ManagerStorage*>& managers);
    
    bool IsAIDRevoked(const std::string& aid);
    std::vector<std::pair<std::string, std::string>> GetRevokeHistory();


private:
    std::string key_dir_ = "./keys/";
    SystemParams* current_params_;
    Blockchain* blockchain_;
    std::vector<ManagerStorage*> all_managers_;  // 所有管理员列表
    std::vector<TransactionSubBlock> pending_transactions_;
    std::vector<std::pair<std::string, std::string>> revoke_history_;
    
    // 辅助函数
    std::string HMAC_SHA512(const std::string& key, const std::string& data);
    std::string ComputeSHA256String(const std::string& input);
    std::string BytesToHexString(const unsigned char* bytes, size_t len);
    std::vector<uint8_t> HexToBytes(const std::string& hex);
    std::vector<uint8_t> ComputeSHA256(const std::vector<uint8_t>& data);
    
    // AES-CTR 加密/解密（线性加密，支持密文异或）
    std::vector<unsigned char> DeriveKeyFromPublicKey(EC_POINT* pk);
    std::vector<unsigned char> DeriveKeyFromPrivateKey(BIGNUM* private_key);
    std::string AESCTREncrypt(const std::vector<unsigned char>& key, const std::string& plaintext);
    std::string AESCTRDecrypt(const std::vector<unsigned char>& key, const std::string& ciphertext);
    
    // 使用管理员公钥/私钥的加密解密
    std::string EncryptWithManagerKey(const std::string& plaintext, EC_POINT* manager_pk);
    std::string DecryptWithManagerKey(const std::string& ciphertext, BIGNUM* manager_sk);
};

} // namespace EcoRedact

#endif // ECOREDACT_H