#include "ecoreact.h"
#include "blockchain.h"
#include <iostream>
#include <vector>
#include <cstdlib>
#include <ctime>
#include <chrono>

using namespace EcoRedact;

// 追溯验证辅助函数
static bool VerifyVAPKEquation_Reverse(EC_GROUP* group, BN_CTX* ctx,
                                       EC_POINT* vpk, EC_POINT* apk_root,
                                       EC_POINT* vapk_root, BIGNUM* msk) {
    EC_POINT* msk_apk = EC_POINT_new(group);
    EC_POINT_mul(group, msk_apk, nullptr, apk_root, msk, ctx);
    
    EC_POINT* computed_vpk = EC_POINT_new(group);
    EC_POINT_copy(computed_vpk, vapk_root);
    EC_POINT_invert(group, msk_apk, ctx);
    EC_POINT_add(group, computed_vpk, computed_vpk, msk_apk, ctx);
    
    bool valid = (EC_POINT_cmp(group, computed_vpk, vpk, ctx) == 0);
    
    EC_POINT_free(msk_apk);
    EC_POINT_free(computed_vpk);
    
    return valid;
}

int main() {
    std::srand(static_cast<unsigned>(std::time(nullptr)));
    
    std::cout << "========================================" << std::endl;
    std::cout << "  EcoRedact 实验程序" << std::endl;
    std::cout << "  基于可编辑区块链的车联网条件隐私保护认证方案" << std::endl;
    std::cout << "========================================" << std::endl;
    
    // 1. 系统初始化
    std::cout << "\n========== 系统初始化 ==========" << std::endl;
    
    EcoRedactSystem system;
    SystemParams* params = system.Setup();
    
    if (!params) {
        std::cerr << "系统初始化失败" << std::endl;
        return -1;
    }
    
    // 2. 创建实体
    std::cout << "\n========== 创建实体 ==========" << std::endl;
    
    std::vector<ManagerStorage*> managers;
    for (int i = 1; i <= 10; i++) {
        int space = 50 + rand() % 151;
        managers.push_back(system.CreateManager("M" + std::to_string(i), space));
    }
    
    RSUStorage* rsu = system.CreateRSU("R001");
    
    std::vector<VehicleStorage*> vehicles;
    for (int i = 1; i <= 5; i++) {
        vehicles.push_back(system.CreateVehicle("V" + std::to_string(i)));
    }
    
    // 3. 空间证明竞争与匿名公钥上链
    std::cout << "\n========== 空间证明竞争与匿名公钥上链 ==========" << std::endl;
    
    auto [winner, qualities] = system.PoSpaceRacing(managers);
    //std::cout << "\n获胜管理员: " << winner->entity_id << " (获得记账权)" << std::endl;
    
    system.UpdateManagerRankings(qualities);
    
    for (auto* vehicle : vehicles) {
        system.GenerateRootKey(params, vehicle, winner->mpk);
        RegisterRequest req = system.BuildRegisterRequest(params, vehicle, winner->mpk, winner->entity_id);
        if (system.ProcessRegisterRequest(params, req, winner)) {
            std::cout << "车辆 " << vehicle->entity_id << " 注册成功, AID: " 
                      << vehicle->aid.substr(0, 16) << "..." << std::endl;
        }
    }
    
    // 4. 匿名通信
    std::cout << "\n========== 匿名通信 ==========" << std::endl;
    
    VehicleStorage* sender = vehicles[0];
    VehicleStorage* receiver = vehicles[1];
    
    auto [ask1, apk1, vapk1, deri1] = system.DeriveKeyFromRoot(params, sender, 1, winner->mpk);
    std::cout << "派生匿名密钥成功" << std::endl;
    
    PeriodProof proof = system.PeriodProofGen(rsu, sender->aid, apk1, 1, 3600);
    std::cout << "RSU 签发周期证明成功 (有效期1小时)" << std::endl;
    
    std::string full_msg = "Emergency: Vehicle at position (34.05, -118.25) speed 65 km/h";
    SignatureOfKnowledge sig = system.SoKGen(params, full_msg,
                                              ask1, sender->vsk, apk1, sender->vpk, winner->mpk, proof);
    std::cout << "知识签名生成成功" << std::endl;
    
    VehicleMessage msg = system.SendMessage(params, full_msg, 
                                            sender->aid,
                                            apk1, vapk1, sig, proof);
    std::cout << "车辆 " << sender->entity_id << " 发送消息" << std::endl;
    
    bool valid = system.ReceiveAndVerify(params, msg, winner->mpk, rsu->rpk);
    std::cout << "车辆 " << receiver->entity_id << " 验证结果: " 
              << (valid ? "有效" : "无效") << std::endl;
    
    // 5. 追溯验证
    std::cout << "\n========== 追溯验证 ==========" << std::endl;

    std::string malicious_aid = vehicles[2]->aid; //假定车辆 V3 为恶意车辆
    std::cout << "  恶意车辆 AID: " << malicious_aid.substr(0, 32) << "..." << std::endl;

    bool vapk_valid = VerifyVAPKEquation_Reverse(
        params->group, params->ctx,
        vehicles[0]->vpk,
        vehicles[0]->apk_root,
        vehicles[0]->vapk_root,
        winner->msk
    );
    std::cout << "  VAPK等式验证: " << (vapk_valid ? "完成" : "失败") << std::endl;

    bool trace_valid = system.TraceVerify(malicious_aid, vehicles[0]->vpk, winner->msk);
    std::cout << "  追溯验证结果: " << (trace_valid ? "成功(已识别恶意车辆)" : "失败") << std::endl;
    
    // 6. 匿名公钥撤销
    std::cout << "\n========== 匿名公钥撤销 ==========" << std::endl;
    
    std::string revoke_aid = vehicles[2]->aid;
    std::cout << "准备撤销车辆 V3, AID: " << revoke_aid.substr(0, 32) << "..." << std::endl;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    bool revoke_success = system.AnonKeyRevoke(revoke_aid, "恶意行为: 发送虚假交通信息", managers);
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    if (revoke_success) {
        std::cout << "\n物理撤销成功! (耗时: " << duration.count() << "ms)" << std::endl;
        std::cout << "核心不变性已保持，区块链接结构未破坏" << std::endl;
    } else {
        std::cout << "\n物理撤销失败" << std::endl;
    }
    
    std::cout << "\n撤销后验证:" << std::endl;
    for (int i = 0; i < 3; i++) {
        bool exists = system.GetBlockchain()->FindTransactionByAID(vehicles[i]->aid) != nullptr;
        std::cout << "  V" << (i+1) << " AID 存在: " << (exists ? "是" : "否") << std::endl;
    }
    
    auto history = system.GetRevokeHistory();
    if (!history.empty()) {
        std::cout << "\n撤销历史:" << std::endl;
        for (const auto& h : history) {
            std::cout << "  - AID: " << h.first.substr(0, 32) << "... 原因: " << h.second << std::endl;
        }
    }
    
    // ========== 清理资源 ==========
    for (auto* v : vehicles) {
        if (v) delete v;
    }
    for (auto* m : managers) {
        if (m) delete m;
    }
    if (rsu) delete rsu;

    std::cout << "\n========================================" << std::endl;
    std::cout << "  实验完成" << std::endl;
    std::cout << "========================================" << std::endl;

    return 0;
}
