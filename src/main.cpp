#include "ecoreact.h"
#include "blockchain.h"
#include <iostream>
#include <vector>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iomanip>

using namespace EcoRedact;

// 辅助函数：计算时间差（毫秒）
template<typename Clock = std::chrono::high_resolution_clock>
double elapsed_ms(const typename Clock::time_point& start, const typename Clock::time_point& end) {
    return std::chrono::duration<double, std::milli>(end - start).count();
}

//验证 vpk = vapk_root - msk * apk_root
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

// 获取当前时间字符串
std::string GetCurrentTimeString() {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t_now), "%Y%m%d_%H%M%S");
    return ss.str();
}

// 保存性能结果到文件
void SavePerformanceResults(const std::string& filename, 
                            double setup_time,
                            const std::vector<double>& registration_times,
                            double avg_reg_time,
                            double key_derivation_time,
                            double signing_time,
                            double verification_time,
                            double trace_time,
                            double revoke_time,
                            bool revoke_success) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        std::cerr << "无法打开文件: " << filename << std::endl;
        return;
    }
    
    // 写入文件头
    file << "========================================\n";
    file << "EcoRedact 性能测试结果\n";
    file << "========================================\n";
    file << "测试时间: " << GetCurrentTimeString() << "\n\n";
    
    // 1. 系统初始化
    file << "1. 系统初始化\n";
    file << "   耗时: " << setup_time << " ms\n\n";
    
    // 2. 匿名公钥上链
    file << "2. 匿名公钥上链（车辆注册）\n";
    file << "   平均耗时: " << avg_reg_time << " ms\n";
    file << "   各车辆注册明细:\n";
    for (size_t i = 0; i < registration_times.size(); i++) {
        file << "     车辆 V" << (i+1) << ": " << registration_times[i] << " ms\n";
    }
    file << "\n";
    
    // 3. 匿名公钥生成
    file << "3. 匿名公钥生成\n";
    file << "   耗时: " << key_derivation_time << " ms\n\n";
    
    // 4. 消息签名
    file << "4. 消息签名\n";
    file << "   耗时: " << signing_time << " ms\n\n";
    
    // 5. 消息验证
    file << "5. 消息验证\n";
    file << "   耗时: " << verification_time << " ms\n\n";
    
    // 6. 追溯验证
    file << "6. 追溯验证\n";
    file << "   耗时: " << trace_time << " ms\n\n";
    
    // 7. 匿名公钥撤销
    file << "7. 匿名公钥撤销\n";
    if (revoke_success) {
        file << "   耗时: " << revoke_time << " ms\n";
        file << "   状态: 成功\n\n";
    } else {
        file << "   状态: 失败\n\n";
    }
    
    // 性能总结表格
    file << "========================================\n";
    file << "性能总结表格\n";
    file << "========================================\n";
    file << std::left << std::setw(25) << "操作" 
         << std::right << std::setw(15) << "耗时(ms)" << "\n";
    file << std::string(40, '-') << "\n";
    file << std::left << std::setw(25) << "系统初始化" 
         << std::right << std::setw(15) << std::fixed << std::setprecision(3) << setup_time << "\n";
    file << std::left << std::setw(25) << "匿名公钥上链(平均)" 
         << std::right << std::setw(15) << avg_reg_time << "\n";
    file << std::left << std::setw(25) << "匿名公钥生成" 
         << std::right << std::setw(15) << key_derivation_time << "\n";
    file << std::left << std::setw(25) << "消息签名" 
         << std::right << std::setw(15) << signing_time << "\n";
    file << std::left << std::setw(25) << "消息验证" 
         << std::right << std::setw(15) << verification_time << "\n";
    file << std::left << std::setw(25) << "追溯验证" 
         << std::right << std::setw(15) << trace_time << "\n";
    if (revoke_success) {
        file << std::left << std::setw(25) << "匿名公钥撤销" 
             << std::right << std::setw(15) << revoke_time << "\n";
    }
    
    file << "\n========================================\n";
    file << "测试完成时间: " << GetCurrentTimeString() << "\n";
    file << "========================================\n";
    
    file.close();
    std::cout << "\n性能结果已保存到文件: " << filename << std::endl;
}

int main() {
    std::srand(static_cast<unsigned>(std::time(nullptr)));
    
    std::cout << "========================================" << std::endl;
    std::cout << "  EcoRedact 实验程序 " << std::endl;
    std::cout << "  基于可编辑区块链的车联网条件隐私保护认证方案" << std::endl;
    std::cout << "========================================" << std::endl;
    
    // 用于记录总时间
    double total_setup_time = 0;
    double total_setuptest_time = 0;
    std::vector<double> registration_times;
    double key_derivation_time = 0;
    double signing_time = 0;
    double verification_time = 0;
    double trace_time = 0;
    double revoke_time = 0;
    bool revoke_success = false;
    
    // ========== 1. 系统初始化时间开销 ==========
    std::cout << "\n========== 性能测量开始 ==========" << std::endl;
    
    auto t1 = std::chrono::high_resolution_clock::now();
    
    EcoRedactSystem system;
    SystemParams* params = system.Setup();
    
    // 临时生成一个RSU来模拟系统初始化完整开销
    RSUStorage* temp_rsu_for_init = system.CreateRSU("TEMP_RSU_INIT");
    
    auto t2 = std::chrono::high_resolution_clock::now();
    total_setup_time = elapsed_ms(t1, t2);
    
    std::cout << "\n[性能] 系统初始化耗时: " 
              << total_setup_time << " ms" << std::endl;
    
    if (!params) return -1;
    
    // ========== 阶段一: 创建实体 ==========
    std::cout << "\n========== 阶段一: 创建实体 ==========" << std::endl;
    
    // 创建10个管理员
    std::vector<ManagerStorage*> managers;
    for (int i = 1; i <= 10; i++) {
        int space = 50 + rand() % 151;
        managers.push_back(system.CreateManager("M" + std::to_string(i), space));
    }
    auto tts = std::chrono::high_resolution_clock::now();
    // 创建正式RSU
    RSUStorage* rsu = system.CreateRSU("R001");
    auto tte = std::chrono::high_resolution_clock::now();
    total_setuptest_time = elapsed_ms(tts, tte);
    
    // 创建5辆车
    std::vector<VehicleStorage*> vehicles;
    for (int i = 1; i <= 5; i++) {
        vehicles.push_back(system.CreateVehicle("V" + std::to_string(i)));
    }
    
    // ========== 阶段二: 匿名公钥上链 ==========
    std::cout << "\n========== 阶段二: 匿名公钥上链 ==========" << std::endl;
    
    auto [winner, qualities] = system.PoSpaceRacing(managers);
    std::cout << "\n  获胜管理员: " << winner->entity_id << std::endl;
    
    // 车辆注册上链 - 测量每次注册的时间
    std::cout << "\n[性能] 车辆注册（公钥上链）耗时明细:" << std::endl;
    for (auto* vehicle : vehicles) {
        auto reg_start = std::chrono::high_resolution_clock::now();
        
        system.GenerateRootKey(params, vehicle, winner->mpk);
        RegisterRequest req = system.BuildRegisterRequest(params, vehicle, winner->mpk, winner->entity_id);
        system.ProcessRegisterRequest(params, req, winner);
        
        auto reg_end = std::chrono::high_resolution_clock::now();
        double reg_time = elapsed_ms(reg_start, reg_end);
        registration_times.push_back(reg_time);
        
        std::cout << "    车辆 " << vehicle->entity_id << " 注册成功, 耗时: " 
                  << reg_time << " ms, AID: " << vehicle->aid.substr(0, 16) << "..." << std::endl;
    }
    
    // 计算平均注册时间
    double avg_reg_time = 0;
    for (double t : registration_times) avg_reg_time += t;
    avg_reg_time /= registration_times.size();
    std::cout << "  [性能] 平均单次注册耗时: " << avg_reg_time << " ms" << std::endl;
    
    // ========== 阶段三: 匿名通信 ==========
    std::cout << "\n========== 阶段三: 匿名通信 ==========" << std::endl;
    
    VehicleStorage* sender = vehicles[0];
    VehicleStorage* receiver = vehicles[1];
    
    // 3. 派生匿名密钥时间开销
    auto derive_start = std::chrono::high_resolution_clock::now();
    
    auto [ask1, apk1, vapk1, deri1] = system.DeriveKeyFromRoot(params, sender, 1, winner->mpk);
    
    auto derive_end = std::chrono::high_resolution_clock::now();
    key_derivation_time = elapsed_ms(derive_start, derive_end);
    std::cout << "\n[性能] 单次匿名公钥生成耗时: " << key_derivation_time << " ms" << std::endl;
    
    // RSU签发周期证明
    PeriodProof proof = system.PeriodProofGen(rsu, sender->aid, apk1, 1, 3600);
    std::cout << "  RSU 签发周期证明成功" << std::endl;
    
    // 4. 知识签名生成时间开销
    auto sign_start = std::chrono::high_resolution_clock::now();
    
    SignatureOfKnowledge sig = system.SoKGen(params, 
                                              "Emergency: Vehicle at position (34.05, -118.25) speed 65 km/h",
                                              ask1, sender->vsk, apk1, sender->vpk, winner->mpk, proof);
    
    auto sign_end = std::chrono::high_resolution_clock::now();
    signing_time = elapsed_ms(sign_start, sign_end);
    std::cout << "[性能] 消息签名生成耗时: " << signing_time << " ms" << std::endl;
    
    // 发送消息
    VehicleMessage msg = system.SendMessage(params, "Emergency message", apk1, vapk1, sig, proof);
    std::cout << "  车辆 " << sender->entity_id << " 发送消息" << std::endl;
    
    // 5. 单消息验证时间开销
    auto verify_start = std::chrono::high_resolution_clock::now();
    
    bool valid = system.ReceiveAndVerify(params, msg, winner->mpk, rsu->rpk);
    
    auto verify_end = std::chrono::high_resolution_clock::now();
    verification_time = elapsed_ms(verify_start, verify_end);
    std::cout << "[性能] 单消息验证耗时: " << verification_time << " ms" << std::endl;
    
    std::cout << "  车辆 " << receiver->entity_id << " 验证结果: " 
              << (valid ? "有效" : "无效") << std::endl;
    
    // ========== 追溯验证性能测试 ==========
    BIGNUM* msk = winner->msk;
    VehicleStorage* trace_vehicle = vehicles[0];

    auto trace_start = std::chrono::high_resolution_clock::now();
    bool trace_valid = VerifyVAPKEquation_Reverse(
        params->group, params->ctx,
        trace_vehicle->vpk,
        trace_vehicle->apk_root,
        trace_vehicle->vapk_root,
        msk
    );
    auto trace_end = std::chrono::high_resolution_clock::now();
    trace_time = elapsed_ms(trace_start, trace_end);

    std::cout << "[性能] 追溯验证耗时: " << trace_time << " ms" << std::endl;
    std::cout << "验证结果: " << (trace_valid ? "成功" : "失败") << std::endl;
    
    // ========== 阶段四: 匿名公钥撤销 ==========
    std::cout << "\n========== 阶段四: 匿名公钥撤销 ==========" << std::endl;
    std::cout << "  演示机动因子机制实现物理撤销" << std::endl;
    
    auto revoke_start = std::chrono::high_resolution_clock::now();
    
    std::string revoke_aid = vehicles[2]->aid;
    std::cout << "\n  准备撤销车辆 V3, AID: " << revoke_aid << std::endl;
    revoke_success = system.AnonKeyRevoke(revoke_aid, "恶意行为: 发送虚假交通信息", managers);
    
    auto revoke_end = std::chrono::high_resolution_clock::now();
    revoke_time = elapsed_ms(revoke_start, revoke_end);
    
    if (revoke_success) {
        std::cout << "\n   物理撤销成功" << std::endl;
        std::cout << "[性能] 匿名公钥撤销耗时: " << revoke_time << " ms" << std::endl;
    }
    
    // 验证撤销结果
    std::cout << "\n  撤销后验证:" << std::endl;
    for (int i = 0; i < 3; i++) {
        bool exists = system.GetBlockchain()->FindTransactionByAID(vehicles[i]->aid) != nullptr;
        std::cout << "    V00" << (i+1) << " AID 存在: " << (exists ? "是" : "否") << std::endl;
    }
    
    // ========== 性能总结（输出到控制台） ==========
    std::cout << "\n========== 性能总结 ==========" << std::endl;
    std::cout << "1. 系统初始化: " << total_setup_time << " ms" << std::endl;
    std::cout << "1. 系统初始化test: " << total_setuptest_time << " ms" << std::endl;
    std::cout << "2. 单次匿名公钥上链: " << avg_reg_time << " ms (平均)" << std::endl;
    std::cout << "   - 各车辆注册明细: ";
    for (size_t i = 0; i < registration_times.size(); i++) {
        std::cout << registration_times[i] << " ms";
        if (i < registration_times.size()-1) std::cout << ", ";
    }
    std::cout << std::endl;
    std::cout << "3. 单次匿名公钥生成: " << key_derivation_time << " ms" << std::endl;
    std::cout << "4. 单次消息签名: " << signing_time << " ms" << std::endl;
    std::cout << "5. 单次消息验证: " << verification_time << " ms" << std::endl;
    std::cout << "6. 追溯验证: " << trace_time << " ms" << std::endl;
    if (revoke_success) {
        std::cout << "7. 匿名公钥撤销: " << revoke_time << " ms" << std::endl;
    }
    
    // ========== 保存性能结果到文件 ==========
    std::string filename = "../result/ecoreact_performance_" + GetCurrentTimeString() + ".txt";
    SavePerformanceResults(filename, total_setup_time, registration_times, avg_reg_time,
                          key_derivation_time, signing_time, verification_time,
                          trace_time, revoke_time, revoke_success);
    
    // 打印撤销后的区块链状态
    system.GetBlockchain()->PrintBlockchain();
    
    auto history = system.GetRevokeHistory();
    if (!history.empty()) {
        std::cout << "\n  撤销历史:" << std::endl;
        for (const auto& h : history) {
            std::cout << "    - AID: " << h.first.substr(0, 32) << "... 原因: " << h.second << std::endl;
        }
    }
    
    // ========== 清理资源 ==========
    for (auto* v : vehicles) delete v;
    delete rsu;
    delete temp_rsu_for_init;
    delete params;
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "  实验完成" << std::endl;
    std::cout << "========================================" << std::endl;
    
    return 0;
}