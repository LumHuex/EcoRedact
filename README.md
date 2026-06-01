# EcoRedact - 基于可编辑区块链的车联网条件隐私保护认证方案

## 项目简介

**EcoRedact** 是一个基于可编辑区块链的车联网条件隐私保护认证（CPPA）方案。该方案通过融合空间证明（Proof of Space, PoSpace）共识机制、机动因子驱动的可编辑区块链架构、分层确定性密钥派生和知识签名（Signature of Knowledge, SoK）等密码学技术，在保障车辆通信强匿名性的同时，实现了恶意身份的高效物理撤销与条件可追溯。

传统的车联网认证方案面临三大核心挑战：

1. **隐私与监管的矛盾**：车辆需要在匿名通信的同时，支持对恶意行为的身份追溯
2. **不可篡改与数据删除的矛盾**：区块链的"不可篡改"特性使得恶意数据无法被物理剔除
3. **高频密钥更新的性能瓶颈**：为抵抗轨迹追踪，车辆需频繁更换匿名密钥，导致严重的网络拥堵

EcoRedact 通过创新的可编辑区块链架构和轻量级密码学协议，在单一框架内同时解决上述三个问题。

## 主要特性

- **强隐私保护**：基于知识签名（SoK）的零知识证明技术，车辆可在不暴露真实身份的情况下完成合法性自证
- **条件可追溯性**：特权实体（管理员）可在检测到恶意行为时解构绑定关系，还原车辆真实身份
- **高效物理撤销**：支持对恶意车辆所有匿名凭证的一次性物理删除，满足GDPR"遗忘权"要求
- **无链上高频交互**：采用"链上注册根密钥、本地派生子密钥"模式，避免频繁链上交互导致的网络拥堵

## 编译与运行

### 环境要求

- 操作系统：Ubuntu 20.04/22.04/24.04 或其他 Linux 发行版
- 编译器：GCC/G++ 9.0+ 支持 C++17
- CMake：3.10 或更高版本
- OpenSSL：1.1.1 或更高版本

### 安装依赖

```bash
# Ubuntu
sudo apt update
sudo apt install build-essential cmake libssl-dev
```

### 编译步骤

```bash
# 1. 克隆仓库
git clone https://github.com/LumHuex/EcoRedact.git
cd EcoRedact

# 2. 创建构建目录
mkdir -p build && cd build

# 3. 配置 CMake
cmake ..

# 4. 编译
make

# 5. 运行程序
./ecoreact
```

### 目录结构

```
EcoRedact/
├── CMakeLists.txt              # CMake 配置文件
├── include/                    # 头文件目录
│   ├── blockchain.h            # 区块链结构头文件
│   └── ecoreact.h              # EcoRedact 系统头文件
├── src/                        # 源代码目录
│   ├── blockchain.cpp          # 区块链实现
│   ├── ecoreact.cpp            # EcoRedact 核心实现
│   └── main.cpp                # 主程序入口
├── build/                      # 构建目录
│   ├── ecoreact                # 可执行文件
│   └── keys/                   # 密钥存储目录（运行时自动创建）
│       ├── vehicle_*.key       # 车辆密钥文件
│       ├── manager_*.key       # 管理员密钥文件
│       ├── rsu_*.key          	# RSU 密钥文件
│       └── blockchain/         # 区块链数据目录
└── README.md                   # 本文档
```

## 实验流程

程序执行时会自动运行以下实验流程：

1. **系统初始化**：生成椭圆曲线参数（secp256k1）
2. **创建实体**：10个管理员、5个车辆、1个RSU
3. **空间证明竞争**：基于存储空间大小竞选记账权
4. **匿名公钥上链**：车辆注册根匿名公钥到区块链
5. **匿名通信**：派生子密钥、签发周期证明、生成知识签名
6. **追溯验证**：验证恶意车辆身份
7. **匿名公钥撤销**：物理删除恶意车辆的根匿名公钥，并保持其核心不变性

## 核心算法说明

### 核心API示例

以下示例展示了如何在代码中使用 EcoRedact 的核心功能：

```cpp
#include "ecoreact.h"

using namespace EcoRedact;

int main() {
    // 1. 系统初始化
    EcoRedactSystem system;
    SystemParams* params = system.Setup();
    
    // 2. 创建实体
    // 创建10个管理员（存储空间 50-200 MB）
    std::vector<ManagerStorage*> managers;
    for (int i = 1; i <= 10; i++) {
        int space = 50 + rand() % 151;
        managers.push_back(system.CreateManager("M" + std::to_string(i), space));
    }
    
    // 创建RSU和车辆
    RSUStorage* rsu = system.CreateRSU("R001");
    VehicleStorage* vehicle = system.CreateVehicle("V001");
    
    // 3. 空间证明竞争（确定记账权）
    auto [winner, qualities] = system.PoSpaceRacing(managers);
    
    // 4. 车辆注册根匿名公钥到区块链
    system.GenerateRootKey(params, vehicle, winner->mpk);
    RegisterRequest req = system.BuildRegisterRequest(params, vehicle, winner->mpk, winner->entity_id);
    system.ProcessRegisterRequest(params, req, winner);
    
    // 5. 派生通信密钥并发送匿名消息
    auto [ask, apk, vapk, deri] = system.DeriveKeyFromRoot(params, vehicle, 1, winner->mpk);
    PeriodProof proof = system.PeriodProofGen(rsu, vehicle->aid, apk, 1, 3600);
    SignatureOfKnowledge sig = system.SoKGen(params, "Emergency message", 
                                              ask, vehicle->vsk, apk, 
                                              vehicle->vpk, winner->mpk, proof);
    VehicleMessage msg = system.SendMessage(params, "Emergency message", 
                                            vehicle->aid, apk, vapk, sig, proof);
    
    // 6. 验证接收到的消息
    bool valid = system.ReceiveAndVerify(params, msg, winner->mpk, rsu->rpk);
    
    // 7. 追溯恶意车辆身份
    bool traced = system.TraceVerify(malicious_aid, vehicle->vpk, winner->msk);
    
    // 8. 撤销恶意车辆的匿名身份
    bool revoked = system.AnonKeyRevoke(malicious_aid, "恶意行为", managers);
    
    return 0;
}
```

## 核心算法

### 机动因子与可编辑性

机动因子是支持区块链可编辑的核心机制。每个区块的签名子块中存储机动因子 $F_i$，其构造方式如下：

$F_i = E_{mpk_1}(x_1) || E_{mpk_2}(x_2) || ... || E_{mpk_s}(x_s)$

其中：

- $E_{mpk}$ 是 ECIES 加密函数（陷门单向函数）
- $x$ 是管理员的专属随机数（陷门输入）
- $||$ 表示字符串拼接操作

**核心不变性**是数据可编辑的数学基础：

$H(τ_i) ⊕ F_i = H(τ_i') ⊕ F_i'$

这个等式的含义是：

- $H(τ_i)$是原始交易子块的哈希值
- $F_i$是原始机动因子
- 当交易内容从$τ_i$修改为$τ_i'$时，管理员群组协作计算新的机动因子 $F_i'$
- 修改前后，$H(τ_i) ⊕ F_i$保持不变
- 因此签名子块中的签名不需要改变，区块哈希链保持完整

**可编辑流程**：

1. 管理员群组检测到恶意车辆，发起撤销请求
2. 计算新交易子块的哈希值$H(τ_i')$
3. 根据核心不变性公式计算新的机动因子$F_i'$
4. 各管理员用私钥解密各自分片，获得新的专属随机数
5. 更新区块中的交易子块和签名子块
6. 区块链结构保持不变，所有后续区块无需调整

### 知识签名

知识签名（Signature of Knowledge, SoK）是一种将数字签名与零知识证明深度融合的密码学原语。车辆使用知识签名在不暴露真实身份的前提下证明其合法性。

**验证等式**：

```text
(Rp₁ + Rp₂)·P + Rp₁·mpk + (apk + vapk)·Ch = Pr₁ + Pr₂
```

其中：

- $apk$是车辆的匿名公钥
- $vapk$是条件验证公钥（绑定真实身份）
- $mpk$是管理员公钥
- $P$ 是椭圆曲线生成元

**安全保证**：

- **完备性**：诚实的证明者总能通过验证
- **可靠性**：攻击者无法在不掌握私钥的情况下伪造有效签名
- **零知识性**：验证者无法从签名中获取任何关于证明者私钥的信息

### 分层确定性密钥派生

EcoRedact 采用改进的 BIP32 分层确定性密钥派生算法，实现"一次注册，无限派生"的密钥管理模型。

```text
根密钥生成：
    I = HMAC-SHA512("VehicleAnonymousKey_Vi", seed)
    ask_root = I_L (mod q)
    deri_root = I_R (mod q)
    apk_root = ask_root · P

子密钥派生（第k次）：
    I = HMAC-SHA512(deri_{k-1}, apk_{k-1} || k)
    ask_k = ask_{k-1} · I_L (mod q)
    deri_k = I_R (mod q)
    apk_k = ask_k · P
```

这种设计使得：

- 车辆只需在区块链上注册一次根匿名公钥
- 后续通信密钥在本地派生，无需链上交互
- RSU 使用相同的派生算法验证车辆密钥的合法性

## 安全属性

| 属性         | 描述                             | 实现方式                      |
| :----------- | :------------------------------- | :---------------------------- |
| 抗伪造性     | 攻击者无法伪造有效签名           | SoK的特殊可靠性 + EUF-CMA安全 |
| 匿名性       | 签名不泄露车辆真实身份           | SoK的计算零知识性             |
| 不可链接性   | 无法判断两个签名是否来自同一车辆 | 随机化挑战值 + 周期证明       |
| 身份可追溯性 | TA可从签名中提取车辆真实身份     | vapk 绑定关系 + 管理员私钥    |
| 可控编辑     | 非授权对手无法伪造修改操作       | ECC陷门单向函数 + 门限协作    |
| 结构完整性   | 合法修改不破坏区块链拓扑         | H(τ) ⊕ F 核心不变性           |

## 输出示例

```text
========================================
  EcoRedact 实验程序
  基于可编辑区块链的车联网条件隐私保护认证方案
========================================

========== 系统初始化 ==========
  Setup - 初始化系统参数
  曲线: secp256k1, 阶位数: 256

========== 创建实体 ==========
  创建管理员: M1, 空间: 156 MB
  ...

========== 空间证明竞争与匿名公钥上链 ==========
  PoSpaceRacing - 空间证明竞争
  管理员 M1: 空间 = 156 MB
  获胜管理员: M1 (空间: 156 MB)

========== 匿名通信 ==========
派生匿名密钥成功
RSU 签发周期证明成功 (有效期1小时)
知识签名生成成功
车辆 V1 发送消息
  消息接受: 所有验证通过

========== 匿名公钥撤销 ==========
准备撤销车辆 V3, AID: abc123...
正确：核心不变性成立
  物理撤销成功!

撤销后验证:
  V1 AID 存在: 是
  V2 AID 存在: 是
  V3 AID 存在: 否

========================================
  实验完成
========================================
```

## 许可证

本项目仅供学术研究使用。

## 项目主页

项目源码已开源至：https://github.com/LumHuex/EcoRedact

## 联系方式

如有问题或建议，请通过 GitHub Issues 联系。
