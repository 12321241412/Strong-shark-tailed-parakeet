import hashlib
from hashlib import sha256
import sys

# 有限域参数（BN254曲线对应的质数）
PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617

def generate_round_constants(seed, n_rounds, t):
    """生成轮常数(Round Constants)"""
    constants = []
    for r in range(n_rounds):
        round_constants = []
        for i in range(t):
            # 使用SHA-256生成伪随机数
            h = sha256()
            h.update(f"{seed}_round{r}_element{i}".encode())
            val = int.from_bytes(h.digest(), 'big') % PRIME
            round_constants.append(hex(val))
        constants.append(round_constants)
    return constants


def generate_mds_matrix(t):
    """生成MDS矩阵（使用Cauchy矩阵构造法）"""
    # 选择两个不相交的集合
    x_set = [i + 1 for i in range(t)]
    y_set = [i + t + 1 for i in range(t)]

    # 构建Cauchy矩阵
    mds = []
    for i in range(t):
        row = []
        for j in range(t):
            # 计算1/(x_i - y_j) mod p
            denominator = (x_set[i] - y_set[j]) % PRIME
            inv_denominator = pow(denominator, PRIME - 2, PRIME)
            row.append(hex(inv_denominator))
        mds.append(row)
    return mds


if __name__ == "__main__":
    # 参数配置 (t=3, 总轮数=64)
    t = 3
    n_rounds = 64
    seed = "poseidon2_seed"

    # 生成参数
    rc = generate_round_constants(seed, n_rounds, t)
    mds = generate_mds_matrix(t)
