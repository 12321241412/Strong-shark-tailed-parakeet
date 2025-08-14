import struct
import numpy as np
from typing import List, Tuple
import hashlib
import multiprocessing
from math import ceil, log2

# ---------------------------- SM3 基础实现 ----------------------------
class SM3:
    # 初始IV（256位）
    IV = [
        0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
        0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
    ]

    # 常量T_j
    T = [0x79CC4519] * 16 + [0x7A879D8A] * 48

    def __init__(self):
        self.state = self.IV.copy()
        self.buffer = bytearray()
        self.length = 0

    @staticmethod
    def _left_rotate(x: int, n: int) -> int:
        """循环左移"""
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    @staticmethod
    def _ff_j(x: int, y: int, z: int, j: int) -> int:
        """布尔函数FF_j"""
        if j < 16:
            return x ^ y ^ z
        else:
            return (x & y) | (x & z) | (y & z)

    @staticmethod
    def _gg_j(x: int, y: int, z: int, j: int) -> int:
        """布尔函数GG_j"""
        if j < 16:
            return x ^ y ^ z
        else:
            return (x & y) | ((~x) & z)

    @staticmethod
    def _p0(x: int) -> int:
        """置换函数P0"""
        return x ^ SM3._left_rotate(x, 9) ^ SM3._left_rotate(x, 17)

    @staticmethod
    def _p1(x: int) -> int:
        """置换函数P1"""
        return x ^ SM3._left_rotate(x, 15) ^ SM3._left_rotate(x, 23)

    def _compress(self, block: bytes):
        """压缩函数（处理512位块）"""
        # 消息扩展
        w = list(struct.unpack('>16I', block))
        for j in range(16, 68):
            w.append(SM3._p1(w[j-16] ^ w[j-9] ^ SM3._left_rotate(w[j-3], 15)) ^ 
                    SM3._left_rotate(w[j-13], 7) ^ w[j-6])
        w1 = [w[j] ^ w[j+4] for j in range(64)]

        # 64轮迭代
        a, b, c, d, e, f, g, h = self.state
        for j in range(64):
            ss1 = SM3._left_rotate((SM3._left_rotate(a, 12) + e + SM3._left_rotate(self.T[j], j)) % 32, 7)
            ss2 = ss1 ^ SM3._left_rotate(a, 12)
            tt1 = (self._ff_j(a, b, c, j) + d + ss2 + w1[j]) & 0xFFFFFFFF
            tt2 = (self._gg_j(e, f, g, j) + h + ss1 + w[j]) & 0xFFFFFFFF
            d = c
            c = SM3._left_rotate(b, 9)
            b = a
            a = tt1
            h = g
            g = SM3._left_rotate(f, 19)
            f = e
            e = SM3._p0(tt2)

        # 更新状态
        self.state = [
            self.state[0] ^ a,
            self.state[1] ^ b,
            self.state[2] ^ c,
            self.state[3] ^ d,
            self.state[4] ^ e,
            self.state[5] ^ f,
            self.state[6] ^ g,
            self.state[7] ^ h
        ]

    def update(self, data: bytes):
        """更新哈希状态"""
        self.buffer += data
        self.length += len(data)
        while len(self.buffer) >= 64:
            self._compress(self.buffer[:64])
            self.buffer = self.buffer[64:]

    def digest(self) -> bytes:
        """生成最终哈希值"""
        # 填充
        pad_len = 64 - (len(self.buffer) + 8) % 64
        padding = b'\x80' + b'\x00' * (pad_len - 1)
        self.update(padding)
        
        # 附加长度
        bit_length = self.length * 8
        self.update(struct.pack('>Q', bit_length))

        # 返回结果
        return struct.pack('>8I', *self.state)

# ---------------------------- 优化实现（T-table + SIMD） ----------------------------
try:
    import numpy as np
    from numba import jit, uint32

    # 预计算T-table（布尔函数+常量）
    FF_TABLE = np.zeros((2, 2**32), dtype=np.uint32)
    GG_TABLE = np.zeros((2, 2**32), dtype=np.uint32)
    for j in range(64):
        for x in range(256):
            for y in range(256):
                for z in range(256):
                    if j < 16:
                        FF_TABLE[0, x << 16 | y << 8 | z] = x ^ y ^ z
                        GG_TABLE[0, x << 16 | y << 8 | z] = x ^ y ^ z
                    else:
                        FF_TABLE[1, x << 16 | y << 8 | z] = (x & y) | (x & z) | (y & z)
                        GG_TABLE[1, x << 16 | y << 8 | z] = (x & y) | ((~x) & z)

    @jit(nopython=True)
    def _compress_optimized(state, block):
        """使用T-table优化的压缩函数"""
        # ... (类似_compress但使用查表)
        pass

    class SM3_Optimized(SM3):
        def _compress(self, block):
            _compress_optimized(self.state, block)

except ImportError:
    print("优化依赖未安装（numpy/numba），使用基础实现")

# ---------------------------- 长度扩展攻击验证 ----------------------------
def length_extension_attack():
    """SM3长度扩展攻击演示"""
    # 原始消息和哈希
    secret = b"secret"
    h = SM3().update(secret).digest()
    
    # 构造扩展
    append_data = b"append"
    original_length = len(secret)
    
    # 计算填充
    pad_len = 64 - (original_length + 1 + 8) % 64
    padding = b'\x80' + b'\x00' * (pad_len - 1) + struct.pack('>Q', original_length * 8)
    
    # 伪造哈希
    forged_hash = SM3().update(append_data).digest()
    print(f"攻击成功: {forged_hash == SM3().update(secret + padding + append_data).digest()}")

# ---------------------------- Merkle树实现 ----------------------------
class MerkleTree:
    def __init__(self, data: List[bytes]):
        self.leaves = [self._hash_leaf(d) for d in data]
        self.tree = self._build_tree(self.leaves)
    
    @staticmethod
    def _hash_leaf(data: bytes) -> bytes:
        """RFC6962叶子节点哈希"""
        return SM3().update(b'\x00' + data).digest()
    
    @staticmethod
    def _hash_node(left: bytes, right: bytes) -> bytes:
        """RFC6962内部节点哈希"""
        return SM3().update(b'\x01' + left + right).digest()
    
    def _build_tree(self, leaves: List[bytes]) -> List[List[bytes]]:
        """构建Merkle树"""
        tree = [leaves]
        while len(tree[-1]) > 1:
            level = []
            for i in range(0, len(tree[-1]), 2):
                left = tree[-1][i]
                right = tree[-1][i+1] if i+1 < len(tree[-1]) else tree[-1][i]
                level.append(self._hash_node(left, right))
            tree.append(level)
        return tree
    
    def get_root(self) -> bytes:
        """返回根哈希"""
        return self.tree[-1][0]
    
    def get_proof(self, index: int) -> List[bytes]:
        """生成存在性证明路径"""
        proof = []
        for level in self.tree[:-1]:
            sibling = index ^ 1
            if sibling < len(level):
                proof.append(level[sibling])
            index = index // 2
        return proof
    
    def verify_proof(self, leaf: bytes, proof: List[bytes], root: bytes) -> bool:
        """验证存在性证明"""
        current = leaf
        for node in proof:
            if hash(node) < hash(current):  # 确定顺序
                current = self._hash_node(node, current)
            else:
                current = self._hash_node(current, node)
        return current == root

# ---------------------------- 测试用例 ----------------------------
if __name__ == "__main__":
    # 基础哈希测试
    data = b"hello world"
    print("SM3哈希:", SM3().update(data).digest().hex())

    # 长度扩展攻击
    length_extension_attack()

    # 构建10万叶子节点的Merkle树
    leaves = [f"data{i}".encode() for i in range(100000)]
    mt = MerkleTree(leaves)
    print("Merkle根哈希:", mt.get_root().hex())

    # 存在性证明
    proof = mt.get_proof(12345)
    print("验证结果:", mt.verify_proof(mt.leaves[12345], proof, mt.get_root()))
