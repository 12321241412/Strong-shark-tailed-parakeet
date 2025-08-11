import socket
import json
import random
import hashlib
import threading
import time
import sys
from phe import paillier
from ecdsa import NIST256p, ellipticcurve

# 椭圆曲线参数配置（采用NIST256p标准曲线）
CURVE = NIST256p.curve
GENERATOR = NIST256p.generator
ORDER = NIST256p.order


def str_to_curve(s):
    """将字符串映射到椭圆曲线上的点"""
    # 哈希后取模，确保落在曲线参数范围内
    hash_bytes = hashlib.sha256(s.encode()).digest()
    x_coord = int.from_bytes(hash_bytes, 'big') % ORDER
    return x_coord * GENERATOR


def curve_point_to_dict(p):
    """椭圆曲线点序列化"""
    return {'x': hex(p.x()), 'y': hex(p.y())}


def dict_to_curve_point(data):
    """椭圆曲线点反序列化"""
    x = int(data['x'], 16)
    y = int(data['y'], 16)
    return ellipticcurve.Point(CURVE, x, y)


class ParticipantA:
    """参与方A（持有用户标识符集合）"""

    def __init__(self, user_ids):
        self.user_ids = user_ids
        self.private_key = random.randint(1, ORDER - 1)  # 随机生成私钥
        self.paillier_pub = None  # 存储参与方B的公钥

    def step1(self):
        """第一步：处理本地标识符并发送"""
        # 计算H(v_i)^k1，然后打乱顺序
        processed = [self.private_key * str_to_curve(uid) for uid in self.user_ids]
        random.shuffle(processed)
        return [curve_point_to_dict(p) for p in processed]

    def step3(self, b_points, c_points, encrypted_values):
        """第三步：计算交集并累加加密值"""
        # 反序列化接收的点
        b_list = [dict_to_curve_point(b) for b in b_points]
        c_list = [dict_to_curve_point(c) for c in c_points]

        # 计算E_j = k1 * C_j
        e_list = [self.private_key * c for c in c_list]

        # 查找交集并累加
        total = self.paillier_pub.encrypt(0)
        count = 0
        for idx, e in enumerate(e_list):
            if e in b_list:
                count += 1
                total += encrypted_values[idx]

        return {
            'sum_enc': str(total.ciphertext()),
            'count': count
        }

    def show_result(self, count):
        """展示本地结果"""
        print(f"参与方A：交集用户数为 {count}")


class ParticipantB:
    """参与方B（持有用户标识符及关联值）"""

    def __init__(self, user_data):
        self.user_data = user_data  # 格式：[(用户ID, 数值), ...]
        self.private_key = random.randint(1, ORDER - 1)  # 随机生成私钥
        # 生成Paillier密钥对
        self.paillier_pub, self.paillier_priv = paillier.generate_paillier_keypair()

    def step0(self):
        """初始步骤：发送公钥"""
        return {'pub_key_n': hex(self.paillier_pub.n)}

    def step2(self, a_points):
        """第二步：处理接收数据并返回"""
        # 处理A发送的点，计算B_i = k2 * A_i
        a_list = [dict_to_curve_point(a) for a in a_points]
        b_list = [self.private_key * a for a in a_list]
        random.shuffle(b_list)

        # 处理本地数据：计算C_j和加密值
        c_list = [self.private_key * str_to_curve(uid) for uid, _ in self.user_data]
        enc_values = [self.paillier_pub.encrypt(val) for _, val in self.user_data]

        # 保持C和加密值的对应关系并打乱
        combined = list(zip(c_list, enc_values))
        random.shuffle(combined)
        shuffled_c, shuffled_enc = zip(*combined)

        return {
            'b_list': [curve_point_to_dict(b) for b in b_list],
            'c_list': [curve_point_to_dict(c) for c in shuffled_c],
            'enc_values': [str(enc.ciphertext()) for enc in shuffled_enc]
        }

    def step4(self, data):
        """第四步：解密并展示结果"""
        # 还原加密值并解密
        enc_sum = paillier.EncryptedNumber(self.paillier_pub, int(data['sum_enc']))
        total = self.paillier_priv.decrypt(enc_sum)
        count = data['count']

        print(f"参与方B：交集用户数为 {count}，总数值为 {total}")
        return count


def start_server(port, data):
    """启动服务端（参与方B）"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('localhost', port))
        sock.listen(1)
        print(f"参与方B已启动，监听端口 {port}...")

        conn, addr = sock.accept()
        print(f"已连接：{addr}")

        # 初始化参与方B
        part_b = ParticipantB(data)

        # 发送公钥
        conn.sendall(json.dumps(part_b.step0()).encode())

        # 接收第一步数据
        a_data = json.loads(conn.recv(102400).decode())
        step2_res = part_b.step2(a_data['a_list'])
        conn.sendall(json.dumps(step2_res).encode())

        # 处理第三步数据并返回结果
        step3_data = json.loads(conn.recv(102400).decode())
        count = part_b.step4(step3_data)
        conn.sendall(str(count).encode())

        conn.close()
        sock.close()
    except Exception as e:
        print(f"服务端错误：{e}")
        sys.exit(1)


def start_client(port, ids):
    """启动客户端（参与方A）"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', port))

        # 初始化参与方A
        part_a = ParticipantA(ids)

        # 接收公钥
        pub_data = json.loads(sock.recv(102400).decode())
        part_a.paillier_pub = paillier.PaillierPublicKey(int(pub_data['pub_key_n'], 16))

        # 发送第一步数据
        step1_res = {'a_list': part_a.step1()}
        sock.sendall(json.dumps(step1_res).encode())

        # 处理第二步数据
        step2_data = json.loads(sock.recv(1024000).decode())
        enc_values = [paillier.EncryptedNumber(part_a.paillier_pub, int(enc))
                      for enc in step2_data['enc_values']]

        # 发送第三步结果
        step3_res = part_a.step3(step2_data['b_list'], step2_data['c_list'], enc_values)
        sock.sendall(json.dumps(step3_res).encode())

        # 接收并展示结果
        count = int(sock.recv(100).decode())
        part_a.show_result(count)
        sock.close()
    except Exception as e:
        print(f"客户端错误：{e}")
        sys.exit(1)


if __name__ == "__main__":
    # 测试数据
    user_ids_a = ["user_001", "user_002", "user_003", "user_005"]
    user_data_b = [("user_001", 150), ("user_002", 200), ("user_004", 300), ("user_003", 250)]

    # 预期结果：交集为user_001, user_002, user_003 → 数量3，总和600
    port = random.randint(10000, 60000)

    # 启动服务端线程
    server_thread = threading.Thread(
        target=start_server,
        args=(port, user_data_b),
        daemon=True
    )
    server_thread.start()
    time.sleep(1)  # 等待服务端启动

    # 启动客户端
    start_client(port, user_ids_a)

    # 等待服务端处理完成
    server_thread.join(timeout=5)
    if server_thread.is_alive():
        print("服务端未正常结束")