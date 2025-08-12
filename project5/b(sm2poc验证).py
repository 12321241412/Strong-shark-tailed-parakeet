import hashlib
import secrets
from fastecdsa import curve, keys
from fastecdsa.point import Point
from fastecdsa.curve import secp256k1  # 用于ECDSA部分
import fastecdsa.ecdsa as ecdsa  # 用于ECDSA部分

# SM2参数
SM2_p = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
SM2_a = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
SM2_b = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
SM2_Gx = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
SM2_Gy = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
SM2_n = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7

# 创建SM2曲线
SM2_curve = curve.Curve(
    "SM2",
    SM2_p, SM2_a, SM2_b,
    SM2_n, SM2_Gx, SM2_Gy
)

# 创建基点G
SM2_G = Point(SM2_Gx, SM2_Gy, curve=SM2_curve)

# SM3哈希实现
def sm3_hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

# 计算ZA
def compute_za(user_id: bytes, public_key: Point) -> bytes:
    entla = len(user_id).to_bytes(2, 'big')
    a_bytes = SM2_a.to_bytes(32, 'big')
    b_bytes = SM2_b.to_bytes(32, 'big')
    gx_bytes = SM2_Gx.to_bytes(32, 'big')
    gy_bytes = SM2_Gy.to_bytes(32, 'big')
    xa_bytes = public_key.x.to_bytes(32, 'big')
    ya_bytes = public_key.y.to_bytes(32, 'big')
    
    za_data = entla + user_id + a_bytes + b_bytes + gx_bytes + gy_bytes + xa_bytes + ya_bytes
    return sm3_hash(za_data)

# SM2签名（修复：添加k参数）
def sm2_sign(private_key: int, msg: bytes, 
             user_id: bytes = b"1234567812345678", 
             k_value: int = None) -> tuple:
    """SM2签名，支持指定k值"""
    public_key = keys.get_public_key(private_key, SM2_curve)
    za = compute_za(user_id, public_key)
    e_input = za + msg
    e_hash = sm3_hash(e_input)
    e_int = int.from_bytes(e_hash, 'big') % SM2_n
    
    while True:
        # 允许外部指定k值
        if k_value is None:
            k_val = secrets.randbelow(SM2_n - 1) + 1
        else:
            k_val = k_value
        
        kG = k_val * SM2_G
        r = (e_int + kG.x) % SM2_n
        
        if r == 0 or r + k_val == SM2_n:
            if k_value is not None: 
                raise ValueError("固定k值导致无效签名")
            continue
            
        # 计算 (1 + dA)^-1 mod n
        inv = pow(1 + private_key, SM2_n - 2, SM2_n)  # 费马小定理求逆
        s = (inv * (k_val - r * private_key)) % SM2_n
        
        if s != 0:
            break
    
    return (r, s)

# SM2验签
def sm2_verify(public_key: Point, msg: bytes, signature: tuple, 
               user_id: bytes = b"1234567812345678") -> bool:
    r, s = signature
    
    # 检查签名值范围
    if not (1 <= r < SM2_n and 1 <= s < SM2_n):
        return False
    
    # 计算ZA
    za = compute_za(user_id, public_key)
    
    # 计算e = H(ZA || M)
    e_input = za + msg
    e_hash = sm3_hash(e_input)
    e_int = int.from_bytes(e_hash, 'big') % SM2_n
    
    # 计算t = (r + s) mod n
    t = (r + s) % SM2_n
    if t == 0:
        return False
    
    # 计算点 (x1', y1') = s * G + t * PA
    sG = s * SM2_G
    tPA = t * public_key
    x1_prime = sG + tPA
    
    # 计算R = (e' + x1') mod n
    R = (e_int + x1_prime.x) % SM2_n
    
    # 验证R == r
    return R == r

# ECDSA签名函数
def ecdsa_sign(private_key: int, msg: bytes, k_value: int = None) -> tuple:
    """ECDSA签名，支持指定k值"""
    # 计算消息哈希
    e_hash = hashlib.sha256(msg).digest()
    e_int = int.from_bytes(e_hash, 'big') % SM2_n
    
    # 生成或使用指定的k值
    if k_value is None:
        k_val = secrets.randbelow(SM2_n - 1) + 1
    else:
        k_val = k_value
    
    # 计算 k * G
    kG = k_val * SM2_G
    r = kG.x % SM2_n
    
    # 计算签名 s = (e + r*d) * k^{-1} mod n
    s = (e_int + r * private_key) * pow(k_val, -1, SM2_n) % SM2_n
    
    return (r, s), e_int

# POC验证部分  

def poc_reuse_k_same_user():
    """同一用户重用k导致私钥泄露"""
    # 生成密钥对
    private_key = keys.gen_private_key(SM2_curve)
    public_key = keys.get_public_key(private_key, SM2_curve)
    
    # 用户ID
    user_id = b"alice@example.com"
    
    # 固定随机数k
    k_fixed = secrets.randbelow(SM2_n - 1) + 1
    
    # 对两个不同消息使用相同k签名
    msg1 = b"Transfer $100 to Bob"
    r1, s1 = sm2_sign(private_key, msg1, user_id, k_value=k_fixed)  # 强制使用固定k
    
    msg2 = b"Transfer $500 to Eve"
    r2, s2 = sm2_sign(private_key, msg2, user_id, k_value=k_fixed)  # 重用相同k
    
    # 修正推导公式
    # 正确公式: dA = (s2 - s1) / (s1 - s2 + r1 - r2) mod n
    numerator = (s2 - s1) % SM2_n
    denominator = (s1 - s2 + r1 - r2) % SM2_n
    
    if denominator == 0:
        print("无法推导：分母为零")
        return
    
    # 计算私钥 dA = numerator / denominator mod n
    dA_recovered = (numerator * pow(denominator, -1, SM2_n)) % SM2_n
    
    # 验证推导结果
    print("\n同一用户重用k导致私钥泄露")
    print(f"真实私钥: {hex(private_key)}")
    print(f"推导私钥: {hex(dA_recovered)}")
    print(f"推导结果: {'成功' if dA_recovered == private_key else '失败'}")
    
    # 使用推导私钥验证签名
    test_msg = b"Test message"
    test_sig = sm2_sign(dA_recovered, test_msg, user_id)
    is_valid = sm2_verify(public_key, test_msg, test_sig, user_id)
    print(f"推导私钥签名验证: {'成功' if is_valid else '失败'}")

def poc_reuse_k_different_users():
    """不同用户重用k导致相互私钥破解"""
    # 生成两个用户的密钥对
    dA = keys.gen_private_key(SM2_curve)
    PA = keys.get_public_key(dA, SM2_curve)
    
    dB = keys.gen_private_key(SM2_curve)
    PB = keys.get_public_key(dB, SM2_curve)
    
    # 用户ID
    userA_id = b"alice@example.com"
    userB_id = b"bob@example.com"
    
    # 共享的随机数k
    k_shared = secrets.randbelow(SM2_n - 1) + 1
    
    # 用户A签名
    msgA = b"Message from Alice"
    rA, sA = sm2_sign(dA, msgA, userA_id, k_value=k_shared)
    
    # 用户B签名（使用相同k）
    msgB = b"Message from Bob"
    rB, sB = sm2_sign(dB, msgB, userB_id, k_value=k_shared)
    
    # 用户A推导用户B的私钥
    # 根据：sB = (1 + dB)^-1 * (k - rB * dB) mod n
    # => k = sB(1 + dB) + rB * dB
    # => dB = (k - sB) / (sB + rB) mod n
    numerator_B = (k_shared - sB) % SM2_n
    denominator_B = (sB + rB) % SM2_n
    
    if denominator_B == 0:
        print("无法推导用户B私钥：分母为零")
        dB_recovered = None
    else:
        dB_recovered = (numerator_B * pow(denominator_B, -1, SM2_n)) % SM2_n
    
    # 用户B推导用户A的私钥
    numerator_A = (k_shared - sA) % SM2_n
    denominator_A = (sA + rA) % SM2_n
    
    if denominator_A == 0:
        print("无法推导用户A私钥：分母为零")
        dA_recovered = None
    else:
        dA_recovered = (numerator_A * pow(denominator_A, -1, SM2_n)) % SM2_n
    
    print("\n不同用户重用k导致相互私钥破解")
    print(f"用户A真实私钥: {hex(dA)}")
    print(f"用户B推导的dA: {hex(dA_recovered) if dA_recovered is not None else 'N/A'}")
    if dA_recovered is not None:
        print(f"推导结果: {'成功' if dA_recovered == dA else '失败'}")
    
    print(f"\n用户B真实私钥: {hex(dB)}")
    print(f"用户A推导的dB: {hex(dB_recovered) if dB_recovered is not None else 'N/A'}")
    if dB_recovered is not None:
        print(f"推导结果: {'成功' if dB_recovered == dB else '失败'}")
    
    # 验证推导私钥
    if dA_recovered is not None:
        test_sig_A = sm2_sign(dA_recovered, b"Test A", userA_id)
        is_valid_A = sm2_verify(PA, b"Test A", test_sig_A, userA_id)
        print(f"推导dA签名验证: {'成功' if is_valid_A else '失败'}")
    
    if dB_recovered is not None:
        test_sig_B = sm2_sign(dB_recovered, b"Test B", userB_id)
        is_valid_B = sm2_verify(PB, b"Test B", test_sig_B, userB_id)
        print(f"推导dB签名验证: {'成功' if is_valid_B else '失败'}")

def poc_shared_k_ecdsa_sm2():
    """ECDSA与SM2共用k导致私钥泄露"""
    print("\n")
    print("ECDSA与SM2共用k导致私钥泄露")
    
    # 生成密钥对
    private_key = keys.gen_private_key(SM2_curve)
    public_key = keys.get_public_key(private_key, SM2_curve)
    
    # 用户ID
    user_id = b"user@example.com"
    
    # 共享的随机数k
    k_shared = secrets.randbelow(SM2_n - 1) + 1
    print(f"共享的随机数k: 0x{k_shared:x}")
    
    # ECDSA签名
    ecdsa_msg = b"ECDSA message"
    ecdsa_sig, e1 = ecdsa_sign(private_key, ecdsa_msg, k_value=k_shared)
    r1, s1 = ecdsa_sig
    print(f"\n[ECDSA签名]")
    print(f"消息: {ecdsa_msg}")
    print(f"r1: 0x{r1:x}")
    print(f"s1: 0x{s1:x}")
    print(f"e1: 0x{e1:x}")
    
    # SM2签名
    sm2_msg = b"SM2 message"
    r2, s2 = sm2_sign(private_key, sm2_msg, user_id, k_value=k_shared)
    print(f"\n[SM2签名]")
    print(f"消息: {sm2_msg}")
    print(f"r2: 0x{r2:x}")
    print(f"s2: 0x{s2:x}")
    
    # 推导私钥
    try:
        # 分子: s1*s2 - e1
        numerator = (s1 * s2 - e1) % SM2_n
        
        # 分母: r1 - s1*s2 - s1*r2
        denominator = (r1 - s1*s2 - s1*r2) % SM2_n
        
        if denominator == 0:
            raise ValueError("分母为零，无法推导私钥")
        
        # 私钥推导公式: d = (s1*s2 - e1) / (r1 - s1*s2 - s1*r2) mod n
        d_recovered = numerator * pow(denominator, -1, SM2_n) % SM2_n
        
        print(f"推导私钥: 0x{d_recovered:x}")
        print(f"真实私钥: 0x{private_key:x}")
        print(f"结果: {'成功' if d_recovered == private_key else '失败'}")
        
        # 验证推导私钥
        test_msg = b"Test message"
        test_sig = sm2_sign(d_recovered, test_msg, user_id)
        is_valid = sm2_verify(public_key, test_msg, test_sig, user_id)
        print(f"签名验证: {'成功' if is_valid else '失败'}")
        
    except ValueError as e:
        print(f"推导失败: {e}")

# 主函数  
if __name__ == "__main__":
    # 运行所有POC验证
    poc_reuse_k_same_user()
    poc_reuse_k_different_users()
    poc_shared_k_ecdsa_sm2()
