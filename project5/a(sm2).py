import hashlib
import secrets
from fastecdsa import curve, keys
from fastecdsa.point import Point

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

# SM3哈希实现（简化版）
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

# SM2签名
def sm2_sign(private_key: int, msg: bytes, user_id: bytes = b"1234567812345678") -> tuple:
    public_key = keys.get_public_key(private_key, SM2_curve)
    za = compute_za(user_id, public_key)
    e_input = za + msg
    e_hash = sm3_hash(e_input)
    e_int = int.from_bytes(e_hash, 'big') % SM2_n
    
    while True:
        k = secrets.randbelow(SM2_n - 1) + 1
        # 正确的点乘法：k * G
        kG = k * SM2_G  # 使用 * 运算符进行标量乘法
        
        r = (e_int + kG.x) % SM2_n
        
        if r == 0 or r + k == SM2_n:
            continue
            
        # 计算 (1 + dA)^-1 mod n
        inv = pow(1 + private_key, SM2_n - 2, SM2_n)  # 费马小定理求逆
        s = (inv * (k - r * private_key)) % SM2_n
        
        if s != 0:
            break
    
    return (r, s)

# SM2验签
def sm2_verify(public_key: Point, msg: bytes, signature: tuple, user_id: bytes = b"1234567812345678") -> bool:
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
    # 使用 * 运算符进行标量乘法
    sG = s * SM2_G
    tPA = t * public_key
    
    # 点加法
    x1_prime = sG + tPA
    
    # 计算R = (e' + x1') mod n
    R = (e_int + x1_prime.x) % SM2_n
    
    # 验证R == r
    return R == r

# 测试
if __name__ == "__main__":
    # 1. 密钥生成
    private_key = keys.gen_private_key(SM2_curve)
    public_key = keys.get_public_key(private_key, SM2_curve)
    
    print(f"私钥: {hex(private_key)}")
    print(f"公钥: ({hex(public_key.x)}, {hex(public_key.y)})")
    
    # 2. 签名
    message = b"Hello, SM2!"
    signature = sm2_sign(private_key, message)
    print(f"\n签名(r, s): ({hex(signature[0])}, {hex(signature[1])})")
    
    # 3. 验签
    is_valid = sm2_verify(public_key, message, signature)
    print(f"\n验签结果: {'成功' if is_valid else '失败'}")
    
    # 4. 篡改消息后验签
    is_valid_tampered = sm2_verify(public_key, b"Tampered message", signature)
    print(f"篡改消息后验签: {'成功' if is_valid_tampered else '失败'}")
    
    # 5. 使用错误公钥验签
    wrong_private_key = keys.gen_private_key(SM2_curve)
    wrong_public_key = keys.get_public_key(wrong_private_key, SM2_curve)
    is_valid_wrong_key = sm2_verify(wrong_public_key, message, signature)
    print(f"错误公钥验签: {'成功' if is_valid_wrong_key else '失败'}")
