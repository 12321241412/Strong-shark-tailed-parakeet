

from ecdsa import SigningKey, NIST384p, VerifyingKey
from ecdsa.util import string_to_number, number_to_string
from ecdsa.numbertheory import inverse_mod
import hashlib

# 密钥生成 
sk = SigningKey.generate(curve=NIST384p)
vk = sk.verifying_key

# 获取曲线参数
curve = NIST384p
G = curve.generator
n = curve.order

# 获取私钥数值
d = sk.privkey.secret_multiplier

# 有漏洞的签名函数（固定k=1）
def insecure_sign(sk, message):
    h = hashlib.sha384(message).digest()
    e = string_to_number(h) % n
    k = 1  # 固定k值 - 致命漏洞
    
    # 计算签名 (r, s)
    R = k * G
    r = R.x() % n
    s = (inverse_mod(k, n) * (e + d * r)) % n
    
    # 编码签名
    return number_to_string(r, n) + number_to_string(s, n)

#修正后的伪造函数 
def forge_signature(vk, original_message, original_signature, target_message):
    curve = vk.curve
    n = curve.order
    
    # 分解原始签名 (r, s)
    r_bytes = original_signature[:48]  # NIST384p的r和s各为48字节
    s_bytes = original_signature[48:]
    r = string_to_number(r_bytes)
    s = string_to_number(s_bytes)
    
    # 计算消息哈希
    h_orig = hashlib.sha384(original_message).digest()
    e_orig = string_to_number(h_orig) % n
    
    h_target = hashlib.sha384(target_message).digest()
    e_target = string_to_number(h_target) % n
    
    # 正确推导：s = e_orig + d·r (mod n)
    # 因此：d·r = s - e_orig (mod n)
    dr = (s - e_orig) % n
    
    # 伪造新签名：s' = e_target + d·r (mod n)
    s_forge = (e_target + dr) % n
    
    # 构建伪造签名 (r保持不变)
    return r_bytes + number_to_string(s_forge, n)

# 原始消息
message = b"Hello, this is a test message!"

# 使用有漏洞的函数签名
signature = insecure_sign(sk, message)
print(f"Generated signature: {signature.hex()}")
print(f"Signature length: {len(signature)} bytes")

# 验证原始签名
is_valid = vk.verify(signature, message, hashlib.sha384)
print(f"Original signature valid: {is_valid}")

# 伪造新消息的签名
target_message = b"Transfer $1000000 to Attacker"
forged_signature = forge_signature(vk, message, signature, target_message)
print(f"\nForged signature: {forged_signature.hex()}")

# 验证伪造签名
try:
    is_forged_valid = vk.verify(forged_signature, target_message, hashlib.sha384)
    print(f"Forged signature valid: {is_forged_valid}")
    print(f"Successfully forged message: {target_message.decode()}")
except Exception as e:
    print(f"Forgery failed: {str(e)}")
