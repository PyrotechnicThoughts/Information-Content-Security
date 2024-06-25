import hmac
import hashlib

def tls_prf(secret, label, seed, output_len):
    """
    TLS PRF using SHA256
    """
    def p_hash(secret, seed, output_len):
        """
        Pseudo-random function P_hash
        """
        result = b''
        A = seed

        print(f"hash secret[{len(secret)}]:")
        print(secret.hex())

        print(f"hash seed[{len(seed)}]:")
        print(seed.hex())

        while len(result) < output_len:
            A = hmac.new(secret, A, hashlib.sha256).digest()
            result += hmac.new(secret, A + seed, hashlib.sha256).digest()
        return result[:output_len]

    return p_hash(secret, label + seed, output_len)

# 定义输入
pre_master_secret = bytes.fromhex("b2ffb548ce67a46e3a40994e11f9d5d7bdce9f3404b65b94710fea37fc6100ab734d79a0f84863c524d5da248b59d0a9")
label = b"key expansion"
client_random = bytes.fromhex("cc81884d0ee0848e9d7235d3644a89e0768bbf705d012f8792e337d4507a616b")
server_random = bytes.fromhex("81812dce57b03817d028ce00b6ac166f93b3d002d50a195dce222b5a65b30a59")

# 组合种子
seed = server_random + client_random

# 计算hash out, PRF out, key expansion
hash_out = tls_prf(pre_master_secret, label, seed, 104)
prf_out = hash_out  # 在这个例子中，我们将 hash_out 用作 prf_out
key_expansion = hash_out  # 同样，在这个例子中，我们将 hash_out 用作 key_expansion


if __name__ == "__main__":

    # 输出结果
    print("hash out[104]:")
    print(hash_out.hex())
    print("\nPRF out[104]:")
    print(prf_out.hex())
    print("\nkey expansion[104]:")
    print(key_expansion.hex())
