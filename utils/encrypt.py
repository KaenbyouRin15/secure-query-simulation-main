import random
import math
from Crypto.Cipher import AES as aes_crypto
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA as rsa_crypto
from Crypto.Cipher import PKCS1_OAEP


# -------------------- 加密类 --------------------
class Encrypt(object):
    """
    加密、解密基类，定义加密解密接口，具体实现由子类完成。
    """
    def __init__(self):
        pass

    def generate_keys(self, seed):
        """生成密钥（需子类实现）"""
        pass

    def encrypt(self, message, key):
        """加密信息（需子类实现）"""
        pass

    def decrypt(self, code, key):
        """解密信息（需子类实现）"""
        pass


# # -------------------- RSA加密类 --------------------
# class RSA(Encrypt):
#     """RSA加密算法实现，继承自Encrypt基类。"""
#
#     def __init__(self):
#         super().__init__()
#
#     def generate_keys(self, p=100003, q=100019, seed=1):
#         """
#         生成RSA密钥对（公钥和私钥）。
#
#         :param p: 第一个大素数，默认29
#         :param q: 第二个大素数，默认31
#         :param seed: 随机数种子，用于重现生成元e的选择过程，默认1
#         :return: 公钥和私钥，均为字典格式，公钥包含n和e，私钥包含n和d
#         """
#         # 计算两个大素数的乘积 n
#         n = p * q
#
#         # 计算欧拉函数 φ(n) = (p-1)*(q-1)
#         m = (p - 1) * (q - 1)
#
#         # 设置随机种子，确保可重现性
#         random.seed = seed
#
#         # 生成所有可能的生成元 e（2 到 m-1），并随机打乱顺序
#         e_list = [i for i in range(2, m)]
#         random.shuffle(e_list)
#
#         # 遍历打乱后的列表，找到第一个与 m 互质的数作为 e
#         e = 0
#         for e_test in e_list:
#             if math.gcd(m, e_test) == 1:
#                 e = e_test
#                 break
#         # 确保找到了合适的 e
#         assert e != 0, "Error: 无法获取正确的生成元 e"
#
#         # 计算 e 模 m 的乘法逆元 d，即满足 e*d ≡ 1 (mod m)
#         d = pow(e, -1, m)
#         # 验证 e*d 与 m 互质（实际满足逆元条件后必然互质，此处可省略，但保留断言作为双重检查）
#         assert math.gcd(e * d, m) == 1, "Error: 无法获取正确的生成元 e 与逆元 d"
#
#         # 构建公钥和私钥字典
#         public_key = {
#             "type": "public",   # 标识为公钥
#             "n": n,
#             "e": e
#         }
#         private_key = {
#             "type": "private",  # 标识为私钥
#             "n": n,
#             "d": d
#         }
#
#         return public_key, private_key
#
#     def encrypt(self, message, public_key):
#         """
#         使用公钥对消息进行RSA加密。
#
#         :param message: 待加密的整数（需小于n）
#         :param public_key: 公钥字典，包含type、n、e
#         :return: 加密后的整数密文
#         """
#         # 确保传入的是公钥
#         assert public_key["type"] == "public", "加密时未使用公钥"
#         n = public_key["n"]
#         e = public_key["e"]
#
#         # 计算密文 c = message^e mod n
#         code = pow(message, e, n)
#
#         return code
#
#     def decrypt(self, code, private_key):
#         """
#         使用私钥对密文进行RSA解密。
#
#         :param code: 待解密的整数密文
#         :param private_key: 私钥字典，包含type、n、d
#         :return: 解密后的整数明文
#         """
#         # 确保传入的是私钥
#         assert private_key["type"] == "private", "解密时未使用私钥"
#         n = private_key["n"]
#         d = private_key["d"]
#
#         # 计算明文 m = code^d mod n
#         message = pow(code, d, n)
#
#         return message


class RSA(Encrypt):
    """RSA加密算法实现，继承自Encrypt基类。"""

    def __init__(self, key_length=2048):
        super().__init__()

        self.key = rsa_crypto.generate(key_length)
        self.public_key = self.key.publickey()

    def generate_keys(self):
        """
        生成RSA密钥对（公钥和私钥）。

        :param p: 第一个大素数，默认29
        :param q: 第二个大素数，默认31
        :param seed: 随机数种子，用于重现生成元e的选择过程，默认1
        :return: 公钥和私钥，均为字典格式，公钥包含n和e，私钥包含n和d
        """

        private_key = self.key.export_key()
        public_key = self.public_key.export_key()

        return private_key, public_key


    def encrypt(self, plaintext: bytes, public_key) -> bytes:
        """
        使用公钥加密明文
        :param plaintext: 明文字符串
        :return: 加密后的字节串
        """
        rsakey = rsa_crypto.importKey(public_key)
        cipher = PKCS1_OAEP.new(rsakey)
        return cipher.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes, private_key) -> bytes:
        """
        使用私钥解密密文
        :param ciphertext: 密文字节串
        :return: 解密后的明文字符串
        """
        # assert private_key == self.key.export_key()

        cipher = PKCS1_OAEP.new(self.key)
        return cipher.decrypt(ciphertext)


# -------------------- AES加密类 --------------------
class AES(Encrypt):
    """AES加密算法实现（ECB模式），继承自Encrypt基类。"""

    def __init__(self, mode=aes_crypto.MODE_ECB):
        """
        初始化AES加密器，指定工作模式。

        :param mode: AES加密模式，默认ECB模式
        """
        super().__init__()
        self.mode = mode

    def generate_keys(self, key_length=16):
        """
        生成随机的AES密钥。

        :param key_length: 密钥长度（字节），默认为16（对应AES-128）
        :return: 随机生成的字节类型密钥
        """
        key = get_random_bytes(key_length)
        return key

    def encrypt(self, message, key):
        """
        使用AES加密消息。

        :param message: 待加密的字节串（长度需为16的倍数，因使用ECB模式）
        :param key: 字节类型的AES密钥
        :return: 加密后的字节串密文
        """
        # 创建AES加密对象，使用指定的模式和密钥
        aes_encrypt = aes_crypto.new(key, self.mode)

        # 执行加密（ECB模式下无需额外的IV，直接对明文分组加密）
        code = aes_encrypt.encrypt(message)

        return code

    def decrypt(self, code, key):
        """
        使用AES解密密文。

        :param code: 待解密的字节串密文（长度需为16的倍数）
        :param key: 字节类型的AES密钥
        :return: 解密后的字节串明文
        """
        # 创建AES解密对象（注意：new函数根据模式自动判断加密/解密，但这里用同一对象也可，因为方法名明确）
        aes_encrypt = aes_crypto.new(key, self.mode)

        # 执行解密
        message = aes_encrypt.decrypt(code)

        return message


if __name__ == "__main__":
    # 测试RSA（已注释，可取消注释进行测试）
    encrypt_method = RSA()
    # message = 527
    message = get_random_bytes(16)

    pub, priv = encrypt_method.generate_keys()
    print(f"密钥：{pub}, {priv}")

    print(f"加密前：{message}")

    code = encrypt_method.encrypt(message, pub)
    print(f"加密后：{code}")

    message_re = encrypt_method.decrypt(code, priv)
    print(f"解密后：{message_re}")


    # 测试AES
    encrypt_method = AES()
    message = b"12345678abcdefgh"   # 16字节，符合AES分组大小
    key = encrypt_method.generate_keys()
    print(f"密钥：{key}")

    print(f"加密前：{message}")

    code = encrypt_method.encrypt(message, key)
    print(f"加密后：{code}")

    message_re = encrypt_method.decrypt(code, key)
    print(f"解密后：{message_re}")