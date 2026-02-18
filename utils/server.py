import random
from Crypto.Cipher import AES as aes_crypto
from utils.encrypt import RSA, AES   # 导入自定义的RSA和AES加密工具类
import socket

# -------------------- 服务器类 --------------------
class Server:
    """
    模拟PIR服务器（实际为安全数据库查询服务器）。
    服务器拥有数据库（每条记录是一个整数），能够与客户端建立安全连接，
    并根据客户端加密的索引返回对应的加密记录。
    注意：此处并未实现真正的PIR协议，仅使用了RSA和AES进行加密通信。
    """
    def __init__(self, database):
        """
        初始化服务器实例。
        :param database: 列表，每个元素是一个整数，代表一条数据库记录。
        """
        self.database = database
        self.num_records = len(database)

        # 创建RSA和AES工具对象
        self.rsa = RSA()
        self.aes = AES()

        self.rsa_pub_key = None   # 存储客户端的RSA公钥（由connect方法传入）
        self.aes_key = None       # 服务器生成的AES密钥，用于后续通信

    def connect(self, rsa_pub_key):
        """
        与客户端建立连接：接收客户端的RSA公钥，生成AES密钥并用RSA公钥加密后返回。
        :param rsa_pub_key: 客户端的RSA公钥（明文）
        :return: 用RSA公钥加密后的AES密钥（字节串）
        """
        # 保存客户端的RSA公钥
        self.rsa_pub_key = rsa_pub_key
        print(f"\n[服务器] 收到客户端的RSA公钥: {rsa_pub_key.hex()[:50]}...")  # 打印公钥前50字符

        # 生成一个AES密钥（通常为16/24/32字节）
        self.aes_key = self.aes.generate_keys()
        print(f"[服务器] 生成AES密钥: {self.aes_key.hex()}")

        # 使用RSA公钥加密AES密钥，准备发送给客户端
        aes_key_code = self.rsa.encrypt(self.aes_key, rsa_pub_key)
        print(f"[服务器] 用RSA公钥加密AES密钥后得到密文: {aes_key_code.hex()[:50]}...")
        return aes_key_code

    def return_data(self, code):
        """
        处理客户端发来的加密索引，解密后从数据库取出对应记录，再加密返回。
        :param code: 客户端用AES加密的索引数据（字节串）
        :return: 用AES加密的数据库记录（字节串）
        """
        print(f"\n[服务器] 收到客户端发来的加密查询: {code.hex()}")
        # 先用AES密钥解密客户端消息，得到索引（字符串形式）
        decrypted = self.aes.decrypt(code, self.aes_key)
        message = decrypted.decode('utf-8')
        database_id = int(message)   # 转换为整数索引
        print(f"[服务器] 解密得到查询索引: {database_id} (明文消息: '{message}')")

        # 根据索引获取数据库记录，并格式化为与AES块大小相同的字符串（补零）
        data_plain = str(self.database[database_id]).zfill(aes_crypto.block_size)
        print(f"[服务器] 从数据库取出记录: {self.database[database_id]}, 填充后明文: '{data_plain}'")
        # 加密数据后返回给客户端
        encrypted_data = self.aes.encrypt(data_plain.encode('utf-8'), self.aes_key)
        print(f"[服务器] 加密记录得到密文: {encrypted_data.hex()}")
        return encrypted_data


# -------------------- 客户端类 --------------------
class Client:
    """
    模拟PIR客户端（实际为安全数据库查询客户端）。
    客户端知道数据库中的记录总数，想要检索索引为idx的记录。
    客户端与服务器建立安全连接，发送加密的查询索引，并解密服务器的响应。
    """
    def __init__(self):
        """
        初始化客户端实例。
        """
        self.rsa = RSA()
        self.aes = AES()

        self.rsa_pub_key = None   # 客户端生成的RSA公钥
        self.rsa_priv_key = None  # 客户端生成的RSA私钥（用于解密服务器发来的加密AES密钥）
        self.aes_key = None       # 从服务器获取的AES密钥（解密后）

    def connect_send_rsa(self):
        """
        第一步：生成RSA密钥对，并将公钥以明文形式发送给服务器。
        :return: RSA公钥（可用于加密）
        """
        # 生成RSA密钥对
        self.rsa_pub_key, self.rsa_priv_key = self.rsa.generate_keys()
        print(f"\n[客户端] 生成RSA密钥对")
        print(f"[客户端] RSA公钥: {self.rsa_pub_key.hex()[:50]}...")
        print(f"[客户端] RSA私钥: {self.rsa_priv_key.hex()[:50]}...")  # 演示环境打印私钥，实际不应打印
        # 明文发送RSA公钥（实际网络传输中需序列化，此处直接返回）
        return self.rsa_pub_key

    def connect_receive_aes(self, aes_key_code):
        """
        第二步：接收服务器返回的加密AES密钥，用本地RSA私钥解密并保存。
        :param aes_key_code: 用RSA公钥加密后的AES密钥（字节串）
        """
        print(f"\n[客户端] 收到服务器返回的加密AES密钥: {aes_key_code.hex()[:50]}...")
        # 使用RSA私钥解密得到AES密钥
        self.aes_key = self.rsa.decrypt(aes_key_code, self.rsa_priv_key)
        print(f"[客户端] 用RSA私钥解密得到AES密钥: {self.aes_key.hex()}")

    def send(self, database_id):
        """
        发送查询索引：将整数索引格式化为定长字符串，再用AES加密后发送。
        :param database_id: 要查询的数据库记录索引
        :return: AES加密后的索引数据（字节串）
        """
        print(f"\n[客户端] 准备查询索引: {database_id}")
        # 将索引转换为字符串，并填充至AES块大小（保证加密数据长度符合要求）
        message = str(database_id).zfill(aes_crypto.block_size)
        print(f"[客户端] 填充后的明文: '{message}' (长度 {len(message)} 字节)")
        # 用AES密钥加密并返回
        encrypted = self.aes.encrypt(message.encode('utf-8'), self.aes_key)
        print(f"[客户端] AES加密后的查询密文: {encrypted.hex()}")
        return encrypted

    def receive(self, code):
        """
        接收服务器返回的加密数据，用AES解密后返回原始字符串。
        :param code: AES加密的数据（字节串）
        :return: 解密后的字符串
        """
        print(f"\n[客户端] 收到服务器返回的加密数据: {code.hex()}")
        decrypted = self.aes.decrypt(code, self.aes_key).decode('utf-8')
        print(f"[客户端] AES解密得到明文: '{decrypted}'")
        return decrypted


def generate_database(length=16):
    """
    生成一个随机整数列表作为模拟数据库。
    :param length: 数据库记录条数，默认为16
    :return: 包含随机整数的列表
    """
    database = []
    for _ in range(length):
        database.append(random.randint(0, 100))
    return database


if __name__ == "__main__":
    # 生成模拟数据库
    DB = generate_database()
    DB_id = 5   # 客户端想要查询的索引

    print("=" * 60)
    print("初始化数据库")
    print(f"数据库内容: {DB}")
    print(f"客户端想要查询的索引: {DB_id}")
    print("=" * 60)

    # 创建服务器和客户端实例
    server = Server(DB)
    client = Client()

    # ---------- 建立安全连接 ----------
    print("\n--- 阶段1: 建立安全连接 (RSA密钥交换) ---")
    # 1. 客户端发送RSA公钥
    client_rsa_pub = client.connect_send_rsa()
    # 2. 服务器接收公钥，生成AES密钥并加密返回
    server_enc_aes = server.connect(client_rsa_pub)
    # 3. 客户端解密得到AES密钥，完成连接建立
    client.connect_receive_aes(server_enc_aes)

    # ---------- 安全数据传输 ----------
    print("\n--- 阶段2: 加密查询与响应 ---")
    # 客户端用AES加密查询索引并发送
    encrypted_query = client.send(DB_id)
    # 服务器处理请求，返回加密的记录
    encrypted_response = server.return_data(encrypted_query)
    # 客户端解密服务器响应，得到查询结果
    result_str = client.receive(encrypted_response)
    result = int(result_str)

    print("\n" + "=" * 60)
    print("最终结果对比")
    print(f"客户端解密得到的数据: {result}")
    print(f"数据库中实际的数据: {DB[DB_id]}")
    print(f"查询成功: {result == DB[DB_id]}")
    print("=" * 60)