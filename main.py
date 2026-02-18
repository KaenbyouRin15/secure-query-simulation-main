from utils.server import Server, Client, generate_database

# 生成模拟数据库
DB = generate_database(length=100)
DB_id = 40   # 客户端想要查询的索引

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