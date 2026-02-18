# Secure Query Simulation with RSA-AES Encrypted Channel

这是一个模拟 **加密数据库查询** 的演示项目。

**注意：** 本项目并未实现可实际使用的加密数据库查询，而是通过RSA密钥交换和AES加密通信构建了一个安全通道。

## 工作流程
![工作流程](/workflow.png "工作流程")
1. **RSA 密钥交换。** 客户端生成RSA密钥对，将公钥发送给服务器；服务器用该公钥加密自己生成的AES密钥并返回。
2. **AES 加密通信。** 后续所有查询和响应均使用协商好的AES密钥进行加密，保证数据机密性。

## 环境要求
- Python 3.6 及以上
- 依赖库：
  - pycryptodome
  - crypto

## 安装流程
1. 克隆或下载本项目代码
```bash
git clone
cd pir-simulation-main
```

2. 安装所需的第三方库：
```bash
pip install pycryptodome
pip install crypto
```

## 使用方法
直接运行主程序 *main.py*：
```bash
python main.py
```

程序将依次执行以下步骤：
1. 生成一个包含随机整数的模拟数据库。
2. 客户端生成 RSA 密钥对，并将公钥发送给服务器。
3. 服务器生成 AES 密钥，用客户端 RSA 公钥加密后返回。
4. 客户端解密得到 AES 密钥，安全通道建立。
5. 客户端用 AES 加密要查询的索引，发送给服务器。
6. 服务器解密索引，从数据库中取出对应记录，用 AES 加密后返回。
7. 客户端解密响应，得到查询结果，并与数据库真实值对比。

控制台将输出每一步的详细信息，包括密钥、明文、密文等，便于观察加密通信的全过程。

## 代码结构

- Server：模拟服务器，拥有数据库，处理客户端连接和查询请求。
  - __init__(database)：初始化数据库和加密工具。
  - connect(rsa_pub_key)：接收客户端RSA公钥，生成AES密钥并加密返回。
  - return_data(code)：解密查询索引，返回加密的记录。

- Client：模拟客户端，发起查询并处理响应。
  - __init__()：初始化加密工具。
  - connect_send_rsa()：生成RSA密钥对，返回公钥。
  - connect_receive_aes(aes_key_code)：解密并保存AES密钥。
  - send(database_id)：加密查询索引并发送。
  - receive(code)：解密服务器返回的数据。

- generate_database：生成随机整数列表作为数据库。

## 注意
1. 这不是真正可用的加密数据库查询，本项目仅用于演示加密通信的基本流程。
2. 代码中打印了RSA私钥，这是仅为演示目的，实际应用中绝不能泄露私钥。
3. 示例加密模块使用了ECB模式，不安全，请勿用于真实场景。实际应使用CBC或GCM等认证加密模式。

---

欢迎贡献和改进！ 如果你有任何问题或建议，请提交Issue或Pull Request。