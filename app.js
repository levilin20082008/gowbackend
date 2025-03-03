const express = require('express');
const fs = require('fs');
const path = require('path');
const properties = require('properties');
const jwt = require('jsonwebtoken');
const ethUtil = require('ethereumjs-util');

const cors = require('cors');
const app = express();
const port = 3020;
const usersDir = path.join(__dirname, 'users');
const caishenDir = path.join(__dirname, 'caishen');
const caishenFilePath = path.join(caishenDir, 'caishen.properties');
const secretKey = 'your_secret_key'; // 用于签名 JWT 的密钥

// 确保 users 和 caishen 目录存在
if (!fs.existsSync(usersDir)) {
  fs.mkdirSync(usersDir);
}
if (!fs.existsSync(caishenDir)) {
  fs.mkdirSync(caishenDir);
}

app.use(cors());

// 缓存用户信息
const userCache = {};
// 存储已登出的 JWT 令牌黑名单
const tokenBlacklist = new Set();

// 读取用户信息文件
function readUserFile(username) {
  const filePath = path.join(usersDir, `${username}.prop`);
  if (fs.existsSync(filePath)) {
    const data = fs.readFileSync(filePath, 'utf8');
    return properties.parse(data);
  }
  return null;
}

// 写入用户信息文件
function writeUserFile(username, userData) {
  const filePath = path.join(usersDir, `${username}.prop`);
  const data = properties.stringify(userData);
  fs.writeFileSync(filePath, data, 'utf8');
  userCache[username] = userData;
}

// 读取财神信息文件
function readCaishenFile() {
  if (fs.existsSync(caishenFilePath)) {
    const data = fs.readFileSync(caishenFilePath, 'utf8');
    return properties.parse(data);
  }
  return { level: 0, grow: 0 };
}

// 写入财神信息文件
function writeCaishenFile(caishenData) {
  const data = properties.stringify(caishenData);
  fs.writeFileSync(caishenFilePath, data, 'utf8');
}

// 中间件，解析 JSON 数据
app.use(express.json());

// 用户信息管理 API

// 创建用户
app.post('/users', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  if (readUserFile(username)) {
    return res.status(409).json({ error: 'User already exists' });
  }
  const userData = { username, password, wlpoints: 0 };
  writeUserFile(username, userData);
  res.status(201).json(userData);
});

// 获取用户信息
app.get('/users/:username', (req, res) => {
  const { username } = req.params;
  const userData = readUserFile(username);
  if (!userData) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.json(userData);
});

// 更新用户信息
app.put('/users/:username', (req, res) => {
  const { username } = req.params;
  const userData = readUserFile(username);
  if (!userData) {
    return res.status(404).json({ error: 'User not found' });
  }
  const updatedData = { ...userData, ...req.body };
  writeUserFile(username, updatedData);
  res.json(updatedData);
});

// 删除用户信息
app.delete('/users/:username', (req, res) => {
  const { username } = req.params;
  const filePath = path.join(usersDir, `${username}.prop`);
  if (fs.existsSync(filePath)) {
    fs.unlinkSync(filePath);
    delete userCache[username];
    res.status(204).send();
  } else {
    res.status(404).json({ error: 'User not found' });
  }
});

// 用户登录
app.post('/api/login', (req, res) => {
  const { walletAddress, signature, message } = req.body;
  console.log('Received request body:', { walletAddress, signature, message });

  // 验证签名
  const msgBuffer = Buffer.from(message, 'utf8');
  const msgHash = ethUtil.hashPersonalMessage(msgBuffer);
  const signatureParams = ethUtil.fromRpcSig(signature);
  const publicKey = ethUtil.ecrecover(msgHash, signatureParams.v, signatureParams.r, signatureParams.s);
  const address = ethUtil.bufferToHex(ethUtil.publicToAddress(publicKey));

  if (address.toLowerCase() === walletAddress.toLowerCase()) {
    // 生成 JWT
    const token = jwt.sign({ walletAddress }, secretKey, { expiresIn: '1h' });
    console.log('Generated JWT:', token);

    // 检查用户文件是否存在，如果不存在则创建
    const existingUser = readUserFile(walletAddress);
    if (!existingUser) {
      const userData = {
        username: walletAddress,
        wlpoints: 0 
      };
      writeUserFile(walletAddress, userData);
    }

    res.json({ success: true, token });
  } else {
    console.log('Signature verification failed. Expected address:', walletAddress, 'Recovered address:', address);
    res.status(401).json({ success: false, message: 'Invalid signature' });
  }
});

// 处理登出请求的接口
app.post('/api/logout', (req, res) => {
  const authHeader = req.headers['authorization'];
  const { walletAddress } = req.body;
  if (authHeader && walletAddress) {
    const token = authHeader.split(' ')[1];
    if (token) {
      tokenBlacklist.add(token);
      console.log(`User with wallet address ${walletAddress} logged out.`);
      return res.json({ success: true, message: 'Logout successful' });
    }
  }
  res.status(400).json({ success: false, message: 'Invalid token or wallet address' });
});

// 示例中间件，用于验证 JWT 并检查是否在黑名单中
app.use((req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (authHeader) {
    const token = authHeader.split(' ')[1];
    if (tokenBlacklist.has(token)) {
      return res.status(401).json({ success: false, message: 'Token has been revoked' });
    }
    jwt.verify(token, secretKey, (err, user) => {
      if (err) {
        return res.status(403).json({ success: false, message: 'Invalid token' });
      }
      req.user = user;
      next();
    });
  } else {
    req.user = null;
    next();
  }
});

// 获取用户当前登录状态
app.get('/users/:username/status', (req, res) => {
  const { username } = req.params;
  const token = req.headers['authorization']?.split(' ')[1];
  if (token && tokenBlacklist.has(token)) {
    return res.json({ message: 'User is logged out' });
  }
  res.json({ message: 'User status check' });
});

// 财神信息管理 API

// 获取财神信息
app.get('/caishen', (req, res) => {
  const caishenData = readCaishenFile();
  res.json(caishenData);
});

// 更新财神信息
app.put('/caishen', (req, res) => {
  const caishenData = readCaishenFile();
  const updatedData = { ...caishenData, ...req.body };
  writeCaishenFile(updatedData);
  res.json(updatedData);
});

// 新增的 API 接口，用于获取用户的 wlpoints 值
app.post('/api/getwlpoints', (req, res) => {
  const authHeader = req.headers['authorization'];
  const { walletAddress } = req.body;

  if (!walletAddress) {
    return res.status(400).json({ error: 'walletAddress is required' });
  }

  if (!authHeader) {
    return res.json({ wlpoints: 0 });
  }

  const token = authHeader.split(' ')[1];

  if (tokenBlacklist.has(token)) {
    return res.status(401).json({ success: false, message: 'Token has been revoked' });
  }

  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      return res.json({ wlpoints: 0 });
    }

    if (user.walletAddress!== walletAddress) {
      return res.json({ wlpoints: 0 });
    }

    const userData = readUserFile(walletAddress);
    if (!userData) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ wlpoints: userData.wlpoints });
  });
});

// 启动服务器
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
