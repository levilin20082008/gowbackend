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
function createUser(reqBody) {
  const { username, password } = reqBody;
  if (!username || !password) {
    return { status: 400, body: { error: 'Username and password are required' } };
  }
  if (readUserFile(username)) {
    return { status: 409, body: { error: 'User already exists' } };
  }
  const userData = { username, password, wlpoints: 0 };
  writeUserFile(username, userData);
  return { status: 201, body: userData };
}

// 获取用户信息
function getUser(username) {
  const userData = readUserFile(username);
  if (!userData) {
    return { status: 404, body: { error: 'User not found' } };
  }
  return { status: 200, body: userData };
}

// 更新用户信息
function updateUser(username, reqBody) {
  const userData = readUserFile(username);
  if (!userData) {
    return { status: 404, body: { error: 'User not found' } };
  }
  const updatedData = { ...userData, ...reqBody };
  writeUserFile(username, updatedData);
  return { status: 200, body: updatedData };
}

// 删除用户信息
function deleteUser(username) {
  const filePath = path.join(usersDir, `${username}.prop`);
  if (fs.existsSync(filePath)) {
    fs.unlinkSync(filePath);
    delete userCache[username];
    return { status: 204, body: null };
  } else {
    return { status: 404, body: { error: 'User not found' } };
  }
}

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




// 财神信息管理 API

// 获取财神信息
function getCaishen() {
  const caishenData = readCaishenFile();
  return { status: 200, body: caishenData };
}

// 更新财神信息
function updateCaishen(reqBody) {
  const caishenData = readCaishenFile();
  const updatedData = { ...caishenData, ...reqBody };
  writeCaishenFile(updatedData);
  return { status: 200, body: updatedData };
}

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

app.post('/api/getuser', (req, res) => {
    const authHeader = req.headers['authorization'];
    const { walletAddress } = req.body;

    // 检查是否传入了 walletAddress
    if (!walletAddress) {
        return res.status(400).json({ error: 'walletAddress is required' });
    }

    // 检查是否提供了 Authorization 头
    if (!authHeader) {
        return res.status(401).json({ error: 'Authorization header is missing' });
    }

    const token = authHeader.split(' ')[1];

    // 检查 token 是否在黑名单中
    if (tokenBlacklist.has(token)) {
        return res.status(401).json({ error: 'Token has been revoked' });
    }

    // 验证 token
    jwt.verify(token, secretKey, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }

        // 检查 token 中的 walletAddress 是否与传入的一致
        if (user.walletAddress!== walletAddress) {
            return res.status(401).json({ error: 'Invalid wallet address in token' });
        }

        // 读取用户信息
        const userData = readUserFile(walletAddress);

        if (!userData) {
            return res.status(404).json({ error: 'User not found' });
        }

        // 返回用户的所有信息
        res.json(userData);
    });
});


app.post('/api/userBurnCenser', (req, res) => {
    const authHeader = req.headers['authorization'];
    const { walletAddress } = req.body;

    // 检查是否传入了 walletAddress
    if (!walletAddress) {
        return res.status(400).json({ success: false, error: 'walletAddress is required' });
    }

    // 检查是否提供了 Authorization 头
    if (!authHeader) {
        return res.status(401).json({ success: false, error: 'Authorization header is missing' });
    }

    const token = authHeader.split(' ')[1];

    // 检查 token 是否在黑名单中
    if (tokenBlacklist.has(token)) {
        return res.status(401).json({ success: false, error: 'Token has been revoked' });
    }

    // 验证 token
    jwt.verify(token, secretKey, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, error: 'Invalid token' });
        }

        // 检查 token 中的 walletAddress 是否与传入的一致
        if (user.walletAddress!== walletAddress) {
            return res.status(401).json({ success: false, error: 'Invalid wallet address in token' });
        }

        // 获取用户信息
        const userData = readUserFile(walletAddress);

        if (!userData) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }

        const timestamp = Date.now();
        if (!userData.lastBurnTime) {
            userData.lastBurnTime = timestamp;
            userData.wlpoints = (parseInt(userData.wlpoints) || 0) + 100;
            writeUserFile(walletAddress, userData);
            return res.json({ success: true, message: 'Successfully burned censer. Your wlpoints have been increased by 100.', wlpoints: userData.wlpoints });
        }

        const twoHoursInMillis = 2 * 60 * 60 * 1000;
        if (timestamp - userData.lastBurnTime >= twoHoursInMillis) {
            userData.wlpoints = (parseInt(userData.wlpoints) || 0) + 100;
            userData.lastBurnTime = timestamp;
            writeUserFile(walletAddress, userData);
            return res.json({ success: true, message: 'Successfully burned censer. Your wlpoints have been increased by 100.', wlpoints: userData.wlpoints });
        } else {
            return res.status(400).json({ success: false, error: 'You can only burn the censer once every two hours.' });
        }
    });
});





// 启动服务器
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
