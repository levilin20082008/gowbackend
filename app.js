const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const properties = require('properties');
const jwt = require('jsonwebtoken');
const ethUtil = require('ethereumjs-util');
const cors = require('cors');
const axios = require('axios'); // 添加axios导入
const app = express();
const port = 80;
const usersDir = path.join(__dirname, 'users');
const caishenDir = path.join(__dirname, 'caishen');
const caishenFilePath = path.join(caishenDir, 'caishen.properties');
// 添加wencaishen相关目录定义
const wencaishenDir = path.join(__dirname, 'wencaishen');
const wencaishenUserInfoDir = path.join(wencaishenDir, 'userinfo');
const secretKey = 'your_secret_key'; // 用于签名 JWT 的密钥

// 确保 users 和 caishen 目录存在
if (!fs.existsSync(usersDir)) {
  fs.mkdirSync(usersDir);
}
if (!fs.existsSync(caishenDir)) {
  fs.mkdirSync(caishenDir);
}
// 确保wencaishen和userinfo目录存在
if (!fs.existsSync(wencaishenDir)) {
  fs.mkdirSync(wencaishenDir);
}
if (!fs.existsSync(wencaishenUserInfoDir)) {
  fs.mkdirSync(wencaishenUserInfoDir);
}

// 删除第一个storage声明（第26-44行左右的代码）

// 从以下代码开始删除
// 将第一个storage声明重命名为avatarStorage
// 配置文件上传存储
const avatarStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    // 从请求参数中获取userId
    const userId = req.body.userId || req.query.userId;
    if (!userId) {
      return cb(new Error('userId is required'));
    }
    
    const userDir = path.join(wencaishenUserInfoDir, userId);
    // 确保用户目录存在
    if (!fs.existsSync(userDir)) {
      fs.mkdirSync(userDir, { recursive: true });
    }
    cb(null, userDir);
  },
  filename: function (req, file, cb) {
    // 使用固定的文件名 'avatar.png'
    cb(null, 'avatar.png');
  }
});

// 创建multer实例，相应地更新storage引用为avatarStorage
const upload = multer({
  storage: avatarStorage,
  // 限制文件大小为10MB
  limits: { fileSize: 10 * 1024 * 1024 },
  // 只接受图片文件
  fileFilter: function (req, file, cb) {
    const filetypes = /jpeg|jpg|png|gif/;
    const mimetype = filetypes.test(file.mimetype);
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    
    if (mimetype && extname) {
      return cb(null, true);
    }
    cb(new Error('Only images are allowed!'));
  }
});

// 保留第二个storage声明不变
// 配置文件上传存储
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    // 从URL查询参数中获取userId
    const userId = req.query.userId;
    if (!userId) {
      return cb(new Error('userId is required as query parameter'));
    }
    
    const userDir = path.join(wencaishenUserInfoDir, userId);
    // 确保用户目录存在
    if (!fs.existsSync(userDir)) {
      fs.mkdirSync(userDir, { recursive: true });
    }
    cb(null, userDir);
  },
filename: function (req, file, cb) {
    // 使用固定的文件名 'avatar.png'
    cb(null, 'avatar.png');
  }
});

// 创建multer实例
// 将upload变量重命名为avatarUpload
// 创建multer实例
const avatarUpload = multer({
  storage: storage,
  // 限制文件大小为10MB
  limits: { fileSize: 10 * 1024 * 1024 },
  // 只接受图片文件
  fileFilter: function (req, file, cb) {
    const filetypes = /jpeg|jpg|png|gif/;
    const mimetype = filetypes.test(file.mimetype);
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    
    if (mimetype && extname) {
      return cb(null, true);
    }
    cb(new Error('Only images are allowed!'));
  }
});




// 添加OPTIONS请求处理中间件
// 自定义CORS中间件 - 更直接、更可靠的实现方式
app.use((req, res, next) => {
  // 允许所有来源
  res.setHeader('Access-Control-Allow-Origin', '*');
  
  // 允许的HTTP方法
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
  
  // 允许的请求头
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  
  // 允许凭证(Cookie等)
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  
  // 暴露额外的响应头
  res.setHeader('Access-Control-Expose-Headers', 'Access-Control-Allow-Origin');
  
  // 预检请求缓存时间(秒)
  res.setHeader('Access-Control-Max-Age', '86400');
  
  // 处理预检请求
  if (req.method === 'OPTIONS') {
    // 对于OPTIONS请求，直接返回200状态码
    return res.status(200).end();
  }
  
  next();
});

// 移除下面这行，因为我们的自定义中间件已经处理了OPTIONS请求
// app.options('*', cors());


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

// 在app.listen之前添加以下代码（大约在第800行左右）


// 添加/getLastCenserLog API接口
app.get('/getLastCenserLog', async (req, res) => {
  try {
    // 从查询参数中获取num参数，默认为3条
    let num = parseInt(req.query.num, 3);
    
    // 验证num参数
    if (isNaN(num) || num <= 0) {
      num = 3; // 默认返回3条
    } else if (num > 1000) {
      // 限制最大返回条数，防止性能问题
      return res.status(400).json({
        success: false,
        error: 'Number of logs requested cannot exceed 1000'
      });
    }
    
    // 定义日志文件路径
    const logsDir = path.join(wencaishenDir, 'logs');
    const logFilePath = path.join(logsDir, 'censer.log');
    
    // 检查日志文件是否存在
    if (!fs.existsSync(logFilePath)) {
      return res.json({
        success: true,
        logs: [],
        message: 'Log file does not exist'
      });
    }
    
    // 读取日志文件内容
    const logContent = fs.readFileSync(logFilePath, 'utf8');
    
    // 按行分割日志，过滤空行
    let lines = logContent.split('\n').filter(line => line.trim() !== '');
    
    // 获取最后num条日志
    const lastLines = lines.slice(-num);
    
    // 去除每条日志中的时间戳信息（格式：[timestamp] message）
    const processedLogs = lastLines.map(line => {
      // 使用正则表达式匹配并移除时间戳
      const match = line.match(/^\[(.*?)\]\s*(.*)$/);
      if (match && match[2]) {
        return match[2]; // 返回去除时间戳后的日志内容
      }
      return line; // 如果格式不符合预期，返回原始行
    });
    
    // 返回处理后的日志数组
    return res.json({
      success: true,
      logs: processedLogs,
      total: processedLogs.length,
      requested: num
    });
  } catch (error) {
    console.error('[GET_LAST_CENSER_LOG] Error reading log file:', error);
    return res.status(500).json({
      success: false,
      error: error.message || 'Internal server error'
    });
  }
});


// 添加/logCenser API接口
app.post('/logCenser', async (req, res) => {
  try {
    // 从请求体中获取log参数
    const { log } = req.body;
    
    // 验证请求参数
    if (!log || typeof log !== 'string') {
      return res.status(400).json({
        success: false,
        error: 'log parameter is required and must be a string'
      });
    }
    
    // 定义日志文件路径
    const logsDir = path.join(wencaishenDir, 'logs');
    const logFilePath = path.join(logsDir, 'censer.log');
    
    // 确保logs目录存在
    if (!fs.existsSync(logsDir)) {
      fs.mkdirSync(logsDir, { recursive: true });
      console.log(`[LOG_CENSER] Created logs directory: ${logsDir}`);
    }
    
    // 格式化日志条目，添加时间戳
    const timestamp = new Date().toISOString();
    const logEntry = `[${timestamp}] ${log}\n`;
    
    // 将日志追加到文件
    fs.appendFileSync(logFilePath, logEntry, 'utf8');
    console.log(`[LOG_CENSER] Log entry added successfully`);
    
    // 返回成功响应
    return res.json({
      success: true,
      message: 'Log entry added successfully',
      logLength: log.length
    });
  } catch (error) {
    console.error(`[LOG_CENSER] Error writing log:`, error);
    return res.status(500).json({
      success: false,
      error: error.message || 'Internal server error'
    });
  }
});

// 添加/getuser API接口
app.get('/getuser', async (req, res) => {
  const { userId } = req.query;
  
  // 验证请求参数
  if (!userId) {
    return res.status(400).json({ success: false, error: 'userId is required' });
  }
  
  try {
    const userDir = path.join(wencaishenUserInfoDir, userId);
    const userPropFile = path.join(userDir, 'user.prop');
    
    // 检查用户是否存在
    if (!fs.existsSync(userPropFile)) {
      // 如果用户不存在，先调用createWenCaishenUser创建用户
      console.log(`User ${userId} not found, creating new user...`);
      await createWenCaishenUser(userId);
    }
    
    // 读取用户属性文件
    const data = fs.readFileSync(userPropFile, 'utf8');
    const userData = properties.parse(data);
    
    // 创建完整的用户信息对象
    // 第395行左右：在getuser接口中添加userface检查逻辑
    const completeUserInfo = {
      userId: userId,
      username: userData.username,
      // 检查userface是否存在或为空字符串，如果是则使用默认头像
      userface: userData.userface && userData.userface.trim() !== '' ? userData.userface : '/wencaishen/head.png',
      // 功德分
      gpoint: userData.gpoint || 0,
    };
    
    return res.json({ success: true, data: completeUserInfo });
} catch (error) {
    console.error('Error getting user information:', error);
return res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// 添加/getExistUser API接口
app.get('/getExistUser', async (req, res) => {
  const { userId } = req.query;
  
  // 验证请求参数
  if (!userId) {
    return res.status(400).json({ success: false, error: 'userId is required' });
  }
  
  try {
    const userDir = path.join(wencaishenUserInfoDir, userId);
    const userPropFile = path.join(userDir, 'user.prop');
    
    // 检查用户是否存在
    if (!fs.existsSync(userPropFile)) {
      // 如果用户不存在，返回错误信息
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    
    // 读取用户属性文件
    const data = fs.readFileSync(userPropFile, 'utf8');
    const userData = properties.parse(data);
    
    // 创建完整的用户信息对象
    // 第395行左右：在getuser接口中添加userface检查逻辑
    const completeUserInfo = {
      userId: userId,
      username: userData.username,
      // 检查userface是否存在或为空字符串，如果是则使用默认头像
      userface: userData.userface && userData.userface.trim() !== '' ? userData.userface : '/wencaishen/head.png',
      // 功德分
      gpoint: userData.gpoint || 0,
    };
    
    return res.json({ success: true, data: completeUserInfo });
} catch (error) {
    console.error('Error getting user information:', error);
return res.status(500).json({ success: false, error: 'Internal server error' });
  }
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





// 生成武侠风格用户名（四字以内）
// 在文件顶部添加axios导入
// 修改generateWuxiaUsername函数为异步函数，调用豆包API
async function generateWuxiaUsername() {
  try {
    // 豆包API的配置信息
    const apiKey = '111903e8-ac9f-4fd5-8122-072e3223d4c8'; // 请替换为实际的API密钥
    const apiEndpoint = 'https://ark.cn-beijing.volces.com/api/v3/chat/completions'; // 正确的端点地址
    
    // 调用豆包API生成武侠风格用户名
    const response = await axios.post(apiEndpoint, {
      model: 'deepseek-v3-250324', // 修改为官方示例中正确的模型名称
      messages: [
        {
          role: 'system',
          content: '你是一位佛教小说作家，请为用户生成一个四字以内的佛教修行风格的用户名'
        },
        {
          role: 'user',
          content: '请生成一个2-4字的佛教修行风格的用户名，只返回用户名本身，不要包含其他解释文字'
        }
      ]
    }, {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`
      }
    });
    
    // 从API响应中提取用户名
    let username = response.data.choices[0].message.content.trim();
    
    // 确保用户名长度在2-4个字符之间
    if (username.length < 2) {
      username = username + '生'; // 添加后缀
    } else if (username.length > 4) {
      username = username.substring(0, 4); // 截取前4个字符
    }
    
    return username;
  } catch (error) {
    console.error('调用豆包API失败:', error);

    // 修复：移除"豆包失败了"的return语句，确保备用方案能够执行
    // 当API调用失败时，使用本地备用方案生成用户名
    const prefixes = ['龙', '虎', '凤', '云', '剑', '刀', '风', '雨', '雷', '电', '金', '木', '水', '火', '土'];
    const middles = ['飞', '天', '行', '空', '霸', '王', '侠', '客', '圣', '仙', '神', '魔', '鬼', '怪'];
    const suffixes = ['子', '生', '士', '客', '侠', '翁', '姑', '婆', '童', '儿'];
    
    // 随机选择长度（2-4字）
    const length = Math.floor(Math.random() * 3) + 2;
    let username = '';
    
    // 生成用户名
    if (length === 2) {
      username = prefixes[Math.floor(Math.random() * prefixes.length)] + 
                 suffixes[Math.floor(Math.random() * suffixes.length)];
    } else if (length === 3) {
      username = prefixes[Math.floor(Math.random() * prefixes.length)] + 
                 middles[Math.floor(Math.random() * middles.length)] + 
                 suffixes[Math.floor(Math.random() * suffixes.length)];
    } else {
      username = prefixes[Math.floor(Math.random() * prefixes.length)] + 
                 prefixes[Math.floor(Math.random() * prefixes.length)] + 
                 middles[Math.floor(Math.random() * middles.length)] + 
                 suffixes[Math.floor(Math.random() * suffixes.length)];
    }
    
    return username;
  }
}

// createWenCaishenUser函数已经是异步函数，不需要修改
// 修复2：在createWenCaishenUser函数中添加await关键字
async function createWenCaishenUser(userId) {
  const userDir = path.join(wencaishenUserInfoDir, userId);
  const userPropFile = path.join(userDir, 'user.prop');
  
  // 检查用户是否已存在
  if (fs.existsSync(userPropFile)) {
    return { exists: true, userDir, userPropFile };
  }
  
  // 创建用户目录
  if (!fs.existsSync(userDir)) {
    fs.mkdirSync(userDir);
  }
  
  // 生成用户名（添加await关键字等待异步函数完成）
  const username = await generateWuxiaUsername();
  
  // 创建user.prop文件
  const userData = {
    username: username,
    // 修改为指向wencaishen目录的head.png
    // userface: '/wencaishen/head.png'
  };
  
  const data = properties.stringify(userData);
  fs.writeFileSync(userPropFile, data, 'utf8');
  
  return { exists: false, userDir, userPropFile, username };
}

// 添加/createuser API接口
app.post('/createuser', async (req, res) => {
  const { userId } = req.body;
  
  // 验证请求参数
  if (!userId) {
    return res.status(400).json({ success: false, error: 'userId is required' });
  }
  
try {
    // 创建用户
    const result = await createWenCaishenUser(userId);
    
    if (result.exists) {
      // 用户已存在
      return res.json({ success: true, message: 'User already exists', userId });
    } else {
      // 用户创建成功
      return res.json({ success: true, message: 'User created successfully', userId, username: result.username });
    }
  } catch (error) {
    console.error('Error creating user:', error);
    return res.status(500).json({ success: false, error: 'Internal server error' });
  }
});
// 配置文件上传存储
// 第81行左右：将第二个storage变量重命名为avatarStorageConfig
const avatarStorageConfig = multer.diskStorage({
  destination: function (req, file, cb) {
    // 从URL查询参数中获取userId
    const userId = req.query.userId;
    if (!userId) {
      return cb(new Error('userId is required as query parameter'));
    }
    
    const userDir = path.join(wencaishenUserInfoDir, userId);
    // 确保用户目录存在
    if (!fs.existsSync(userDir)) {
      fs.mkdirSync(userDir, { recursive: true });
    }
    cb(null, userDir);
  },
  filename: function (req, file, cb) {
    // 使用固定的文件名 'avatar.png'
    cb(null, 'avatar.png');
  }
});

// 确保在启动服务器前添加静态文件服务
app.use('/wencaishen', express.static(wencaishenDir));
app.use('/wencaishen/userinfo', express.static(path.join(wencaishenDir, 'userinfo')));


// 添加/updateUser API接口
app.post('/updateUser', async (req, res) => {
  // 从请求体中获取userId和要更新的字段
  const { userId, ...updateFields } = req.body;
  
  // 验证请求参数
  if (!userId) {
    return res.status(400).json({ success: false, error: 'userId is required' });
  }
  
  // 检查是否有要更新的字段
  if (Object.keys(updateFields).length === 0) {
    return res.status(400).json({ success: false, error: 'No fields to update' });
  }
  
  try {
    const userDir = path.join(wencaishenUserInfoDir, userId);
    const userPropFile = path.join(userDir, 'user.prop');
    
    // 检查用户是否存在
    if (!fs.existsSync(userPropFile)) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    
    // 读取当前用户数据
    const data = fs.readFileSync(userPropFile, 'utf8');
    const userData = properties.parse(data);
    
    // 只更新传入的字段，保持其他字段不变
    const updatedUserData = { ...userData, ...updateFields };
    
    // 写回更新后的用户数据
    const updatedData = properties.stringify(updatedUserData);
    fs.writeFileSync(userPropFile, updatedData, 'utf8');
    
    // 创建完整的响应数据
    const responseData = {
      userId: userId,
      username: updatedUserData.username,
      // 确保userface字段处理正确
      // userface: updatedUserData.userface && updatedUserData.userface.trim() !== '' ? 
      //           updatedUserData.userface : '/wencaishen/head.png',
      // 可以根据需要添加其他需要返回的用户属性
    };
    
    return res.json({
      success: true,
      message: 'User information updated successfully',
      data: responseData
    });
  } catch (error) {
    console.error('Error updating user information:', error);
    return res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// 添加在app.listen之前
app.get('/test-cors', (req, res) => {
  res.json({
    success: true,
    message: 'CORS configuration test successful',
    timestamp: new Date().toISOString()
  });
});


// 添加/changeUserId API接口
app.post('/changeUserId', async (req, res) => {
  try {
    // 从请求体中获取oldUserId和newUserId参数
    const { oldUserId, newUserId } = req.body;
    
    // 验证请求参数
    if (!oldUserId || !newUserId) {
      return res.status(400).json({
        success: false,
        error: 'Both oldUserId and newUserId are required'
      });
    }
    
    // 验证用户ID格式（简单验证，确保不为空且合理）
    if (typeof oldUserId !== 'string' || typeof newUserId !== 'string' || 
        oldUserId.trim() === '' || newUserId.trim() === '') {
      return res.status(400).json({
        success: false,
        error: 'User IDs must be non-empty strings'
      });
    }
    
    // 定义旧用户目录和新用户目录路径
    const oldUserDir = path.join(wencaishenUserInfoDir, oldUserId);
    const newUserDir = path.join(wencaishenUserInfoDir, newUserId);
    
    // 检查旧用户是否存在（通过检查用户目录和user.prop文件）
    const oldUserPropFile = path.join(oldUserDir, 'user.prop');
    if (!fs.existsSync(oldUserDir) || !fs.existsSync(oldUserPropFile)) {
      return res.status(404).json({
        success: false,
        error: `Old user with ID '${oldUserId}' does not exist`
      });
    }
    
    // 检查新用户ID是否已存在
    if (fs.existsSync(newUserDir)) {
      return res.status(409).json({
        success: false,
        error: `New user ID '${newUserId}' already exists`
      });
    }
    
    // 读取旧用户属性文件，准备更新必要信息
    const userData = properties.parse(fs.readFileSync(oldUserPropFile, 'utf8'));
    
    // 如果用户头像路径包含旧的userId，也需要更新
    // if (userData.userface && userData.userface.includes(oldUserId)) {
    //   userData.userface = userData.userface.replace(oldUserId, newUserId);
    // }
    
    // 保存更新后的用户属性
    fs.writeFileSync(oldUserPropFile, properties.stringify(userData), 'utf8');
    
    // 执行目录重命名操作
    fs.renameSync(oldUserDir, newUserDir);
    
    console.log(`[CHANGE_USER_ID] Successfully changed user ID from '${oldUserId}' to '${newUserId}'`);
    
    // 返回成功响应
    return res.json({
      success: true,
      message: `User ID changed successfully from '${oldUserId}' to '${newUserId}'`,
      oldUserId: oldUserId,
      newUserId: newUserId
    });
  } catch (error) {
    console.error(`[CHANGE_USER_ID] Error changing user ID:`, error);
    return res.status(500).json({
      success: false,
      error: error.message || 'Internal server error'
    });
  }
});




// 修改/updateUserFace API接口
// 移除multer中间件，直接处理base64字符串
app.post('/updateUserFace', (req, res, next) => {
  // 先确保CORS头被设置
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  next();
}, async (req, res) => {
  try {
    // 步骤1: 从URL查询参数中获取userId
    console.log(`[UPDATE_USER_FACE] 收到更新头像请求，开始处理`);
    const userId = req.query.userId;
    console.log(`[UPDATE_USER_FACE] 获取到userId: ${userId}`);
    
    // 步骤2: 验证请求参数
    if (!userId) {
      console.error(`[UPDATE_USER_FACE] 错误: userId参数缺失`);
      return res.status(400).json({ success: false, error: 'userId is required as query parameter' });
    }
    
    // 步骤3: 从请求体中获取base64字符串
    const { avatarBase64 } = req.body;
    if (!avatarBase64) {
      console.error(`[UPDATE_USER_FACE] 错误: 未提供avatarBase64参数，userId: ${userId}`);
      return res.status(400).json({ success: false, error: 'avatarBase64 parameter is required' });
    }
    
    console.log(`[UPDATE_USER_FACE] 成功获取base64字符串，长度: ${avatarBase64.length}字符`);
    
    // 步骤4: 确定用户目录和文件路径
    const userDir = path.join(wencaishenUserInfoDir, userId);
    const userPropFile = path.join(userDir, 'user.prop');
    const avatarTxtFile = path.join(userDir, 'avatar.txt'); // 新的avatar.txt文件路径
    console.log(`[UPDATE_USER_FACE] 用户目录: ${userDir}, 属性文件: ${userPropFile}, avatar.txt文件: ${avatarTxtFile}`);
    
    // 步骤5: 检查用户是否存在，如果不存在则创建
    let userData;
    let isNewUser = false;
    if (fs.existsSync(userPropFile)) {
      // 读取现有用户属性
      console.log(`[UPDATE_USER_FACE] 用户已存在，读取用户属性文件`);
      const data = fs.readFileSync(userPropFile, 'utf8');
      userData = properties.parse(data);
      console.log(`[UPDATE_USER_FACE] 成功读取用户属性，当前头像路径: ${userData.userface || '未设置'}`);
    } else {
      // 用户不存在，创建用户
      console.log(`[UPDATE_USER_FACE] 用户不存在，开始创建新用户`);
      const result = await createWenCaishenUser(userId);
      console.log(`[UPDATE_USER_FACE] 用户创建成功: ${JSON.stringify(result)}`);
      const data = fs.readFileSync(userPropFile, 'utf8');
      userData = properties.parse(data);
      isNewUser = true;
      console.log(`[UPDATE_USER_FACE] 新用户属性已加载，默认头像路径: ${userData.userface}`);
    }
    
    // 步骤6: 保存base64字符串到avatar.txt文件
    console.log(`[UPDATE_USER_FACE] 准备保存base64字符串到avatar.txt文件`);
    fs.writeFileSync(avatarTxtFile, avatarBase64, 'utf8');
    console.log(`[UPDATE_USER_FACE] base64字符串保存成功`);
    
    // 步骤7: 根据用户是否为新创建来决定是否更新头像路径
    // 只有当用户不是新创建的时候，才更新头像路径
    if (!isNewUser) {
      console.log(`[UPDATE_USER_FACE] 更新用户头像路径，旧路径: ${userData.userface}`);
      userData.userface = `/wencaishen/userinfo/${userId}/avatar.txt`; // 更新为txt文件路径
      console.log(`[UPDATE_USER_FACE] 更新后头像路径: ${userData.userface}`);
    } else {
      console.log(`[UPDATE_USER_FACE] 新创建用户，保持默认头像路径: ${userData.userface}`);
    }
    
    // 步骤8: 保存更新后的用户信息
    console.log(`[UPDATE_USER_FACE] 准备保存更新后的用户信息`);
    const data = properties.stringify(userData);
    fs.writeFileSync(userPropFile, data, 'utf8');
    console.log(`[UPDATE_USER_FACE] 用户信息保存成功`);
    
    // 步骤9: 返回成功响应
    console.log(`[UPDATE_USER_FACE] 头像更新流程完成，最终头像路径: ${userData.userface}`);
    return res.json({
      success: true,
      message: 'Avatar base64 string saved successfully',
      userId: userId,
      avatarUrl: userData.userface
    });
  } catch (error) {
    console.error(`[UPDATE_USER_FACE] 处理头像更新时发生错误:`, error);
    return res.status(500).json({ success: false, error: error.message || 'Internal server error' });
  }
});



// 添加/getUserFace API接口
app.get('/getUserFace', async (req, res) => {
  try {
    // 从查询参数中获取userId
    const { userId } = req.query;
    
    // 验证请求参数
    if (!userId) {
      return res.status(400).json({
        success: false,
        error: 'userId is required'
      });
    }
    
    // 构建用户目录和avatar.txt文件路径
    const userDir = path.join(wencaishenUserInfoDir, userId);
    const avatarTxtPath = path.join(userDir, 'avatar.txt');
    
    // 检查avatar.txt文件是否存在
    if (!fs.existsSync(avatarTxtPath)) {
      return res.status(404).json({
        success: false,
        error: 'Avatar file not found'
      });
    }
    
    // 读取avatar.txt文件内容
    const avatarContent = fs.readFileSync(avatarTxtPath, 'utf8');
    
    // 返回avatar内容
    return res.json({
      success: true,
      userId: userId,
      avatar: avatarContent
    });
  } catch (error) {
    console.error('[GET_USER_FACE] Error reading avatar file:', error);
    return res.status(500).json({
      success: false,
      error: error.message || 'Internal server error'
    });
  }
});



// 添加/addRecord API接口
app.post('/addRecord', async (req, res) => {
  try {
    // 从请求体中获取所有必要参数
    const { uid, jingzhou, type, count, timestamp } = req.body;
    
    // 验证请求参数
    if (!uid || !jingzhou || !type || count === undefined || !timestamp) {
      return res.status(400).json({
        success: false,
        error: 'All parameters (uid, jingzhou, type, count, timestamp) are required'
      });
    }
    
    // 验证type参数值
    if (type !== '分钟' && type !== '遍') {
      return res.status(400).json({
        success: false,
        error: 'type must be either "分钟" or "遍"'
      });
    }
    
    // 验证count参数必须为数字
    if (isNaN(Number(count))) {
      return res.status(400).json({
        success: false,
        error: 'count must be a number'
      });
    }
    
    // 构建用户目录和records.txt文件路径
    const userDir = path.join(wencaishenUserInfoDir, uid);
    const recordsFilePath = path.join(userDir, 'records.txt');
    
    // 确保用户目录存在
    if (!fs.existsSync(userDir)) {
      fs.mkdirSync(userDir, { recursive: true });
      console.log(`[ADD_RECORD] Created user directory: ${userDir}`);
    }
    
    // 格式化记录内容，使用"｜"作为分隔符
    const recordLine = `${jingzhou}｜${type}｜${count}｜${timestamp}\n`;
    
    // 将记录追加到文件中
    fs.appendFileSync(recordsFilePath, recordLine, 'utf8');
    console.log(`[ADD_RECORD] Record added successfully for user: ${uid}`);
    
    // 返回成功响应
    return res.json({
      success: true,
      message: 'Record added successfully',
      record: {
        uid: uid,
        jingzhou: jingzhou,
        type: type,
        count: count,
        timestamp: timestamp
      }
    });
  } catch (error) {
    console.error('[ADD_RECORD] Error adding record:', error);
    return res.status(500).json({
      success: false,
      error: error.message || 'Internal server error'
    });
  }
});

// 添加/getRecords API接口
app.get('/getRecords', async (req, res) => {
  try {
    // 从查询参数中获取uid
    const { uid } = req.query;
    
    // 验证请求参数
    if (!uid) {
      return res.status(400).json({
        success: false,
        error: 'uid is required'
      });
    }
    
    // 构建用户目录和records.txt文件路径
    const userDir = path.join(wencaishenUserInfoDir, uid);
    const recordsFilePath = path.join(userDir, 'records.txt');
    
    // 检查records.txt文件是否存在
    if (!fs.existsSync(recordsFilePath)) {
      // 如果文件不存在，返回空数组
      return res.json({
        success: true,
        records: []
      });
    }
    
    // 读取records.txt文件内容
    const fileContent = fs.readFileSync(recordsFilePath, 'utf8');
    
    // 按行分割文件内容，过滤空行
    const lines = fileContent.split('\n').filter(line => line.trim() !== '');
    
    // 解析每一行记录为JSON对象
    const records = lines.map(line => {
      // 使用"｜"作为分隔符分割每一行
      const parts = line.split('｜');
      
      // 确保每一行有4个部分（jingzhou, type, count, timestamp）
      if (parts.length === 4) {
        return {
          jingzhou: parts[0],
          type: parts[1],
          count: parseInt(parts[2], 10),
          timestamp: parts[3]
        };
      }
      
      // 如果格式不正确，跳过该行
      return null;
    }).filter(record => record !== null); // 过滤掉格式不正确的记录
    
    // 返回记录数组
    return res.json({
      success: true,
      records: records,
      total: records.length,
      uid: uid
    });
  } catch (error) {
    console.error('[GET_RECORDS] Error reading records:', error);
    return res.status(500).json({
      success: false,
      error: error.message || 'Internal server error'
    });
  }
});


// 启动服务器
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});