// server.js

// 引入 dotenv 并加载 .env 文件中的环境变量
require('dotenv').config();

// 引入 Express 和其他必要的模块
const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
require('express-async-errors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

// --- 应用配置 ---
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

// app.use(express.static('public'));

// 检查密钥是否存在
if (!JWT_SECRET) {
    console.error('错误：未找到 JWT_SECRET 环境变量。请在 .env 文件中设置它。');
    process.exit(1);
}

// 启用 CORS，允许跨域请求
app.use(cors());
// 解析 JSON 格式的请求体
app.use(express.json());

// --- 数据库连接和初始化 ---
const db = new sqlite3.Database('./qzkago.db', (err) => {
    if (err) {
        console.error(err.message);
    } else {
        console.log('成功连接到 qzkago 数据库。');
    }
});

// --- 订单ID生成函数 ---
const generateOrderId = () => {
    const timestamp = Date.now();
    // 生成一个短的随机字符串
    const randomString = Math.random().toString(36).substring(2, 8);
    return `${timestamp}-${randomString}`;
};


// 确保数据库操作按顺序执行
db.serialize(() => {
    // 创建 'users' 用户表
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        phone_number TEXT,
        admin_notes TEXT,
        registration_ua TEXT,
        last_login_ua TEXT,
        role TEXT NOT NULL,
        is_active INTEGER DEFAULT 1,
        is_banned INTEGER DEFAULT 0,
        is_admin INTEGER DEFAULT 0,
        balance REAL DEFAULT 0.0,
        avatar TEXT,
        created_at INTEGER DEFAULT (CAST(STRFTIME('%s', 'now') AS INTEGER))
    )`, (err) => {
        if (err) {
            console.error('创建用户表时出错:', err.message);
        } else {
            console.log('用户表已创建或已存在。');
        }
    });

    // 创建 'records' 访客记录表
    db.run(`CREATE TABLE IF NOT EXISTS records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id TEXT UNIQUE NOT NULL, 
    user_id INTEGER,
    user_name TEXT, 
    in_time TEXT,
    out_time TEXT,
    status TEXT DEFAULT 'ongoing',
    amount_spent REAL DEFAULT 0.0,
    unit_price REAL DEFAULT 0.0,
    total_duration_minutes INTEGER DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id)
)`, (err) => {
        if (err) {
            console.error('创建访客记录表时出错:', err.message);
        } else {
            console.log('访客记录表已创建或已存在。');
        }
    });

    // 创建 'orders' 订单表
    db.run(`CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    user_name TEXT NOT NULL, 
    record_id INTEGER NOT NULL,
    session_order_id TEXT, -- 关键修改: 新增字段，用于存储 records 表的 order_id
    order_time TEXT NOT NULL,
    items TEXT, -- 使用 JSON 字符串存储商品列表
    total_amount REAL DEFAULT 0.0,
    status TEXT DEFAULT 'pending',
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(record_id) REFERENCES records(id)
)`, (err) => {
        if (err) {
            console.error('创建订单表时出错:', err.message);
        } else {
            console.log('订单表已创建或已存在。');
        }
    });

    // 创建价格设置表
    db.run(`
    CREATE TABLE IF NOT EXISTS price_settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        day_of_week TEXT NOT NULL, -- JSON string of array of numbers (0=Sun, 1=Mon, ..., 6=Sat)
        start_time TEXT NOT NULL, -- HH:mm format
        end_time TEXT NOT NULL,   -- HH:mm format
        price_per_hour REAL NOT NULL
    )
`, (err) => {
        if (err) {
            console.error('创建 price_settings 表失败:', err.message);
        } else {
            console.log('price_settings 表已准备就绪。');
        }
    });

    // 创建平台设置表
    db.run(`
    CREATE TABLE IF NOT EXISTS platform_settings (
        id INTEGER PRIMARY KEY DEFAULT 1,
        default_price REAL NOT NULL DEFAULT 5.00,
        free_duration_minutes INTEGER NOT NULL DEFAULT 5,
        customer_service_contact TEXT NOT NULL DEFAULT '19237480125',
        account_approval_required INTEGER NOT NULL DEFAULT 0 -- 关键修改: 添加账户审批字段，0为不需要，1为需要
    )
`, (err) => {
        if (err) {
            console.error('创建 platform_settings 表失败:', err.message);
        } else {
            console.log('platform_settings 表已准备就绪。');
            // 确保始终有一条记录
            db.get(`SELECT COUNT(*) as count FROM platform_settings`, (err, row) => {
                if (err) {
                    console.error('查询 platform_settings 记录失败:', err.message);
                    return;
                }
                if (row.count === 0) {
                    // 关键修改: 插入默认记录时，包含新的 account_approval_required 字段
                    db.run(`INSERT INTO platform_settings (id, default_price, free_duration_minutes, customer_service_contact, account_approval_required) VALUES (1, 5.00, 5, '19237480125', 0)`, (insertErr) => {
                        if (insertErr) {
                            console.error('插入默认 platform_settings 记录失败:', insertErr.message);
                        } else {
                            console.log('已插入默认 platform_settings 记录。');
                        }
                    });
                }
            });
        }
    });

    // 关键修改: 创建 'carousel_images' 轮播图图片表
    db.run(`
    CREATE TABLE IF NOT EXISTS carousel_images (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        image_url TEXT NOT NULL,
        type TEXT NOT NULL, -- 'home' 或 'dashboard'，用于区分首页轮播图和仪表盘轮播图
        order_index INTEGER DEFAULT 0, -- 用于排序，避免与 SQL 关键字 'order' 冲突
        created_at INTEGER DEFAULT (CAST(STRFTIME('%s', 'now') AS INTEGER)) -- 记录创建时间，秒级时间戳
    )
`, (err) => {
        if (err) {
            console.error('创建 carousel_images 表失败:', err.message);
        } else {
            console.log('carousel_images 表已准备就绪。');
        }
    });

});


// --- JWT 验证中间件 ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        return res.status(401).json({ error: '需要提供 Token。' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            // 如果 JWT 过期或无效
            return res.status(403).json({ error: '无效或过期的 Token。' });
        }
        req.user = user; // 将用户信息附加到请求对象上
        next();
    });
};

// --- API 接口：用户注册 ---
app.post('/api/register', async (req, res) => {
    const { username, password, phone } = req.body;

    // 验证用户名、密码和手机号的格式
    if (!username || username.length < 5) {
        return res.status(400).json({ error: '用户名不能少于5位。' });
    }
    if (!password || password.length < 6) {
        return res.status(400).json({ error: '密码不能少于6位。' });
    }
    const phoneRegex = /^1[0-9]{10}$/;
    if (!phone || !phoneRegex.test(phone)) {
        return res.status(400).json({ error: '手机号格式不正确，必须是11位数字且以1开头。' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        // 检查用户名是否已存在，以避免重复注册
        db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            if (row) {
                return res.status(409).json({ error: '用户名已存在。' });
            }

            // 检查是否为第一个用户
            db.get("SELECT COUNT(*) AS count FROM users", (err, row) => {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }
                const isFirstUser = row.count === 0;
                const role = isFirstUser ? 'super_admin' : 'user';
                const isAdmin = isFirstUser ? 1 : 0;

                // 关键修改1: 获取平台设置中的 account_approval_required
                db.get(`SELECT account_approval_required FROM platform_settings WHERE id = 1`, (settingsErr, settingsRow) => {
                    if (settingsErr) {
                        console.error('获取平台设置失败:', settingsErr.message);
                        return res.status(500).json({ error: '获取平台设置失败。' });
                    }

                    // 根据平台设置确定 is_active 的初始值
                    // 如果 settingsRow 不存在或 account_approval_required 为 0 (不需要审批)，则 isActive 为 1
                    // 否则 (account_approval_required 为 1，需要审批)，则 isActive 为 0
                    const accountApprovalRequired = settingsRow ? settingsRow.account_approval_required : 0;
                    const isActive = (accountApprovalRequired === 0) ? 1 : 0; // 关键修改2: 动态设置 is_active

                    const defaultAvatar = '/img/user_avatar.jpg';

                    const sql = `INSERT INTO users (username, password, phone_number, role, is_admin, is_active, avatar) VALUES (?, ?, ?, ?, ?, ?, ?)`;
                    db.run(sql, [username, hashedPassword, phone, role, isAdmin, isActive, defaultAvatar], function (err) {
                        if (err) {
                            return res.status(500).json({ error: err.message });
                        }
                        res.status(201).json({
                            message: isFirstUser ? '成功注册，您是超级管理员！' : '注册成功。' + (isActive === 0 ? ' 请等待管理员激活账户。' : ''), // 关键修改3: 根据活跃状态调整消息
                            user_id: this.lastID,
                            username: username,
                            is_admin: isAdmin,
                            is_active: isActive,
                            avatar: defaultAvatar
                        });
                    });
                });
            });
        });
    } catch (err) {
        res.status(500).json({ error: '密码加密失败。' });
    }
});

// --- API 接口：用户登录 ---
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: '用户名和密码是必填项。' });
    }

    // 关键修改: 查询用户时，除了所有字段，还额外查询 is_banned 和 is_active
    const sql = `SELECT id, username, password, is_admin, is_banned, is_active FROM users WHERE username = ?`;
    db.get(sql, [username], async (err, user) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (!user) {
            return res.status(401).json({ error: '用户名或密码不正确。' });
        }

        try {
            const match = await bcrypt.compare(password, user.password);
            if (!match) {
                return res.status(401).json({ error: '用户名或密码不正确。' });
            }

            // 关键修改1: 判断用户是否被封禁
            if (user.is_banned === 1) { // 假设 is_banned 为 1 表示被封禁
                return res.status(403).json({ error: '您的账户已被封禁，请联系管理员。' });
            }

            // 关键修改2: 判断用户是否活跃
            if (user.is_active === 0) { // 假设 is_active 为 0 表示不活跃
                return res.status(403).json({ error: '您的账户尚未激活，请联系管理员激活账户。' });
            }

            // 签发 JWT
            const token = jwt.sign(
                { id: user.id, username: user.username, is_admin: user.is_admin },
                JWT_SECRET,
                { expiresIn: '30d' } // 30天有效期
            );

            res.status(200).json({
                message: '登录成功',
                token,
                user: {
                    id: user.id,
                    username: user.username,
                    is_admin: user.is_admin,
                    is_banned: user.is_banned, // 关键修改: 返回封禁状态
                    is_active: user.is_active  // 关键修改: 返回活跃状态
                }
            });
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
});

// --- API 接口：获取首页图片 (公共接口，无需认证) ---
// 路径为 /api/home_img
// 此接口将返回 'home' 类型的轮播图图片，与 /api/carousel/home 接口返回相同的数据。
app.get('/api/home_img', (req, res, next) => {
    const carousel_type = 'home'; // 固定为首页轮播图类型

    // 从 carousel_images 表中查询 'home' 类型的图片，并按 order_index 和 created_at 排序
    const sql = `SELECT id, image_url, type, order_index, created_at FROM carousel_images WHERE type = ? ORDER BY order_index ASC, created_at DESC`;
    db.all(sql, [carousel_type], (err, rows) => {
        if (err) {
            console.error(`获取首页图片失败:`, err.message);
            return next(err); // 将错误传递给全局错误处理中间件
        }
        res.status(200).json(rows); // 返回获取到的图片数据
    });
});

// --- API 接口：获取用户信息 (已修改，根据角色返回字段) ---
// 路径为 /api/user/info，需要 JWT 验证
app.get('/api/user/info', authenticateToken, (req, res) => {
    // 从 JWT 中获取用户ID
    const user_id = req.user.id;

    // 从数据库中查询所有相关字段
    const sql = `SELECT id, username, avatar, is_admin, balance FROM users WHERE id = ?`;
    db.get(sql, [user_id], (err, user) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (!user) {
            return res.status(404).json({ error: '用户未找到。' });
        }

        // 关键修改：根据用户角色有条件地构建响应对象
        const responseUser = {
            id: user.id,
            username: user.username,
            avatar: user.avatar,
            balance: user.balance
        };

        // 如果用户是管理员，才在响应中添加 is_admin 字段
        if (user.is_admin === 1) {
            responseUser.is_admin = 1;
        }

        res.status(200).json(responseUser);
    });
});

// --- API 接口：更新用户个人资料 (用户专用) ---
// 路径为 /api/user/profile，需要 JWT 验证
// 接收请求体: { avatar }
// 关键修改: 仅处理 avatar 字段的更新
app.put('/api/user/profile', authenticateToken, (req, res, next) => {
    const user_id = req.user.id; // 从 JWT 获取当前用户的 ID
    const { avatar } = req.body; // 从请求体中仅获取 avatar 字段

    // 验证传入的字段，确保只提供了 avatar
    if (avatar === undefined) {
        return res.status(400).json({ error: '请求体中需要提供头像URL (avatar)。' });
    }

    let updateFields = [];
    let params = [];

    // 仅当提供了非空值时才更新 avatar
    if (avatar !== undefined && avatar.trim() !== '') {
        updateFields.push('avatar = ?');
        params.push(avatar.trim());
    } else if (avatar !== undefined && avatar.trim() === '') {
        // 允许将头像设置为空
        updateFields.push('avatar = ?');
        params.push(null);
    }

    if (updateFields.length === 0) {
        return res.status(400).json({ error: '没有有效的字段可以更新。' });
    }

    const sql = `UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`;
    params.push(user_id); // 更新当前登录用户

    db.run(sql, params, function (err) {
        if (err) {
            console.error('更新用户个人资料时数据库错误:', err.message);
            return next(err); // 传递其他错误给全局错误处理中间件
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: '未找到要更新的用户资料或未进行任何更改。' });
        }
        res.status(200).json({ message: '个人资料更新成功！', updated_user_id: user_id });
    });
});

// --- API 接口：用户密码更改 (用户专用) ---
// 路径为 /api/user/password-change，需要 JWT 验证
// 接收请求体: { old_password, new_password }
app.put('/api/user/password-change', authenticateToken, async (req, res, next) => {
    const user_id = req.user.id; // 从 JWT 获取当前用户的 ID
    const { old_password, new_password } = req.body;

    // 验证新旧密码是否提供
    if (!old_password || !new_password) {
        return res.status(400).json({ error: '旧密码和新密码是必填项。' });
    }
    // 验证新密码长度
    if (new_password.length < 6) {
        return res.status(400).json({ error: '新密码不能少于6位。' });
    }
    // 验证新旧密码是否相同
    if (old_password === new_password) {
        return res.status(400).json({ error: '新密码不能与旧密码相同。' });
    }

    try {
        // 1. 获取用户当前存储的密码哈希
        const userRow = await new Promise((resolve, reject) => {
            db.get(`SELECT password FROM users WHERE id = ?`, [user_id], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (!userRow) {
            return res.status(404).json({ error: '用户信息未找到。' });
        }

        // 2. 验证旧密码
        const match = await bcrypt.compare(old_password, userRow.password);
        if (!match) {
            return res.status(401).json({ error: '旧密码不正确。' });
        }

        // 3. 哈希新密码
        const hashedNewPassword = await bcrypt.hash(new_password, 10);

        // 4. 更新数据库中的密码
        const updateSql = `UPDATE users SET password = ? WHERE id = ?`;
        db.run(updateSql, [hashedNewPassword, user_id], function (err) {
            if (err) {
                console.error('更新密码时数据库错误:', err.message);
                return next(err);
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: '未找到要更新的用户或未进行任何更改。' });
            }
            res.status(200).json({ message: '密码更新成功！请使用新密码重新登录。' });
        });

    } catch (err) {
        console.error('修改密码失败:', err.message);
        return next(err);
    }
});

// --- API 接口：验证管理员权限 (失败时返回 404) ---
// 路径为 /api/admin/check-admin，需要 JWT 验证
app.get('/api/admin/check-admin', authenticateToken, (req, res) => {
    // 从 JWT 中获取用户ID
    const user_id = req.user.id;

    // 从数据库查询用户的 is_admin、is_active 和 is_banned 字段
    const sql = `SELECT is_admin, is_active, is_banned FROM users WHERE id = ?`;
    db.get(sql, [user_id], (err, row) => {
        if (err) {
            // 数据库查询出错，返回 500
            return res.status(500).json({ error: err.message });
        }

        // 检查用户是否存在
        if (!row) {
            return res.status(404).json({ error: '资源不存在。' });
        }

        // 新增逻辑: 检查用户状态
        if (row.is_active === 0) {
            return res.status(403).json({ 
                error: '权限验证失败：您的账户未激活，请联系管理员。',
                code: 'ACCOUNT_INACTIVE'
            });
        }

        if (row.is_banned === 1) {
            return res.status(403).json({ 
                error: '权限验证失败：您的账户已被封禁，请联系管理员。',
                code: 'ACCOUNT_BANNED'
            });
        }

        // 关键修改：如果不是管理员，返回 404
        if (row.is_admin !== 1) {
            return res.status(404).json({ error: '资源不存在。' });
        }

        // 如果是管理员，返回成功信息
        return res.status(200).json({ is_admin: 1, message: '权限验证成功。' });
    });
});

// --- API 接口：获取访客记录  ---
// 路径为 /api/user/records，需要 JWT 验证，默认返回最新的5条记录
app.get('/api/user/records', authenticateToken, (req, res) => {
    // 从 JWT 中获取用户ID
    const user_id = req.user.id;

    // 查询用户的访客记录，按时间倒序排列，并限制为5条
    const sql = `SELECT * FROM records WHERE user_id = ? ORDER BY in_time DESC LIMIT 5`;
    db.all(sql, [user_id], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.status(200).json(rows);
    });
});

// --- API 接口：记录访客进店时间 (已修改，直接从SQL计算当前计价并保存至 unit_price) ---
// 路径为 /api/user/arrive，需要 JWT 验证
app.post('/api/user/arrive', authenticateToken, async (req, res, next) => {
    // 通过 JWT 中间件获取 user_id
    const user_id = req.user.id;

    try {
        // 1. 首先获取用户的 username、balance、is_active 和 is_banned
        const userRow = await new Promise((resolve, reject) => {
            // 修改 SQL 查询，增加对 is_active 和 is_banned 字段的获取
            db.get(`SELECT username, balance, is_active, is_banned FROM users WHERE id = ?`, [user_id], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (!userRow) {
            // 如果用户不存在，仍然返回 404
            return res.status(404).json({ error: '用户信息未找到。' });
        }
        const user_name = userRow.username;
        const user_balance = userRow.balance; // 获取用户余额
        const is_active = userRow.is_active; // 获取用户的激活状态
        const is_banned = userRow.is_banned; // 获取用户的封禁状态

        // 新增逻辑: 检查用户状态
        if (is_active === 0) {
            return res.status(403).json({ 
                error: '进店失败：您的账户未激活，请联系管理员。',
                code: 'ACCOUNT_INACTIVE'
            });
        }

        if (is_banned === 1) {
            return res.status(403).json({ 
                error: '进店失败：您的账户已被封禁，请联系管理员。',
                code: 'ACCOUNT_BANNED'
            });
        }
        
        // 2. 检查用户是否有进行中的记录
        const existingRecord = await new Promise((resolve, reject) => {
            const checkSql = `SELECT id FROM records WHERE user_id = ? AND status = 'ongoing'`;
            db.get(checkSql, [user_id], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (existingRecord) {
            return res.status(409).json({ error: '您已在店铺内，请勿重复进店。' });
        }

        // 3. 计算当前入场单价 (直接从 SQL 读取和计算)
        const now = new Date();
        const currentDayOfWeek = now.getDay(); // 0 for Sunday, 1 for Monday, ..., 6 for Saturday
        const currentTimeHHMM = now.toTimeString().substring(0, 5); // "HH:mm" format

        let entryUnitPrice; // 将由 platform_settings 或 price_settings 确定

        // 3.1. 首先从 platform_settings 获取默认价格
        const platformSettings = await new Promise((resolve, reject) => {
            db.get(`SELECT default_price FROM platform_settings WHERE id = 1`, (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        // 检查平台设置是否存在且默认价格字段完整
        if (!platformSettings || platformSettings.default_price === undefined) {
            throw new Error('平台设置中的默认单价未配置或不完整。');
        }

        entryUnitPrice = platformSettings.default_price; // 初始化为平台设置的默认价格

        // 3.2. 接着查找 price_settings 中的时间段价格规则，这会覆盖平台设置的默认价格（如果匹配）
        try {
            const priceRules = await new Promise((resolve, reject) => {
                const sql = `SELECT day_of_week, start_time, end_time, price_per_hour FROM price_settings`;
                db.all(sql, [], (err, rows) => {
                    if (err) reject(err);
                    else resolve(rows);
                });
            });

            for (const rule of priceRules) {
                let ruleDays;
                try {
                    // 确保 rule.day_of_week 是非空的 JSON 字符串且可解析
                    if (rule.day_of_week) {
                        ruleDays = JSON.parse(rule.day_of_week);
                    } else {
                        continue; // 跳过 day_of_week 为空的规则
                    }
                } catch (e) {
                    console.warn('解析 day_of_week 失败:', rule.day_of_week, e);
                    continue; // 跳过无效规则
                }

                // 检查当前星期是否在规则中，并且规则天数数组有效
                if (Array.isArray(ruleDays) && ruleDays.includes(currentDayOfWeek)) {
                    // 检查当前时间是否在规则的时间段内
                    if (currentTimeHHMM >= rule.start_time && currentTimeHHMM <= rule.end_time) {
                        entryUnitPrice = rule.price_per_hour; // 找到匹配规则，覆盖默认价格
                        break; // 找到第一个匹配规则后即停止
                    }
                }
            }
        } catch (priceRuleError) {
            console.error('获取时间段价格规则失败 (将使用平台默认价格作为回退):', priceRuleError.message);
            // 这里不抛出错误，因为我们已经有了 platform_settings 的默认价格作为回退
        }
        // 至此，entryUnitPrice 已确定

        // 关键修改: 4. 检查用户余额是否高于当前计费单价
        if (user_balance < entryUnitPrice) {
            // 关键修改: 返回 200 状态码，并在消息中告知余额不足，但进店操作不会执行
            return res.status(200).json({
                message: `进店失败：余额不足，当前计费单价为 ¥${entryUnitPrice.toFixed(2)}/小时，您的余额为 ¥${user_balance.toFixed(2)}。`,
                code: 'BALANCE_INSUFFICIENT', // 添加自定义错误码，方便前端判断
                required_balance: entryUnitPrice,
                current_balance: user_balance
            });
        }


        // 5. 如果没有进行中的记录且余额充足，则创建新记录
        const inTime = Math.floor(Date.now() / 1000); // 获取当前秒级时间戳

        const generateOrderId = () => {
            const now = new Date();
            const year = now.getFullYear();
            const month = String(now.getMonth() + 1).padStart(2, '0');
            const day = String(now.getDate()).padStart(2, '0');
            const datePart = `${year}${month}${day}`;
            const uuidPart = Math.random().toString(16).slice(2, 10);
            return `${datePart}${uuidPart}`;
        };

        const order_id = generateOrderId(); // 生成订单ID
        const status = 'ongoing'; // 设置状态为进行中

        // 6. 插入 user_name 和 unit_price 字段到 records 表
        const insertSql = 'INSERT INTO records (order_id, user_id, user_name, in_time, status, unit_price) VALUES (?, ?, ?, ?, ?, ?)';
        const result = await new Promise((resolve, reject) => {
            db.run(insertSql, [order_id, user_id, user_name, inTime, status, entryUnitPrice], function (err) {
                if (err) reject(err);
                else resolve(this);
            });
        });

        res.status(201).json({
            message: '进店时间已记录',
            record_id: result.lastID,
            order_id: order_id,
            user_name: user_name,
            in_time: inTime,
            status: status,
            unit_price: entryUnitPrice // 返回记录的单价
        });
    } catch (err) {
        console.error('访客进店记录失败:', err.message);
        // 如果是自定义错误，返回更具体的错误信息
        if (err.message.includes('平台设置')) {
            return res.status(500).json({ error: `进店失败：${err.message}` });
        }
        next(err); // 传递其他错误给全局错误处理中间件
    }
});

// --- API 接口：记录访客离店时间，计算时长和金额，并扣款 ---
// 路径为 /api/user/leave，需要 JWT 验证
app.post('/api/user/leave', authenticateToken, async (req, res, next) => { // 改为 async 函数
    const user_id = req.user.id;
    const { order_id } = req.body; // 注意：这里的 order_id 是 records 表中的 order_id

    if (!order_id) {
        return res.status(400).json({ error: '订单ID是必填项。' });
    }

    try {
        // 1. 查找用户正在进行中的记录，获取 id, in_time, unit_price, user_name, order_id (records表的字符串ID)
        const recordRow = await new Promise((resolve, reject) => {
            const checkSql = `SELECT id, in_time, unit_price, user_name, order_id FROM records WHERE user_id = ? AND order_id = ? AND status = 'ongoing'`;
            db.get(checkSql, [user_id, order_id], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (!recordRow) {
            return res.status(404).json({ error: '未找到您正在进行中的订单或订单ID不匹配。' });
        }

        const inTimeSeconds = Number(recordRow.in_time);
        const recordUnitPrice = Number(recordRow.unit_price);
        const user_name = recordRow.user_name; // 获取用户名称
        const session_order_id_from_records = recordRow.order_id; // 从 records 表获取字符串 order_id
        const outTimeSeconds = Math.floor(Date.now() / 1000); // 当前秒级时间戳

        // 2. 获取平台设置中的免费时长
        let freeDurationMinutes = 0;
        try {
            const platformSettings = await new Promise((resolve, reject) => {
                db.get(`SELECT free_duration_minutes FROM platform_settings WHERE id = 1`, (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                });
            });
            if (platformSettings && platformSettings.free_duration_minutes !== undefined) {
                freeDurationMinutes = platformSettings.free_duration_minutes;
            }
        } catch (platformSettingsError) {
            console.error('获取平台设置中的免费时长失败 (将使用0分钟作为回退):', platformSettingsError.message);
            // 免费时长默认为 0
        }

        // 3. 计算总入店时长 (分钟)
        let totalDurationSeconds = outTimeSeconds - inTimeSeconds;
        let totalDurationMinutes = Math.ceil(totalDurationSeconds / 60); // 向上取整到分钟
        if (totalDurationMinutes < 0) totalDurationMinutes = 0; // 确保时长不为负

        // 4. 计算实际计费时长 (分钟)
        let billedDurationMinutes = Math.max(0, totalDurationMinutes - freeDurationMinutes);

        // 5. 计算实际计费小时数 (不满一小时按一小时计算，如果计费分钟为0则小时也为0)
        let billedHours = 0;
        if (billedDurationMinutes > 0) {
            billedHours = Math.ceil(billedDurationMinutes / 60);
        }

        // 6. 计算花费金额
        let amountSpent = billedHours * recordUnitPrice;
        amountSpent = parseFloat(amountSpent.toFixed(2)); // 精确到两位小数

        // 7. 更新 records 表：设置 out_time, status, total_duration_minutes, amount_spent
        const updateRecordSql = `UPDATE records SET out_time = ?, status = 'finished', total_duration_minutes = ?, amount_spent = ? WHERE id = ?`;

        await new Promise((resolve, reject) => {
            db.run(updateRecordSql, [outTimeSeconds, totalDurationMinutes, amountSpent, recordRow.id], function (err) {
                if (err) reject(err);
                else resolve(this);
            });
        });

        // 关键新增步骤: 8. 将入店时长订单写入 orders 表
        const orderItems = JSON.stringify([
            { type: '入店', name: '入店时长', quantity: 1, details: `入店 ${totalDurationMinutes} 分钟` }
        ]);
        const orderStatusForOrdersTable = 'completed'; // 对于 orders 表，设置为 'completed'
        const orderTimeForOrdersTable = outTimeSeconds; // 订单创建时间为离店时间

        // 关键修改: 插入 session_order_id
        const insertOrderSql = `INSERT INTO orders (user_id, user_name, record_id, session_order_id, order_time, items, total_amount, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
        await new Promise((resolve, reject) => {
            db.run(insertOrderSql, [user_id, user_name, recordRow.id, session_order_id_from_records, orderTimeForOrdersTable, orderItems, amountSpent, orderStatusForOrdersTable], function (err) {
                if (err) reject(err);
                else resolve(this);
            });
        });

        // 9. 从用户余额中扣除 amount_spent (原步骤8)
        const user = await new Promise((resolve, reject) => {
            db.get(`SELECT balance FROM users WHERE id = ?`, [user_id], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (!user) {
            // 理论上不会发生，因为用户ID来自JWT
            throw new Error('用户余额信息未找到。');
        }

        const newBalance = parseFloat((user.balance - amountSpent).toFixed(2)); // 计算新余额并保持精度
        const updateUserBalanceSql = `UPDATE users SET balance = ? WHERE id = ?`;

        await new Promise((resolve, reject) => {
            db.run(updateUserBalanceSql, [newBalance, user_id], function (err) {
                if (err) reject(err);
                else resolve(this);
            });
        });

        res.status(200).json({
            message: '离店时间已记录，订单已结束并结算。',
            record_id: recordRow.id,
            order_id: order_id, // records 表中的订单ID
            user_name: user_name,
            in_time: recordRow.in_time,
            out_time: outTimeSeconds,
            status: 'finished', // records 表状态
            total_duration_minutes: totalDurationMinutes,
            amount_spent: amountSpent,
            unit_price: recordUnitPrice,
            new_balance: newBalance, // 返回更新后的用户余额
            // 可以选择返回 orders 表中新创建的订单ID，如果需要
            // new_order_id: orders_table_new_id // 需要从 db.run 的 this.lastID 获取
        });

    } catch (err) {
        console.error('离店结算失败:', err.message);
        // 如果是自定义错误，返回更具体的错误信息
        if (err.message.includes('平台设置')) {
            return res.status(500).json({ error: `离店结算失败：${err.message}` });
        }
        next(err); // 传递其他错误给全局错误处理中间件
    }
});


// --- API 接口：检查用户当前是否在店状态，并计算预估费用 ---
// 路径为 /api/user/status，需要 JWT 验证
app.get('/api/user/status', authenticateToken, async (req, res, next) => { // 改为 async 函数
    const user_id = req.user.id;

    try {
        // 1. 查询用户是否有状态为 'ongoing' 的记录，获取 in_time, order_id, unit_price
        const recordRow = await new Promise((resolve, reject) => {
            const sql = `SELECT in_time, order_id, unit_price FROM records WHERE user_id = ? AND status = 'ongoing'`;
            db.get(sql, [user_id], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (recordRow) {
            const inTime = Number(recordRow.in_time);
            const unitPrice = Number(recordRow.unit_price);
            const currentTime = Math.floor(Date.now() / 1000); // 当前秒级时间戳

            // 关键修改: 简化计算实际计费时长和计费小时数，不再考虑免费时长
            let billedDurationSeconds = currentTime - inTime;
            let billedDurationMinutes = Math.ceil(billedDurationSeconds / 60); // 向上取整到分钟
            if (billedDurationMinutes < 0) billedDurationMinutes = 0; // 确保时长不为负

            let billedHours = Math.ceil(billedDurationMinutes / 60);
            if (billedHours < 0) billedHours = 0; // 确保小时数不为负

            // 6. 计算预估花费金额
            let estimatedCost = billedHours * unitPrice;
            estimatedCost = parseFloat(estimatedCost.toFixed(2)); // 精确到两位小数

            // 如果存在进行中的记录，返回进店时间戳、订单ID、单价、预估费用
            res.status(200).json({
                is_in_store: true,
                in_time: recordRow.in_time, // 返回秒级时间戳
                order_id: recordRow.order_id,
                unit_price: unitPrice, // 返回当前订单单价
                estimated_cost: estimatedCost, // 返回预估结算金额
                // 关键修改: 移除 total_duration_minutes 和 free_duration_minutes
                // total_duration_minutes: totalDurationMinutes, 
                // free_duration_minutes: freeDurationMinutes, 
                message: '您当前在店内。'
            });
        } else {
            // 如果没有进行中的记录，表示用户不在店内
            res.status(200).json({
                is_in_store: false,
                message: '您当前不在店内。'
            });
        }
    } catch (err) {
        // 数据库查询出错，交由全局错误处理
        console.error('检查用户在店状态或计算费用时数据库错误:', err.message);
        next(err);
    }
});


// --- API 接口：获取当前入场单价和免费时长 (公共接口，无需认证) ---
// 路径为 /api/current-price
// 根据当前星期和时间，查找 price_settings 表中匹配的规则。
// 如果找到，返回匹配价格；否则，返回默认价格 5.00。
// 此外，还返回 platform_settings 中的 free_duration_minutes。
app.get('/api/current-price', (req, res, next) => {
    const now = new Date();
    const currentDayOfWeek = now.getDay(); // 0 for Sunday, 1 for Monday, ..., 6 for Saturday
    const currentTimeHHMM = now.toTimeString().substring(0, 5); // "HH:mm" format

    let matchedPrice = 5.00; // 默认价格
    let freeDurationMinutes = 0; // 默认免费时长

    // 首先获取平台设置中的免费时长和默认单价 (如果 platform_settings 存在 default_price)
    // 尽管我们硬编码了 matchedPrice 的默认值，但最好还是从 platform_settings 中获取最新的默认单价
    db.get(`SELECT default_price, free_duration_minutes FROM platform_settings WHERE id = 1`, (err, platformSettings) => {
        if (err) {
            console.error('获取平台设置失败:', err.message);
            // 如果获取失败，使用硬编码的默认值
            freeDurationMinutes = 5; // Fallback default
        } else if (platformSettings) {
            matchedPrice = platformSettings.default_price || 5.00; // 使用平台设置的默认单价
            freeDurationMinutes = platformSettings.free_duration_minutes || 5; // 使用平台设置的免费时长
        } else {
            // 如果 platform_settings 表中没有记录 (理论上不应该，因为有 INSERT OR IGNORE)
            // 使用硬编码的默认值
            freeDurationMinutes = 5;
        }

        // 接着查找时间段价格规则
        const sql = `SELECT day_of_week, start_time, end_time, price_per_hour FROM price_settings`;
        db.all(sql, [], (err, rows) => {
            if (err) {
                console.error('获取价格规则失败:', err.message);
                // 如果获取价格规则失败，仍然返回 platform_settings 或硬编码的默认值
                return res.status(200).json({ price: matchedPrice, free_duration_minutes: freeDurationMinutes });
            }

            for (const rule of rows) {
                let ruleDays;
                try {
                    ruleDays = JSON.parse(rule.day_of_week);
                } catch (e) {
                    console.warn('解析 day_of_week 失败:', rule.day_of_week);
                    continue; // 跳过无效规则
                }

                // 检查当前星期是否在规则中
                if (ruleDays && ruleDays.includes(currentDayOfWeek)) { // 增加 ruleDays 存在性检查
                    // 检查当前时间是否在规则的时间段内
                    if (currentTimeHHMM >= rule.start_time && currentTimeHHMM <= rule.end_time) {
                        matchedPrice = rule.price_per_hour;
                        break; // 找到第一个匹配规则后即停止
                    }
                }
            }
            res.status(200).json({ price: matchedPrice, free_duration_minutes: freeDurationMinutes }); // 返回匹配价格和免费时长
        });
    });
});


// AdminPanel

// --- API 接口：获取所有轮播图图片 (管理员专用，支持类型筛选) ---
// 路径为 /api/admin/carousel-images，需要管理员权限
// 支持查询参数: type (例如: 'home', 'dashboard')
app.get('/api/admin/carousel-images', authenticateToken, (req, res, next) => {
    const user_id = req.user.id;
    const { type } = req.query; // 获取 type 查询参数

    // 检查用户是否为管理员
    db.get(`SELECT is_admin FROM users WHERE id = ?`, [user_id], (err, userRow) => {
        if (err) {
            console.error('查询管理员权限时数据库错误:', err.message);
            return next(err);
        }
        if (!userRow || userRow.is_admin !== 1) {
            return res.status(403).json({ error: '您没有权限访问此资源。' });
        }

        // 关键修改: 将表名从 home_img 改为 carousel_images
        let sql = `SELECT id, image_url, type, order_index, created_at FROM carousel_images`;
        const params = [];

        // 关键修改: 如果提供了 type 参数，则进行筛选
        // 在 AdminDashboard 组件中，我们会明确传递 type=dashboard
        if (type) {
            sql += ` WHERE type = ?`;
            params.push(type);
        }

        sql += ` ORDER BY order_index ASC, created_at DESC`;

        db.all(sql, params, (err, rows) => {
            if (err) {
                // 关键修改: 更新错误日志信息
                console.error('获取轮播图图片失败 (carousel_images):', err.message);
                return next(err);
            }
            res.status(200).json(rows);
        });
    });
});


// --- API 接口：获取在线访客列表 (管理员专用) ---
// 路径为 /api/admin/online-visitors，需要管理员权限
app.get('/api/admin/online-visitors', authenticateToken, (req, res, next) => {
    const admin_user_id = req.user.id;

    // 检查用户是否为管理员
    db.get(`SELECT is_admin FROM users WHERE id = ?`, [admin_user_id], (err, userRow) => {
        if (err) {
            console.error('查询管理员权限时数据库错误:', err.message);
            return next(err);
        }
        if (!userRow || userRow.is_admin !== 1) {
            return res.status(403).json({ error: '您没有权限访问此资源。' });
        }

        // 查询所有状态为 'ongoing' 的记录，并获取对应的用户头像和名称
        const sql = `
            SELECT 
                u.id AS user_id,
                u.username,
                u.avatar,
                r.in_time
            FROM records r
            JOIN users u ON r.user_id = u.id
            WHERE r.status = 'ongoing'
            ORDER BY r.in_time ASC
        `;
        db.all(sql, [], (err, rows) => {
            if (err) {
                console.error('获取在线访客列表失败:', err.message);
                return next(err);
            }

            res.status(200).json({
                total_online_visitors: rows.length,
                visitors: rows
            });
        });
    });
});


// --- API 接口：获取所有用户 (管理员专用) ---
// 路径为 /api/admin/users，需要管理员权限
app.get('/api/admin/users', authenticateToken, (req, res, next) => {
    const admin_user_id = req.user.id; // 当前操作的管理员用户ID

    // 检查用户是否为管理员
    db.get(`SELECT is_admin FROM users WHERE id = ?`, [admin_user_id], (err, userRow) => {
        if (err) {
            console.error('查询管理员权限时数据库错误:', err.message);
            return next(err);
        }
        if (!userRow || userRow.is_admin !== 1) {
            return res.status(403).json({ error: '您没有权限访问此资源。' });
        }

        // 获取所有用户信息，不包括密码和 email
        // 关键修改: 移除 email 字段
        const sql = `SELECT id, username, balance, is_admin, created_at, phone_number, role, is_active, is_banned FROM users`;
        db.all(sql, [], (err, rows) => {
            if (err) {
                console.error('获取所有用户失败:', err.message);
                return next(err);
            }
            res.status(200).json(rows);
        });
    });
});

// --- API 接口：更新用户 (管理员专用) ---
// 路径为 /api/admin/users/:id，需要管理员权限
// 接收请求体: { username, balance, is_admin, phone_number, role, is_active, is_banned }
app.put('/api/admin/users/:id', authenticateToken, (req, res, next) => {
    const userIdToUpdate = req.params.id; // 要更新的用户ID
    const admin_user_id = req.user.id; // 当前操作的管理员用户ID
    // 关键修改: 从请求体中移除 email
    const { username, balance, is_admin, phone_number, role, is_active, is_banned } = req.body;

    // 新增后端验证：不允许修改ID为1的用户，直接返回200和错误信息
    if (Number(userIdToUpdate) === 1) {
        return res.status(200).json({ error: 'ID 为 1 的用户账户不允许被修改。' });
    }

    // 检查用户是否为管理员
    db.get(`SELECT is_admin FROM users WHERE id = ?`, [admin_user_id], (err, userRow) => {
        if (err) {
            console.error('查询管理员权限时数据库错误:', err.message);
            return next(err);
        }
        if (!userRow || userRow.is_admin !== 1) {
            return res.status(403).json({ error: '您没有权限执行此操作。' });
        }

        let updateFields = [];
        let params = [];

        if (username !== undefined) {
            updateFields.push('username = ?');
            params.push(username);
        }
        if (balance !== undefined && !isNaN(Number(balance))) {
            updateFields.push('balance = ?');
            params.push(Number(balance));
        }
        if (is_admin !== undefined) {
            updateFields.push('is_admin = ?');
            params.push(is_admin ? 1 : 0); // 将布尔值转换为 1 或 0
        }
        // 关键修改: 添加 phone_number, role, is_active, is_banned 的更新逻辑
        if (phone_number !== undefined) {
            updateFields.push('phone_number = ?');
            params.push(phone_number);
        }
        if (role !== undefined) {
            updateFields.push('role = ?');
            params.push(role);
        }
        if (is_active !== undefined) {
            updateFields.push('is_active = ?');
            params.push(is_active ? 1 : 0);
        }
        if (is_banned !== undefined) {
            updateFields.push('is_banned = ?');
            params.push(is_banned ? 1 : 0);
        }

        if (updateFields.length === 0) {
            return res.status(400).json({ error: '没有有效的字段可以更新。' });
        }

        const sql = `UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`;
        params.push(userIdToUpdate);

        db.run(sql, params, function (err) {
            if (err) {
                console.error('更新用户时数据库错误:', err.message);
                return next(err);
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: '未找到要更新的用户或未进行任何更改。' });
            }
            res.status(200).json({ message: '用户更新成功！', updated_user_id: userIdToUpdate });
        });
    });
});

// --- API 接口：删除用户 (管理员专用) ---
// 路径为 /api/admin/users/:id，需要管理员权限
app.delete('/api/admin/users/:id', authenticateToken, (req, res, next) => {
    const userIdToDelete = req.params.id; // 要删除的用户ID
    const admin_user_id = req.user.id; // 当前操作的管理员用户ID

    // 新增后端验证：不允许删除ID为1的用户，直接返回200和错误信息
    if (Number(userIdToDelete) === 1) {
        return res.status(200).json({ error: 'ID 为 1 的用户账户不允许被删除。' });
    }

    // 检查用户是否为管理员
    db.get(`SELECT is_admin FROM users WHERE id = ?`, [admin_user_id], (err, userRow) => {
        if (err) {
            console.error('查询管理员权限时数据库错误:', err.message);
            return next(err);
        }
        if (!userRow || userRow.is_admin !== 1) {
            return res.status(403).json({ error: '您没有权限执行此操作。' });
        }

        // 不允许删除管理员自己
        if (Number(userIdToDelete) === Number(admin_user_id)) {
            return res.status(403).json({ error: '您不能删除您自己的管理员账户。' });
        }

        // 首先检查用户是否存在
        db.get(`SELECT id FROM users WHERE id = ?`, [userIdToDelete], (err, userExists) => {
            if (err) {
                console.error('查询用户是否存在时数据库错误:', err.message);
                return next(err);
            }
            if (!userExists) {
                return res.status(404).json({ error: '要删除的用户不存在。' });
            }

            // 执行删除操作
            const sql = `DELETE FROM users WHERE id = ?`;
            db.run(sql, [userIdToDelete], function (err) {
                if (err) {
                    console.error('删除用户时数据库错误:', err.message);
                    return next(err);
                }
                if (this.changes === 0) {
                    return res.status(404).json({ error: '未找到要删除的用户。' });
                }
                res.status(200).json({ message: '用户删除成功！', deleted_user_id: userIdToDelete });
            });
        });
    });
});


// --- API 接口：获取所有商品订单记录 (管理员专用，支持筛选和模糊搜索) ---
// 路径为 /api/admin/new-orders/all
// 需要管理员权限
// 支持查询参数:
//   - search_term: 模糊搜索订单ID、用户ID或用户名称
//   - start_time: 订单开始时间戳 (秒)
//   - end_time: 订单结束时间戳 (秒)
//   - status: 订单状态 ('pending', 'completed', 'cancelled', etc.)
app.get('/api/admin/orders/all', authenticateToken, (req, res, next) => {
    const user_id = req.user.id;

    db.get(`SELECT is_admin FROM users WHERE id = ?`, [user_id], (err, userRow) => {
        if (err) {
            console.error('查询管理员权限时数据库错误:', err.message);
            return next(err);
        }
        if (!userRow || userRow.is_admin !== 1) {
            return res.status(403).json({ error: '您没有权限访问此资源。' });
        }

        const { search_term, start_time, end_time, status } = req.query;
        let sql = `SELECT 
                        id AS order_db_id,             -- orders表实际主键，用于后端操作
                        session_order_id AS id,        -- 对应 records表的order_id，作为前端展示的订单ID
                        user_id, 
                        user_name, 
                        record_id, 
                        order_time, 
                        items, 
                        total_amount, 
                        status 
                     FROM orders`;
        
        const params = [];
        const conditions = [];

        // 模糊搜索条件：现在搜索 session_order_id, user_name, user_id
        if (search_term) {
            conditions.push(`(session_order_id LIKE ? OR user_name LIKE ? OR user_id = ?)`);
            params.push(`%${search_term}%`, `%${search_term}%`, search_term);
        }

        // 订单时间筛选条件 (orders.order_time)
        if (start_time && !isNaN(Number(start_time))) {
            conditions.push(`order_time >= ?`);
            params.push(Number(start_time));
        }
        if (end_time && !isNaN(Number(end_time))) {
            conditions.push(`order_time <= ?`);
            params.push(Number(end_time));
        }

        // 状态筛选条件 (orders.status)
        if (status) { // 允许任何非空状态字符串
            conditions.push(`status = ?`);
            params.push(status);
        }

        if (conditions.length > 0) {
            sql += ` WHERE ` + conditions.join(' AND ');
        }

        sql += ` ORDER BY order_time DESC`; // 从新到老排序
        
        db.all(sql, params, (err, rows) => {
            if (err) {
                console.error('获取所有商品订单记录失败:', err.message);
                return next(err);
            }
            res.status(200).json(rows);
        });
    });
});

// --- API 接口：更新 orders 表的商品订单记录 (管理员专用) ---
// 路径为 /api/admin/all-orders/:id，这里的 id 是 orders 表的实际主键 (order_db_id)
// 接收请求体: { status, total_amount }
app.put('/api/admin/all-orders/:id', authenticateToken, (req, res, next) => {
    const order_db_id = req.params.id; // 从 URL 参数获取 orders 表的实际主键
    const user_id = req.user.id; // 当前操作的管理员用户ID
    const { status, total_amount } = req.body; // 从请求体获取要更新的字段

    db.get(`SELECT is_admin FROM users WHERE id = ?`, [user_id], (err, userRow) => {
        if (err) {
            console.error('查询管理员权限时数据库错误:', err.message);
            return next(err);
        }
        if (!userRow || userRow.is_admin !== 1) {
            return res.status(403).json({ error: '您没有权限执行此操作。' });
        }

        if (status === undefined && total_amount === undefined) {
            return res.status(400).json({ error: '请求体中至少需要提供一个要更新的字段（status, total_amount）。' });
        }

        let updateFields = [];
        let params = [];

        if (status !== undefined) {
            updateFields.push('status = ?');
            params.push(status);
        }
        if (total_amount !== undefined && !isNaN(Number(total_amount))) {
            updateFields.push('total_amount = ?');
            params.push(Number(total_amount));
        }

        if (updateFields.length === 0) {
            return res.status(400).json({ error: '没有有效的字段可以更新。' });
        }

        const sql = `UPDATE orders SET ${updateFields.join(', ')} WHERE id = ?`;
        params.push(order_db_id); // 使用 orders 表的实际主键进行更新

        db.run(sql, params, function (err) {
            if (err) {
                console.error('更新商品订单记录时数据库错误:', err.message);
                return next(err);
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: '未找到要更新的商品订单记录或未进行任何更改。' });
            }
            res.status(200).json({ message: '商品订单记录更新成功！', updated_id: order_db_id });
        });
    });
});

// --- API 接口：删除 orders 表的商品订单记录 (管理员专用) ---
// 路径为 /api/admin/all-orders/:id，这里的 id 是 orders 表的实际主键 (order_db_id)
app.delete('/api/admin/all-orders/:id', authenticateToken, (req, res, next) => {
    const order_db_id = req.params.id; // 从 URL 参数获取 orders 表的实际主键
    const user_id = req.user.id; // 当前操作的管理员用户ID

    db.get(`SELECT is_admin FROM users WHERE id = ?`, [user_id], (err, userRow) => {
        if (err) {
            console.error('查询管理员权限时数据库错误:', err.message);
            return next(err);
        }
        if (!userRow || userRow.is_admin !== 1) {
            return res.status(403).json({ error: '您没有权限执行此操作。' });
        }

        const sql = `DELETE FROM orders WHERE id = ?`;
        db.run(sql, [order_db_id], function (err) {
            if (err) {
                console.error('删除商品订单记录时数据库错误:', err.message);
                return next(err);
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: '未找到要删除的商品订单记录。' });
            }
            res.status(200).json({ message: '商品订单记录删除成功！', deleted_id: order_db_id });
        });
    });
});

// --- API 接口：获取所有入店订单记录 (管理员专用，支持筛选和模糊搜索) ---
// 路径为 /api/admin/orders/in-store，需要管理员权限
// 支持查询参数:
//   - search_term: 模糊搜索订单ID、用户ID或用户名称
//   - start_time: 入店开始时间戳 (秒)
//   - end_time: 入店结束时间戳 (秒)
app.get('/api/admin/orders/in-store', authenticateToken, (req, res, next) => {
    const user_id = req.user.id;

    // 再次检查用户是否为管理员，以确保接口独立安全性
    db.get(`SELECT is_admin FROM users WHERE id = ?`, [user_id], (err, userRow) => {
        if (err) {
            console.error('查询管理员权限时数据库错误:', err.message);
            return next(err);
        }
        if (!userRow || userRow.is_admin !== 1) {
            // 如果不是管理员，返回 403 Forbidden
            return res.status(403).json({ error: '您没有权限访问此资源。' });
        }

        const { order_id_search, user_name_search, user_id_search, start_time, end_time, status_filter } = req.query; // 关键修改: 添加 status_filter
        let sql = `SELECT 
                        id, 
                        order_id, 
                        user_id, 
                        user_name, 
                        in_time, 
                        out_time, 
                        status, 
                        amount_spent, 
                        unit_price,
                        total_duration_minutes
                     FROM records`;

        const params = [];
        const conditions = [];

        // 关键修改: 移除默认的 `status = 'ongoing'` 筛选。
        // 现在可以通过 `status_filter` 查询参数来筛选状态。

        // 订单ID模糊搜索
        if (order_id_search) {
            conditions.push(`order_id LIKE ?`);
            params.push(`%${order_id_search}%`);
        }
        // 用户名称模糊搜索
        if (user_name_search) {
            conditions.push(`user_name LIKE ?`);
            params.push(`%${user_name_search}%`);
        }
        // 用户ID精确搜索 (假设用户ID是数字，进行精确匹配)
        if (user_id_search && !isNaN(Number(user_id_search))) {
            conditions.push(`user_id = ?`);
            params.push(Number(user_id_search));
        }

        // 时间筛选条件
        if (start_time && !isNaN(Number(start_time))) {
            conditions.push(`in_time >= ?`);
            params.push(Number(start_time));
        }
        if (end_time && !isNaN(Number(end_time))) {
            conditions.push(`in_time <= ?`);
            params.push(Number(end_time));
        }

        // 关键修改: 添加订单状态筛选
        if (status_filter && (status_filter === 'ongoing' || status_filter === 'finished')) {
            conditions.push(`status = ?`);
            params.push(status_filter);
        }

        // 拼接 WHERE 子句
        if (conditions.length > 0) {
            sql += ` WHERE ` + conditions.join(' AND ');
        }

        sql += ` ORDER BY in_time DESC`; // 从新到老排序

        db.all(sql, params, (err, rows) => {
            if (err) {
                console.error('获取订单记录失败:', err.message);
                return next(err);
            }
            res.status(200).json(rows);
        });
    });
});

// --- API 接口：更新订单记录 (管理员专用) ---
// 路径为 /api/admin/orders/:id，需要管理员权限
// 接收请求体: { status, amount_spent, unit_price, total_duration_minutes }
// 注意：此API操作的数据库表名为 'records'，与URL中的资源名称 'orders' 相对应。
app.put('/api/admin/orders/:id', authenticateToken, (req, res, next) => {
    const record_id = req.params.id; // 从 URL 参数获取要更新的记录ID
    const user_id = req.user.id; // 当前操作的管理员用户ID
    // 关键修改: 添加 total_duration_minutes 字段
    const { status, amount_spent, unit_price, total_duration_minutes } = req.body;

    // 再次检查用户是否为管理员，以确保接口独立安全性
    db.get(`SELECT is_admin FROM users WHERE id = ?`, [user_id], (err, userRow) => {
        if (err) {
            console.error('查询管理员权限时数据库错误:', err.message);
            return next(err);
        }
        if (!userRow || userRow.is_admin !== 1) {
            // 如果不是管理员，返回 403 Forbidden
            return res.status(403).json({ error: '您没有权限执行此操作。' });
        }

        // 验证传入的字段
        if (status === undefined && amount_spent === undefined && unit_price === undefined && total_duration_minutes === undefined) {
            return res.status(400).json({ error: '请求体中至少需要提供一个要更新的字段（status, amount_spent, unit_price, total_duration_minutes）。' });
        }

        let updateFields = [];
        let params = [];

        if (status !== undefined) {
            updateFields.push('status = ?');
            params.push(status);
        }
        if (amount_spent !== undefined) {
            updateFields.push('amount_spent = ?');
            params.push(amount_spent);
        }
        if (unit_price !== undefined) {
            updateFields.push('unit_price = ?');
            params.push(unit_price);
        }
        // 关键修改: 允许更新 total_duration_minutes
        if (total_duration_minutes !== undefined && !isNaN(Number(total_duration_minutes))) {
            updateFields.push('total_duration_minutes = ?');
            params.push(Number(total_duration_minutes));
        }


        if (updateFields.length === 0) {
            return res.status(400).json({ error: '没有有效的字段可以更新。' });
        }

        // 构建 SQL 更新语句，明确指定操作 'records' 表
        const sql = `UPDATE records SET ${updateFields.join(', ')} WHERE id = ?`;
        params.push(record_id); // 将记录ID添加到参数列表的最后

        db.run(sql, params, function (err) {
            if (err) {
                console.error('更新订单记录时数据库错误:', err.message);
                return next(err); // 传递错误给全局错误处理中间件
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: '未找到要更新的订单记录或未进行任何更改。' });
            }
            res.status(200).json({ message: '订单记录更新成功！', updated_id: record_id });
        });
    });
});

// --- API 接口：删除订单记录 (管理员专用) ---
// 路径为 /api/admin/orders/:id，需要管理员权限
// 注意：此API操作的数据库表名为 'records'，与URL中的资源名称 'orders' 相对应。
app.delete('/api/admin/orders/:id', authenticateToken, (req, res, next) => {
    const record_id = req.params.id; // 从 URL 参数获取要删除的记录ID
    const user_id = req.user.id; // 当前操作的管理员用户ID

    // 再次检查用户是否为管理员，以确保接口独立安全性
    db.get(`SELECT is_admin FROM users WHERE id = ?`, [user_id], (err, userRow) => {
        if (err) {
            console.error('查询管理员权限时数据库错误:', err.message);
            return next(err);
        }
        if (!userRow || userRow.is_admin !== 1) {
            // 如果不是管理员，返回 403 Forbidden
            return res.status(403).json({ error: '您没有权限执行此操作。' });
        }

        // 构建 SQL 删除语句，明确指定操作 'records' 表
        const sql = `DELETE FROM records WHERE id = ?`;
        db.run(sql, [record_id], function (err) {
            if (err) {
                console.error('删除订单记录时数据库错误:', err.message);
                return next(err);
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: '未找到要删除的订单记录。' });
            }
            res.status(200).json({ message: '订单记录删除成功！', deleted_id: record_id });
        });
    });
});

// --- API 接口：获取所有价格规则 (管理员专用) ---
app.get('/api/admin/price-settings', authenticateToken, (req, res, next) => {
    const user_id = req.user.id;

    db.get(`SELECT is_admin FROM users WHERE id = ?`, [user_id], (err, userRow) => {
        if (err) {
            console.error('查询管理员权限时数据库错误:', err.message);
            return next(err);
        }
        if (!userRow || userRow.is_admin !== 1) {
            // 关键修改: 非管理员返回 403 Forbidden
            return res.status(403).json({ error: '您没有权限访问此资源。' });
        }

        const sql = `SELECT id, day_of_week, start_time, end_time, price_per_hour FROM price_settings ORDER BY id ASC`;
        db.all(sql, [], (err, rows) => {
            if (err) {
                console.error('获取价格规则失败:', err.message);
                return next(err);
            }
            res.status(200).json(rows);
        });
    });
});

// --- API 接口：获取所有价格规则 (管理员专用) ---
app.get('/api/admin/price-settings', authenticateToken, (req, res, next) => {
    const user_id = req.user.id;

    db.get(`SELECT is_admin FROM users WHERE id = ?`, [user_id], (err, userRow) => {
        if (err) {
            console.error('查询管理员权限时数据库错误:', err.message);
            return next(err);
        }
        if (!userRow || userRow.is_admin !== 1) {
            return res.status(403).json({ error: '您没有权限访问此资源。' });
        }

        // 移除了 is_default 字段和排序
        const sql = `SELECT id, day_of_week, start_time, end_time, price_per_hour FROM price_settings ORDER BY id ASC`;
        db.all(sql, [], (err, rows) => {
            if (err) {
                console.error('获取价格规则失败:', err.message);
                return next(err);
            }
            res.status(200).json(rows);
        });
    });
});

// --- API 接口：添加新的价格规则 (管理员专用) ---
app.post('/api/admin/price-settings', authenticateToken, (req, res, next) => {
    const user_id = req.user.id;
    // 移除了 is_default
    const { day_of_week, start_time, end_time, price_per_hour } = req.body;

    db.get(`SELECT is_admin FROM users WHERE id = ?`, [user_id], (err, userRow) => {
        if (err) {
            console.error('查询管理员权限时数据库错误:', err.message);
            return next(err);
        }
        if (!userRow || userRow.is_admin !== 1) {
            return res.status(403).json({ error: '您没有权限执行此操作。' });
        }

        // 验证所有字段，因为没有默认规则
        if (!day_of_week || !start_time || !end_time || price_per_hour === undefined || isNaN(price_per_hour)) {
            return res.status(400).json({ error: '缺少必要的字段（day_of_week, start_time, end_time, price_per_hour）。' });
        }

        // 移除了 is_default 相关逻辑
        const sql = `INSERT INTO price_settings (day_of_week, start_time, end_time, price_per_hour) VALUES (?, ?, ?, ?)`;
        db.run(sql, [day_of_week, start_time, end_time, price_per_hour], function (err) {
            if (err) {
                console.error('添加价格规则失败:', err.message);
                return next(err);
            }
            res.status(201).json({ message: '价格规则添加成功！', id: this.lastID });
        });
    });
});

// --- API 接口：更新价格规则 (管理员专用) ---
app.put('/api/admin/price-settings/:id', authenticateToken, (req, res, next) => {
    const rule_id = req.params.id;
    const user_id = req.user.id;
    // 移除了 is_default
    const { day_of_week, start_time, end_time, price_per_hour } = req.body;

    db.get(`SELECT is_admin FROM users WHERE id = ?`, [user_id], (err, userRow) => {
        if (err) {
            console.error('查询管理员权限时数据库错误:', err.message);
            return next(err);
        }
        if (!userRow || userRow.is_admin !== 1) {
            return res.status(403).json({ error: '您没有权限执行此操作。' });
        }

        // 验证所有字段，因为没有默认规则
        if (!day_of_week || !start_time || !end_time || price_per_hour === undefined || isNaN(price_per_hour)) {
            return res.status(400).json({ error: '缺少必要的字段（day_of_week, start_time, end_time, price_per_hour）。' });
        }

        // 移除了 is_default 相关逻辑
        const sql = `UPDATE price_settings SET day_of_week = ?, start_time = ?, end_time = ?, price_per_hour = ? WHERE id = ?`;
        db.run(sql, [day_of_week, start_time, end_time, price_per_hour, rule_id], function (err) {
            if (err) {
                console.error('更新价格规则失败:', err.message);
                return next(err);
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: '未找到要更新的价格规则或未进行任何更改。' });
            }
            res.status(200).json({ message: '价格规则更新成功！', updated_id: rule_id });
        });
    });
});

// --- API 接口：删除价格规则 (管理员专用) ---
app.delete('/api/admin/price-settings/:id', authenticateToken, (req, res, next) => {
    const rule_id = req.params.id;
    const user_id = req.user.id;

    db.get(`SELECT is_admin FROM users WHERE id = ?`, [user_id], (err, userRow) => {
        if (err) {
            console.error('查询管理员权限时数据库错误:', err.message);
            return next(err);
        }
        if (!userRow || userRow.is_admin !== 1) {
            return res.status(403).json({ error: '您没有权限执行此操作。' });
        }

        const sql = `DELETE FROM price_settings WHERE id = ?`;
        db.run(sql, [rule_id], function (err) {
            if (err) {
                console.error('删除价格规则失败:', err.message);
                return next(err);
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: '未找到要删除的价格规则。' });
            }
            res.status(200).json({ message: '价格规则删除成功！', deleted_id: rule_id });
        });
    });
});

// --- API 接口：获取特定类型的轮播图 (管理员专用) ---
// 路径为 /api/admin/carousel/:type，需要管理员权限
// :type 可以是 'home' 或 'dashboard'
app.get('/api/admin/carousel/:type', authenticateToken, (req, res, next) => {
    const user_id = req.user.id;
    const carousel_type = req.params.type; // 'home' 或 'dashboard'

    // 验证轮播图类型
    if (carousel_type !== 'home' && carousel_type !== 'dashboard') {
        return res.status(400).json({ error: '无效的轮播图类型。' });
    }

    db.get(`SELECT is_admin FROM users WHERE id = ?`, [user_id], (err, userRow) => {
        if (err) {
            console.error('查询管理员权限时数据库错误:', err.message);
            return next(err);
        }
        if (!userRow || userRow.is_admin !== 1) {
            return res.status(403).json({ error: '您没有权限访问此资源。' });
        }

        const sql = `SELECT id, image_url, type, order_index, created_at FROM carousel_images WHERE type = ? ORDER BY order_index ASC, created_at DESC`;
        db.all(sql, [carousel_type], (err, rows) => {
            if (err) {
                console.error(`获取${carousel_type}轮播图失败:`, err.message);
                return next(err);
            }
            res.status(200).json(rows);
        });
    });
});

// --- API 接口：添加特定类型的轮播图 (管理员专用) ---
// 路径为 /api/admin/carousel/:type，需要管理员权限
// 接收请求体: { image_url, order }
app.post('/api/admin/carousel/:type', authenticateToken, (req, res, next) => {
    const user_id = req.user.id;
    const carousel_type = req.params.type; // 'home' 或 'dashboard'
    const { image_url, order } = req.body; // 注意：这里使用 'order' 字段名

    // 验证轮播图类型
    if (carousel_type !== 'home' && carousel_type !== 'dashboard') {
        return res.status(400).json({ error: '无效的轮播图类型。' });
    }

    db.get(`SELECT is_admin FROM users WHERE id = ?`, [user_id], (err, userRow) => {
        if (err) {
            console.error('查询管理员权限时数据库错误:', err.message);
            return next(err);
        }
        if (!userRow || userRow.is_admin !== 1) {
            return res.status(403).json({ error: '您没有权限执行此操作。' });
        }

        // 验证输入
        if (!image_url || image_url.trim() === '') {
            return res.status(400).json({ error: '图片URL不能为空。' });
        }
        if (order === undefined || isNaN(Number(order))) {
            return res.status(400).json({ error: '排序值必须是有效数字。' });
        }

        const sql = `INSERT INTO carousel_images (image_url, type, order_index, created_at) VALUES (?, ?, ?, ?)`;
        const createdAt = Math.floor(Date.now() / 1000); // 秒级时间戳
        db.run(sql, [image_url, carousel_type, Number(order), createdAt], function (err) {
            if (err) {
                console.error(`添加${carousel_type}轮播图失败:`, err.message);
                return next(err);
            }
            res.status(201).json({ message: `添加${carousel_type}轮播图成功！`, id: this.lastID });
        });
    });
});

// --- API 接口：删除特定类型的轮播图 (管理员专用) ---
// 路径为 /api/admin/carousel/:type/:id，需要管理员权限
app.delete('/api/admin/carousel/:type/:id', authenticateToken, (req, res, next) => {
    const user_id = req.user.id;
    const carousel_type = req.params.type; // 'home' 或 'dashboard'
    const image_id = req.params.id; // 要删除的图片ID

    // 验证轮播图类型
    if (carousel_type !== 'home' && carousel_type !== 'dashboard') {
        return res.status(400).json({ error: '无效的轮播图类型。' });
    }

    db.get(`SELECT is_admin FROM users WHERE id = ?`, [user_id], (err, userRow) => {
        if (err) {
            console.error('查询管理员权限时数据库错误:', err.message);
            return next(err);
        }
        if (!userRow || userRow.is_admin !== 1) {
            return res.status(403).json({ error: '您没有权限执行此操作。' });
        }

        const sql = `DELETE FROM carousel_images WHERE id = ? AND type = ?`;
        db.run(sql, [image_id, carousel_type], function (err) {
            if (err) {
                console.error(`删除${carousel_type}轮播图失败:`, err.message);
                return next(err);
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: '未找到要删除的轮播图。' });
            }
            res.status(200).json({ message: `轮播图删除成功！`, deleted_id: image_id });
        });
    });
});


// --- API 接口：获取平台设置 (管理员专用) ---
app.get('/api/admin/settings/platform', authenticateToken, (req, res, next) => {
    const user_id = req.user.id;
    db.get(`SELECT is_admin FROM users WHERE id = ?`, [user_id], (err, userRow) => {
        if (err) {
            console.error('查询管理员权限时数据库错误:', err.message);
            return next(err);
        }
        if (!userRow || userRow.is_admin !== 1) {
            return res.status(403).json({ error: '您没有权限访问此资源。' });
        }

        // 关键修改: 查询 account_approval_required 字段
        db.get(`SELECT default_price, free_duration_minutes, customer_service_contact, account_approval_required FROM platform_settings WHERE id = 1`, (err, settings) => {
            if (err) {
                console.error('获取平台设置失败:', err.message);
                return next(err);
            }
            if (!settings) {
                // 如果没有找到设置，返回默认值
                // 关键修改: 默认值中包含 account_approval_required
                return res.status(200).json({
                    default_price: 5.00,
                    free_duration_minutes: 10,
                    customer_service_contact: '请联系客服：123456789',
                    account_approval_required: 0 // 默认不需要审批
                });
            }
            res.status(200).json(settings);
        });
    });
});

// --- API 接口：更新平台设置 (管理员专用) ---
app.put('/api/admin/settings/platform', authenticateToken, (req, res, next) => {
    const user_id = req.user.id;
    // 关键修改: 接收 account_approval_required 字段
    const { default_price, free_duration_minutes, customer_service_contact, account_approval_required } = req.body;

    db.get(`SELECT is_admin FROM users WHERE id = ?`, [user_id], (err, userRow) => {
        if (err) {
            console.error('查询管理员权限时数据库错误:', err.message);
            return next(err);
        }
        if (!userRow || userRow.is_admin !== 1) {
            return res.status(403).json({ error: '您没有权限执行此操作。' });
        }

        if (default_price === undefined || isNaN(default_price) || default_price < 0.01 ||
            free_duration_minutes === undefined || isNaN(free_duration_minutes) || free_duration_minutes < 0 ||
            !customer_service_contact || customer_service_contact.trim() === '' ||
            account_approval_required === undefined || (account_approval_required !== 0 && account_approval_required !== 1)) { // 关键修改: 验证 account_approval_required
            return res.status(400).json({ error: '无效的设置参数。' });
        }

        // 关键修改: 更新语句中包含 account_approval_required
        const sql = `UPDATE platform_settings SET default_price = ?, free_duration_minutes = ?, customer_service_contact = ?, account_approval_required = ? WHERE id = 1`;
        db.run(sql, [default_price, free_duration_minutes, customer_service_contact, account_approval_required], function (err) {
            if (err) {
                console.error('更新平台设置失败:', err.message);
                return next(err);
            }
            if (this.changes === 0) {
                // 如果没有更新，尝试插入默认值（这不应该发生如果表初始化正确）
                // 关键修改: 插入默认值时也包含 account_approval_required
                db.run(`INSERT OR IGNORE INTO platform_settings (id, default_price, free_duration_minutes, customer_service_contact, account_approval_required) VALUES (1, ?, ?, ?, ?)`,
                    [default_price, free_duration_minutes, customer_service_contact, account_approval_required], (insertErr) => {
                        if (insertErr) {
                            console.error('插入平台设置失败:', insertErr.message);
                            return next(insertErr);
                        }
                        res.status(200).json({ message: '平台设置更新成功！' });
                    });
            } else {
                res.status(200).json({ message: '平台设置更新成功！' });
            }
        });
    });
});



// 关键修改：全局 404 错误处理中间件
app.use((req, res, next) => {
    res.status(404).json({ error: '资源未找到。' });
});

// 关键修改：全局错误处理中间件，捕获所有未处理的错误
// 必须放在所有路由和 404 处理之后
app.use((err, req, res, next) => {
    console.error('全局捕获到错误:', err.stack); // 打印错误堆栈到服务器日志

    // 根据错误类型或状态码进行处理
    if (err.status >= 500 || !err.status) { // 默认所有未指定状态码的错误都认为是 500
        res.status(500).json({ error: '服务端错误' });
    } else {
        res.status(err.status || 500).json({ error: err.message || '未知错误' });
    }
});

// --- 启动服务器 ---
app.listen(PORT, () => {
    console.log(`服务器正在端口 ${PORT} 上运行`);
});