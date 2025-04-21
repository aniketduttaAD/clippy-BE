const express = require('express');
const bodyParser = require('body-parser');
const { Telegraf } = require('telegraf');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const http = require('http');
const validator = require('validator');
const winston = require('winston');
require('dotenv').config();

// Initialize logger
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        winston.format.printf(info => `${info.timestamp} ${info.level}: ${info.message}`)
    ),
    transports: [
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
                winston.format.printf(info => `${info.timestamp} ${info.level}: ${info.message}`)
            )
        }),
        new winston.transports.File({
            filename: 'error.log',
            level: 'error',
            maxsize: 5242880,
            maxFiles: 5
        }),
        new winston.transports.File({
            filename: 'combined.log',
            maxsize: 5242880,
            maxFiles: 5
        })
    ]
});

const {
    PORT,
    NODE_ENV = 'development',
    TELEGRAM_BOT_TOKEN,
    JWT_SECRET,
    ENCRYPTION_MASTER_KEY,
    ENCRYPTION_KEY_ROTATION_DAYS = 30,
    SESSION_TOKEN_EXPIRY = '1d',
    REFRESH_TOKEN_EXPIRY = '7d'
} = process.env;

if (!TELEGRAM_BOT_TOKEN || !JWT_SECRET || !ENCRYPTION_MASTER_KEY) {
    logger.error('Critical environment variables missing. Check your .env file (TELEGRAM_BOT_TOKEN, JWT_SECRET, ENCRYPTION_MASTER_KEY)');
    process.exit(1);
}

const app = express();

app.use(bodyParser.json({ limit: '100kb' }));

app.use(cors({
    origin: (origin, callback) => {
        const isChromeExtension = origin && origin.startsWith('chrome-extension://');
        const isOtherAllowed = !origin || origin === 'null';
        if (isChromeExtension || isOtherAllowed) {
            return callback(null, true);
        } else {
            logger.warn(`CORS rejected origin: ${origin}`);
            return callback(new Error('CORS not allowed for this origin'));
        }
    },
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    maxAge: 86400
}));

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'"],
            connectSrc: ["'self'"],
            upgradeInsecureRequests: []
        }
    },
    hsts: NODE_ENV === 'production' ? {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    } : false,
    noSniff: true,
    frameguard: { action: 'deny' },
    xssFilter: true
}));

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, error: 'Too many requests, please try again later' },
});

const authLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, error: 'Too many authentication attempts' }
});

app.use('/api/', apiLimiter);
app.use('/api/auth/refresh', authLimiter);
app.use('/api/auth/token', authLimiter);

app.set('trust proxy', 1);

let bot;
try {
    bot = new Telegraf(TELEGRAM_BOT_TOKEN);
} catch (error) {
    logger.error(`Failed to initialize Telegram Bot: ${error.message}`);
    process.exit(1);
}

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE_PATH = path.join(DATA_DIR, 'encrypted-users.json');
const ENCRYPTION_KEYS_PATH = path.join(DATA_DIR, 'encryption-keys.json');
const MESSAGES_FILE_PATH = path.join(DATA_DIR, 'encrypted-messages.json');

async function ensureDataDirectory() {
    try {
        await fs.mkdir(DATA_DIR, { recursive: true });
        logger.info(`Data directory ensured at: ${DATA_DIR}`);
    } catch (error) {
        logger.error(`Failed to create data directory: ${error.message}`);
        process.exit(1);
    }
}

const keyManager = {
    keys: [],
    currentKeyId: null,

    async initialize() {
        await ensureDataDirectory();
        try {
            const data = await fs.readFile(ENCRYPTION_KEYS_PATH, 'utf8')
                .catch((err) => {
                    if (err.code === 'ENOENT') {
                        logger.info('Encryption keys file not found, initializing new one.');
                        return '{"keys":[]}';
                    }
                    throw err;
                });

            const keysData = JSON.parse(data);
            this.keys = keysData.keys || [];
            logger.info(`Loaded ${this.keys.length} encryption key(s)`);

            const now = Date.now();
            let currentKey = this.keys.find(k =>
                k.expiresAt > now && k.createdAt <= now
            );

            if (!currentKey) {
                logger.info('No valid current key found or key expired. Generating new key.');
                currentKey = this.generateNewKey();
                this.keys.push(currentKey);
                await this.saveKeys();
            } else {
                logger.info(`Using existing encryption key ID: ${currentKey.id}`);
            }

            this.currentKeyId = currentKey.id;

            const ninetyDaysAgo = now - (90 * 24 * 60 * 60 * 1000);
            const originalKeyCount = this.keys.length;
            this.keys = this.keys.filter(k =>
                k.expiresAt > ninetyDaysAgo || k.id === this.currentKeyId
            );

            if (this.keys.length < originalKeyCount) {
                logger.info(`Cleaned up ${originalKeyCount - this.keys.length} expired encryption keys.`);
                await this.saveKeys();
            }

        } catch (error) {
            logger.error(`Error initializing encryption keys: ${error.message}`);
            logger.info('Attempting recovery by generating a new encryption key.');
            const currentKey = this.generateNewKey();
            this.keys = [currentKey];
            this.currentKeyId = currentKey.id;
            await this.saveKeys().catch(saveErr => {
                logger.error(`CRITICAL: Failed to save new key during error recovery: ${saveErr.message}`);
                process.exit(1);
            });
        }
    },

    generateNewKey() {
        const keyId = crypto.randomBytes(8).toString('hex');
        const key = crypto.randomBytes(32).toString('hex');
        const encryptedKey = this.encryptWithMasterKey(key);
        const now = Date.now();
        const expiryDays = parseInt(ENCRYPTION_KEY_ROTATION_DAYS, 10);
        const expiresAt = now + (expiryDays * 24 * 60 * 60 * 1000);
        logger.info(`Generated new encryption key ID: ${keyId}, expires: ${new Date(expiresAt).toISOString()}`);
        return { id: keyId, key: encryptedKey, createdAt: now, expiresAt };
    },

    async saveKeys() {
        try {
            await fs.writeFile(
                ENCRYPTION_KEYS_PATH,
                JSON.stringify({ keys: this.keys }, null, 2),
                'utf8'
            );
            logger.info(`Encryption keys saved to ${ENCRYPTION_KEYS_PATH}`);
        } catch (error) {
            logger.error(`Failed to save encryption keys: ${error.message}`);
        }
    },

    encryptWithMasterKey(text) {
        try {
            const iv = crypto.randomBytes(16);
            const derivedKey = crypto.createHash('sha256').update(String(ENCRYPTION_MASTER_KEY)).digest();
            const cipher = crypto.createCipheriv('aes-256-cbc', derivedKey, iv);
            let encrypted = cipher.update(String(text), 'utf8', 'hex');
            encrypted += cipher.final('hex');
            return iv.toString('hex') + ':' + encrypted;
        } catch (error) {
            logger.error(`Master key encryption failed: ${error.message}`);
            throw new Error("Master key encryption failed");
        }
    },

    decryptWithMasterKey(text) {
        try {
            const parts = text.split(':');
            if (parts.length !== 2) throw new Error("Invalid master key encrypted format");
            const iv = Buffer.from(parts[0], 'hex');
            const encryptedText = parts[1];
            const derivedKey = crypto.createHash('sha256').update(String(ENCRYPTION_MASTER_KEY)).digest();
            const decipher = crypto.createDecipheriv('aes-256-cbc', derivedKey, iv);
            let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            return decrypted;
        } catch (error) {
            logger.error(`Master key decryption failed: ${error.message}`);
            throw new Error("Master key decryption failed");
        }
    },

    getCurrentKey() {
        const keyObj = this.keys.find(k => k.id === this.currentKeyId);
        if (!keyObj) {
            logger.error(`Critical: Current encryption key with ID ${this.currentKeyId} not found!`);
            throw new Error('Current encryption key configuration error');
        }
        try {
            return this.decryptWithMasterKey(keyObj.key);
        } catch (error) {
            logger.error(`Critical: Failed to decrypt current key ID ${this.currentKeyId}: ${error.message}`);
            throw new Error('Failed to access current encryption key');
        }
    },

    getKeyById(keyId) {
        const keyObj = this.keys.find(k => k.id === keyId);
        if (!keyObj) {
            logger.warn(`Encryption key with ID ${keyId} not found during decryption attempt.`);
            throw new Error(`Encryption key not found`);
        }
        try {
            return this.decryptWithMasterKey(keyObj.key);
        } catch (error) {
            logger.error(`Failed to decrypt key ID ${keyId}: ${error.message}`);
            throw new Error('Failed to access required encryption key');
        }
    }
};

function encrypt(text) {
    try {
        const iv = crypto.randomBytes(16);
        const currentKeyHex = keyManager.getCurrentKey();
        if (!currentKeyHex) throw new Error("Encryption key unavailable");
        const key = Buffer.from(currentKeyHex, 'hex');
        const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        const inputText = typeof text === 'string' ? text : JSON.stringify(text);
        let encrypted = cipher.update(Buffer.from(inputText, 'utf8'));
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        return `${keyManager.currentKeyId}:${iv.toString('hex')}:${encrypted.toString('hex')}`;
    } catch (error) {
        logger.error(`Encryption error: ${error.message}`);
        throw new Error('Failed to encrypt data');
    }
}

function decrypt(encryptedText) {
    try {
        if (typeof encryptedText !== 'string' || !encryptedText.includes(':')) {
            throw new Error('Invalid encrypted data format (not a string or missing delimiters)');
        }
        const parts = encryptedText.split(':');
        if (parts.length !== 3) {
            logger.error(`Invalid encrypted data format. Expected 3 parts, got ${parts.length}. Data: ${encryptedText.substring(0, 50)}...`);
            throw new Error('Invalid encrypted data format');
        }
        const [keyId, ivHex, encryptedHex] = parts;
        if (!/^[a-f0-9]+$/i.test(keyId) || !/^[a-f0-9]+$/i.test(ivHex) || !/^[a-f0-9]+$/i.test(encryptedHex)) {
            throw new Error("Invalid hex character in encrypted data components");
        }
        const keyHex = keyManager.getKeyById(keyId);
        if (!keyHex) throw new Error(`Decryption key unavailable for ID: ${keyId}`);
        const key = Buffer.from(keyHex, 'hex');
        const iv = Buffer.from(ivHex, 'hex');
        const encryptedData = Buffer.from(encryptedHex, 'hex');
        if (iv.length !== 16) {
            throw new Error(`Invalid IV length: ${iv.length}`);
        }
        const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
        let decrypted = decipher.update(encryptedData);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        try {
            return JSON.parse(decrypted.toString('utf8'));
        } catch (parseError) {
            logger.error(`Decryption succeeded, but JSON parsing failed: ${parseError.message}`);
            throw new Error("Failed to parse decrypted data");
        }
    } catch (error) {
        logger.error(`Decryption error: ${error.message}`);
        if (error.message.includes("key") || error.message.includes("IV")) {
            throw new Error("Decryption failed due to key or data integrity issue.");
        }
        throw new Error('Failed to decrypt data');
    }
}

const userDb = {
    users: {},

    async load() {
        try {
            await fs.access(USERS_FILE_PATH);
            const encryptedData = await fs.readFile(USERS_FILE_PATH, 'utf8');
            if (encryptedData) {
                logger.info(`User data file found (${encryptedData.length} bytes), attempting decryption...`);
                this.users = decrypt(encryptedData);
                logger.info(`Successfully loaded and decrypted data for ${Object.keys(this.users).length} users.`);
            } else {
                logger.info('User data file is empty, initializing empty user store.');
                this.users = {};
            }
        } catch (error) {
            if (error.code === 'ENOENT') {
                logger.info('User data file not found. Initializing empty user store.');
                this.users = {};
                await this.save();
            } else {
                logger.error(`CRITICAL Error loading user database: ${error.message}`);
                logger.error("Server continuing with an empty user store due to load error. PREVIOUS USER DATA MAY BE LOST IF NOT RECOVERED.");
                this.users = {};
            }
        }
    },

    async save() {
        try {
            const encryptedData = encrypt(this.users);
            await fs.writeFile(USERS_FILE_PATH, encryptedData, 'utf8');
            logger.info(`User database saved (${encryptedData.length} bytes).`);
        } catch (error) {
            logger.error(`Error saving user database: ${error.message}`);
            throw new Error('Failed to save user data');
        }
    },

    getByTelegramId(telegramId) {
        if (!telegramId) return null;
        const stringId = String(telegramId);
        for (const clippyId in this.users) {
            if (String(this.users[clippyId].telegramId) === stringId) {
                return { clippyId, ...this.users[clippyId] };
            }
        }
        return null;
    },

    getByClippyId(clippyId) {
        if (!clippyId || !this.users[clippyId]) return null;
        return { clippyId, ...this.users[clippyId] };
    },

    async addUser(telegramId) {
        if (!telegramId) throw new Error('Telegram ID is required');
        const stringId = String(telegramId);
        if (this.getByTelegramId(stringId)) {
            logger.warn(`Attempted to re-register existing Telegram ID: ${stringId}`);
            throw new Error('This Telegram account is already registered.');
        }
        let clippyId;
        let attempts = 0;
        const MAX_ATTEMPTS = 10;
        do {
            if (attempts >= MAX_ATTEMPTS) {
                logger.error('Failed to generate unique Clippy ID after multiple attempts.');
                throw new Error('Failed to generate a unique user ID. Please try again later.');
            }
            const randomBytes = crypto.randomBytes(4);
            const randomDigits = (parseInt(randomBytes.toString('hex'), 16) % 9000) + 1000;
            clippyId = `clippy${randomDigits}`;
            attempts++;
        } while (this.users[clippyId]);
        logger.info(`Assigning new Clippy ID ${clippyId} to Telegram ID ${stringId}`);
        this.users[clippyId] = {
            telegramId: stringId,
            createdAt: new Date().toISOString(),
            lastActivity: new Date().toISOString(),
            refreshTokens: [],
            failedAttempts: 0
        };
        await this.save();
        return clippyId;
    },

    async updateLastActivity(clippyId) {
        if (!this.users[clippyId]) {
            logger.warn(`Attempted to update last activity for non-existent user: ${clippyId}`);
            return false;
        }
        this.users[clippyId].lastActivity = new Date().toISOString();
        await this.save();
        return true;
    },

    async addRefreshToken(clippyId, tokenId) {
        if (!this.users[clippyId]) {
            logger.warn(`Attempted to add refresh token for non-existent user: ${clippyId}`);
            return false;
        }
        if (!this.users[clippyId].refreshTokens) {
            this.users[clippyId].refreshTokens = [];
        }
        const MAX_REFRESH_TOKENS = 5;
        this.users[clippyId].refreshTokens = [
            ...(this.users[clippyId].refreshTokens || []),
            tokenId
        ].slice(-MAX_REFRESH_TOKENS);
        await this.save();
        logger.info(`Added refresh token JTI ${tokenId.substring(0, 8)}... for user ${clippyId}. Total: ${this.users[clippyId].refreshTokens.length}`);
        return true;
    },

    async removeRefreshToken(clippyId, tokenId) {
        if (!this.users[clippyId] || !this.users[clippyId].refreshTokens) {
            logger.warn(`Attempted to remove refresh token for user ${clippyId} but no tokens found.`);
            return false;
        }
        const initialLength = this.users[clippyId].refreshTokens.length;
        this.users[clippyId].refreshTokens = this.users[clippyId].refreshTokens
            .filter(id => id !== tokenId);
        if (this.users[clippyId].refreshTokens.length < initialLength) {
            await this.save();
            logger.info(`Removed refresh token JTI ${tokenId.substring(0, 8)}... for user ${clippyId}. Remaining: ${this.users[clippyId].refreshTokens.length}`);
            return true;
        }
        logger.info(`Refresh token JTI ${tokenId.substring(0, 8)}... not found for user ${clippyId} during removal.`);
        return false;
    },

    async validateRefreshToken(clippyId, tokenId) {
        if (!this.users[clippyId] || !this.users[clippyId].refreshTokens) return false;
        return this.users[clippyId].refreshTokens.some(storedId => storedId === tokenId);
    }
};

// Message database to store user messages
// Message database to store user messages
const messageDb = {
    messages: {},

    async load() {
        try {
            await fs.access(MESSAGES_FILE_PATH);
            const encryptedData = await fs.readFile(MESSAGES_FILE_PATH, 'utf8');
            if (encryptedData) {
                logger.info(`Message data file found (${encryptedData.length} bytes), attempting decryption...`);
                this.messages = decrypt(encryptedData);
                logger.info(`Successfully loaded and decrypted messages for ${Object.keys(this.messages).length} users.`);
            } else {
                logger.info('Message data file is empty, initializing empty message store.');
                this.messages = {};
            }
        } catch (error) {
            if (error.code === 'ENOENT') {
                logger.info('Message data file not found. Initializing empty message store.');
                this.messages = {};
                await this.save();
            } else {
                logger.error(`Error loading message database: ${error.message}`);
                logger.error("Server continuing with an empty message store due to load error.");
                this.messages = {};
            }
        }
    },

    async save() {
        try {
            const encryptedData = encrypt(this.messages);
            await fs.writeFile(MESSAGES_FILE_PATH, encryptedData, 'utf8');
            logger.info(`Message database saved (${encryptedData.length} bytes).`);
        } catch (error) {
            logger.error(`Error saving message database: ${error.message}`);
            throw new Error('Failed to save message data');
        }
    },

    async storeMessage(clippyId, messageText) {
        try {
            if (!this.messages[clippyId]) {
                this.messages[clippyId] = [];
            }
            const message = {
                text: messageText,
                timestamp: new Date().toISOString()
            };
            this.messages[clippyId].unshift(message);
            if (this.messages[clippyId].length > 5) {
                this.messages[clippyId].length = 5;
            }
            await this.save();
            logger.info(`Stored new message for user ${clippyId}, now has ${this.messages[clippyId].length} recent messages`);
            return true;
        } catch (error) {
            logger.error(`Error storing message for user ${clippyId}: ${error.message}`);
            return false;
        }
    },

    getLatestMessage(clippyId) {
        if (!this.messages[clippyId] || this.messages[clippyId].length === 0) {
            return null;
        }
        return this.messages[clippyId][0];
    }
};

function generateTokens(userId) {
    const tokenId = crypto.randomBytes(16).toString('hex');
    const sessionToken = jwt.sign(
        { userId: userId, type: 'session', jti: tokenId },
        JWT_SECRET,
        { expiresIn: SESSION_TOKEN_EXPIRY }
    );
    const refreshToken = jwt.sign(
        { userId: userId, type: 'refresh', jti: tokenId },
        JWT_SECRET,
        { expiresIn: REFRESH_TOKEN_EXPIRY }
    );
    userDb.addRefreshToken(userId, tokenId).catch(error => {
        logger.error(`Failed to add refresh token ${tokenId} for user ${userId}: ${error.message}`);
    });
    return { sessionToken, refreshToken };
}

function verifyToken(req, res, next) {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) {
            return res.status(401).json({
                success: false,
                error: 'Authentication required. No token provided.'
            });
        }
        const parts = authHeader.split(' ');
        if (parts.length !== 2 || parts[0] !== 'Bearer') {
            return res.status(401).json({
                success: false,
                error: 'Invalid token format. Expected "Bearer <token>".'
            });
        }
        const token = parts[1];
        if (!token || token.length < 10) {
            return res.status(401).json({
                success: false,
                error: 'Invalid token format or missing token.'
            });
        }
        jwt.verify(token, JWT_SECRET, (err, decoded) => {
            if (err) {
                logger.warn(`Token verification failed: ${err.name} - ${err.message}`);
                if (err.name === 'TokenExpiredError') {
                    return res.status(401).json({
                        success: false,
                        error: 'Token expired',
                        code: 'TOKEN_EXPIRED'
                    });
                }
                return res.status(403).json({
                    success: false,
                    error: 'Invalid or malformed token',
                    code: 'INVALID_TOKEN'
                });
            }
            if (decoded.type !== 'session') {
                logger.warn(`Attempt to use non-session token (type: ${decoded.type}) for protected route.`);
                return res.status(403).json({
                    success: false,
                    error: 'Invalid token type. Expected session token.',
                    code: 'INVALID_TOKEN_TYPE'
                });
            }
            if (!decoded.userId) {
                logger.error('Token decoded successfully but missing userId payload.');
                return res.status(403).json({
                    success: false,
                    error: 'Invalid token payload.',
                    code: 'INVALID_TOKEN_PAYLOAD'
                });
            }
            req.userId = decoded.userId;
            req.tokenId = decoded.jti;
            next();
        });
    } catch (error) {
        logger.error(`Auth middleware unexpected error: ${error.message}`);
        return res.status(500).json({
            success: false,
            error: 'Internal server error during authentication.'
        });
    }
}

function validateMessageInput(req, res, next) {
    const { message } = req.body;
    if (message == null) {
        return res.status(400).json({
            success: false,
            error: 'Missing "message" field in request body.'
        });
    }
    if (typeof message !== 'string') {
        return res.status(400).json({
            success: false,
            error: 'The "message" field must be a string.'
        });
    }
    const trimmedMessage = message.trim();
    if (trimmedMessage.length === 0) {
        return res.status(400).json({
            success: false,
            error: 'Message cannot be empty or contain only whitespace.'
        });
    }
    const MAX_MESSAGE_LENGTH = 4096;
    if (trimmedMessage.length > MAX_MESSAGE_LENGTH) {
        return res.status(400).json({
            success: false,
            error: `Message exceeds maximum length of ${MAX_MESSAGE_LENGTH} characters.`
        });
    }
    req.sanitizedMessage = trimmedMessage;
    next();
}

async function initialize() {
    try {
        logger.info("Initializing system...");
        await ensureDataDirectory();
        await keyManager.initialize();
        await userDb.load();
        await messageDb.load(); // Load message database
        logger.info("Setting Telegram bot commands...");
        await bot.telegram.setMyCommands([
            { command: 'start', description: 'Register and get your access token' },
            { command: 'token', description: 'Get a new access token' },
            { command: 'help', description: 'Get help using Clippy' }
        ]).catch(error => {
            logger.error(`Failed to set bot commands: ${error.message}`);
        });
        logger.info('System initialized successfully.');
    } catch (error) {
        logger.error(`CRITICAL Initialization error: ${error.message}`);
        process.exit(1);
    }
}

bot.start(async (ctx) => {
    try {
        const telegramId = ctx.from.id;
        const firstName = ctx.from.first_name || 'User';
        logger.info(`/start command received from Telegram ID: ${telegramId}`);
        let user = userDb.getByTelegramId(telegramId);
        let clippyId;
        if (!user) {
            logger.info(`New user (ID: ${telegramId}). Registering...`);
            try {
                clippyId = await userDb.addUser(telegramId);
                await ctx.reply(
                    `Welcome to Clippy, ${firstName}\\! Your unique Clippy ID is: \`${clippyId}\`\n\n` +
                    `This ID is all you need to set up the Clippy extension\\.`,
                    { parse_mode: 'MarkdownV2' }
                );
            } catch (addError) {
                logger.error(`Error adding user ${telegramId}: ${addError.message}`);
                await ctx.reply(`Sorry, there was an error registering your account. Please try again later.`);
                return;
            }
        } else {
            clippyId = user.clippyId;
            logger.info(`Existing user (Clippy ID: ${clippyId}, Telegram ID: ${telegramId}) used /start.`);
            await ctx.reply(
                `Welcome back to Clippy, ${firstName}\\! Your Clippy ID is: \`${clippyId}\`\n\n` +
                `Enter this ID in the Clippy extension to connect it with Telegram\\.`,
                { parse_mode: 'MarkdownV2' }
            );
        }
        // Generate tokens but don't send them to the user
        logger.info(`Generating new tokens for ${clippyId}`);
        generateTokens(clippyId);

        await ctx.reply(
            `*How to use Clippy:*\n\n` +
            `1\\. Install the Clippy browser extension\n` +
            `2\\. Enter your Clippy ID in the extension setup\n` +
            `3\\. Send any message to this bot to save it as a clip\n` +
            `4\\. Use the extension to retrieve or send messages\n\n` +
            `Type /help for more information\\.`,
            { parse_mode: 'MarkdownV2' }
        );
    } catch (error) {
        logger.error(`Error processing /start command: ${error.message}`);
        try {
            await ctx.reply('An unexpected error occurred while processing your request. Please try the /start command again.');
        } catch (replyError) {
            logger.error(`Failed to send error reply to user: ${replyError.message}`);
        }
    }
});

bot.command('token', async (ctx) => {
    try {
        const telegramId = ctx.from.id;
        logger.info(`/token command received from Telegram ID: ${telegramId}`);
        const user = userDb.getByTelegramId(telegramId);
        if (!user) {
            logger.info(`User ${telegramId} used /token but is not registered.`);
            await ctx.reply('You need to be registered first. Please use the /start command.');
            return;
        }
        logger.info(`Generating new tokens for existing user ${user.clippyId}`);
        // Generate new tokens but don't send them to the user
        generateTokens(user.clippyId);

        await ctx.reply(
            `Your authentication has been refreshed\\.\n\n` +
            `You don't need to do anything else \\- your Clippy extension will automatically use the new authentication\\.`,
            { parse_mode: 'MarkdownV2' }
        );
    } catch (error) {
        logger.error(`Error processing /token command: ${error.message}`);
        try {
            await ctx.reply('An error occurred while refreshing your authentication. Please try again.');
        } catch (replyError) {
            logger.error(`Failed to send error reply to user: ${replyError.message}`);
        }
    }
});

bot.command('help', (ctx) => {
    logger.info(`/help command received from Telegram ID: ${ctx.from.id}`);
    const helpText = `*clippy_thebot Help*\n\n` +
        `Use this bot to connect with the Clippy browser extension\\. Messages you send here can be retrieved by the extension, and the extension can send messages back to you here\\.\n\n` +
        `*Commands:*\n` +
        `/start \\- Register your Telegram account with Clippy and get your Clippy ID\\.\n` +
        `/token \\- Refresh your authentication with Clippy\\.\n` +
        `/help \\- Show this help message\\.\n\n` +
        `*Usage:*\n` +
        `1\\. Use /start to get your Clippy ID\\.\n` +
        `2\\. Enter your Clippy ID into the Clippy browser extension\\.\n` +
        `3\\. Any text message you send to this bot \\(not starting with \\/\\) will be considered your latest \"clipping\" and can be retrieved by the extension\\.\n` +
        `4\\. The extension can send messages back to you, which will appear here from the bot\\.\n\n` +
        `Keep your Clippy ID secure\\!`;
    ctx.replyWithMarkdownV2(helpText).catch(err => {
        logger.error(`Failed to send help message: ${err.message}`);
        ctx.reply(helpText.replace(/\\([_*`\[\]()~>#+\-=|{}.!])/g, '$1'));
    });
});

bot.on('text', async (ctx) => {
    if (ctx.message.text && ctx.message.text.startsWith('/')) {
        return;
    }
    try {
        const telegramId = ctx.from.id;
        logger.info(`Received text message from Telegram ID: ${telegramId}`);
        const user = userDb.getByTelegramId(telegramId);
        if (!user) {
            logger.info(`User ${telegramId} sent text but is not registered.`);
            await ctx.reply('You need to register first using the /start command before sending messages.');
            return;
        }
        await userDb.updateLastActivity(user.clippyId);

        // Store the message in the message database
        await messageDb.storeMessage(user.clippyId, ctx.message.text);

        await ctx.reply('Clipping received\\!', { parse_mode: 'MarkdownV2' });
    } catch (error) {
        logger.error(`Error processing text message: ${error.message}`);
        try {
            await ctx.reply('Sorry, there was an error processing your message.');
        } catch (replyError) {
            logger.error(`Failed to send error reply to user: ${replyError.message}`);
        }
    }
});

// New endpoint to get tokens using Clippy ID
app.post('/api/auth/token', async (req, res) => {
    try {
        const { userId } = req.body;

        if (!userId) {
            return res.status(400).json({
                success: false,
                error: 'User ID is required'
            });
        }

        // Check if user exists
        const user = userDb.getByClippyId(userId);
        if (!user) {
            logger.warn(`Token request for non-existent user: ${userId}`);
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }

        // Generate tokens
        logger.info(`Generating tokens through API for user ${userId}`);
        const { sessionToken, refreshToken } = generateTokens(userId);

        return res.json({
            success: true,
            sessionToken,
            refreshToken
        });
    } catch (error) {
        logger.error(`Error in token endpoint: ${error.message}`);
        return res.status(500).json({
            success: false,
            error: 'Server error occurred during token generation'
        });
    }
});

app.post('/api/auth/refresh', async (req, res) => {
    try {
        const { refreshToken } = req.body;
        if (!refreshToken || typeof refreshToken !== 'string') {
            return res.status(400).json({
                success: false,
                error: 'Refresh token is required and must be a string.'
            });
        }
        jwt.verify(refreshToken, JWT_SECRET, { ignoreExpiration: false }, async (err, decoded) => {
            if (err) {
                logger.warn(`Refresh token verification failed: ${err.name} - ${err.message}`);
                if (err.name === 'TokenExpiredError') {
                    return res.status(401).json({ success: false, error: 'Refresh token expired', code: 'REFRESH_TOKEN_EXPIRED' });
                }
                return res.status(403).json({ success: false, error: 'Invalid refresh token', code: 'INVALID_REFRESH_TOKEN' });
            }
            if (decoded.type !== 'refresh') {
                logger.warn(`Attempted refresh with non-refresh token type: ${decoded.type}`);
                return res.status(403).json({ success: false, error: 'Invalid token type for refresh', code: 'INVALID_TOKEN_TYPE' });
            }
            if (!decoded.userId || !decoded.jti) {
                logger.error('Refresh token missing userId or jti payload.');
                return res.status(403).json({ success: false, error: 'Invalid refresh token payload', code: 'INVALID_TOKEN_PAYLOAD' });
            }
            const userId = decoded.userId;
            const tokenId = decoded.jti;
            const isValidInDb = await userDb.validateRefreshToken(userId, tokenId);
            if (!isValidInDb) {
                logger.warn(`Refresh token JTI ${tokenId.substring(0, 8)}... for user ${userId} not found in DB (likely revoked or old).`);
                return res.status(403).json({
                    success: false,
                    error: 'Refresh token has been revoked or is invalid',
                    code: 'REFRESH_TOKEN_REVOKED'
                });
            }
            logger.info(`Refresh token validated for user ${userId}. Issuing new tokens.`);
            const { sessionToken: newSessionToken, refreshToken: newRefreshToken } = generateTokens(userId);
            await userDb.removeRefreshToken(userId, tokenId);
            return res.json({
                success: true,
                sessionToken: newSessionToken,
                refreshToken: newRefreshToken
            });
        });
    } catch (error) {
        logger.error(`Refresh token endpoint error: ${error.message}`);
        return res.status(500).json({
            success: false,
            error: 'Server error occurred during token refresh.'
        });
    }
});

app.post('/api/messages/latest', verifyToken, async (req, res) => {
    try {
        const userId = req.userId;
        logger.info(`Received request for latest message from user ${userId}`);
        const user = userDb.getByClippyId(userId);
        if (!user) {
            logger.error(`User ${userId} passed token verification but not found in DB.`);
            return res.status(404).json({
                success: false,
                error: 'User associated with token not found.'
            });
        }
        await userDb.updateLastActivity(userId);

        // Retrieve latest message from message database instead of Telegram
        const latestMessage = messageDb.getLatestMessage(userId);

        if (!latestMessage) {
            logger.info(`No messages found for user ${userId}.`);
            return res.json({
                success: true,
                message: null,
                status: 'No recent messages found.'
            });
        }

        logger.info(`Found latest message for user ${userId} from ${latestMessage.timestamp}`);
        return res.json({
            success: true,
            message: latestMessage.text,
            timestamp: latestMessage.timestamp
        });
    } catch (error) {
        logger.error(`Latest message endpoint unexpected error: ${error.message}`);
        return res.status(500).json({
            success: false,
            error: 'Server error occurred while retrieving the latest message.'
        });
    }
});

app.post('/api/messages/send', verifyToken, validateMessageInput, async (req, res) => {
    try {
        const userId = req.userId;
        const sanitizedMessage = req.sanitizedMessage;
        logger.info(`Received request to send message from user ${userId}`);
        const user = userDb.getByClippyId(userId);
        if (!user) {
            logger.error(`User ${userId} passed token verification but not found in DB during send.`);
            return res.status(404).json({
                success: false,
                error: 'User associated with token not found.'
            });
        }
        await userDb.updateLastActivity(userId);
        try {
            logger.info(`Sending message to Telegram ID ${user.telegramId} for user ${userId}`);
            const messageToSend = `*From Clippy Extension:*\n\n${sanitizedMessage}`
                .replace(/([_*\[\]()~`>#+\-=|{}.!])/g, '\\$1');
            await bot.telegram.sendMessage(
                user.telegramId,
                messageToSend,
                { parse_mode: 'MarkdownV2' }
            );
            logger.info(`Message successfully sent to Telegram for user ${userId}.`);
            return res.json({ success: true, status: 'Message delivered to Telegram.' });
        } catch (telegramError) {
            logger.error(`Telegram sending error: ${telegramError.message}`);
            let errorMessage = 'Failed to deliver message via Telegram.';
            if (telegramError.code === 403 && telegramError.description.includes('blocked')) {
                errorMessage = 'Failed to send: The user has blocked the bot.';
            } else if (telegramError.code === 400 && telegramError.description.includes('chat not found')) {
                errorMessage = 'Failed to send: User chat not found (maybe deactivated account?).';
            }
            return res.status(503).json({
                success: false,
                error: errorMessage
            });
        }
    } catch (error) {
        logger.error(`Send message endpoint unexpected error: ${error.message}`);
        return res.status(500).json({
            success: false,
            error: 'Server error occurred while attempting to send the message.'
        });
    }
});

app.get('/health', (req, res) => {
    res.status(200).json({ status: 'healthy', timestamp: new Date().toISOString() });
});

app.use((req, res) => {
    res.status(404).json({ success: false, error: 'Not Found', path: req.originalUrl });
});

app.use((err, req, res, next) => {
    logger.error(`Unhandled error: ${err.message}`);
    const statusCode = err.status || 500;
    res.status(statusCode).json({
        success: false,
        error: NODE_ENV === 'production' ? 'An internal server error occurred' : err.message
    });
});

async function startServer() {
    await initialize();
    const port = process.env.PORT || 8080;
    const httpServer = http.createServer(app);
    httpServer.listen(port, () => {
        logger.info(`Clippy Server listening on HTTP port ${port}`);
        logger.info(`Server is ready to accept connections.`);
        bot.launch().then(() => {
            logger.info('Telegram bot started successfully.');
        }).catch(error => {
            logger.error(`CRITICAL: Failed to launch Telegram bot: ${error.message}`);
        });
    });
    httpServer.on('error', (error) => {
        if (error.syscall !== 'listen') {
            throw error;
        }
        switch (error.code) {
            case 'EACCES':
                logger.error(`Port ${PORT} requires elevated privileges`);
                process.exit(1);
                break;
            case 'EADDRINUSE':
                logger.error(`Port ${PORT} is already in use`);
                process.exit(1);
                break;
            default:
                throw error;
        }
    });
}

function setupGracefulShutdown() {
    let isShuttingDown = false;
    async function shutdown(signal) {
        if (isShuttingDown) {
            logger.info('Shutdown already in progress...');
            return;
        }
        isShuttingDown = true;
        logger.info(`\nReceived ${signal}. Shutting down gracefully...`);
        logger.info('Stopping Telegram bot...');
        try {
            bot.stop(signal);
            logger.info('Telegram bot stopped.');
        } catch (err) {
            logger.error(`Error stopping Telegram bot: ${err.message}`);
        }
        logger.info('Closing HTTP server...(will wait for existing connections)');
        logger.info('Saving final user data...');
        try {
            await userDb.save();
            await messageDb.save();
            logger.info('User and message data saved.');
        } catch (err) {
            logger.error(`Error saving data during shutdown: ${err.message}`);
        }
        await new Promise(resolve => setTimeout(resolve, 1000));
        logger.info('Shutdown complete.');
        process.exit(0);
    }
    process.on('SIGINT', () => shutdown('SIGINT'));
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('uncaughtException', (error, origin) => {
        logger.error('-------------------- UNCAUGHT EXCEPTION --------------------');
        logger.error(`Origin: ${origin}`);
        logger.error(error);
        logger.error('------------------------------------------------------------');
        shutdown('UNCAUGHT_EXCEPTION').catch(() => process.exit(1));
        setTimeout(() => process.exit(1), 5000).unref();
    });
    process.on('unhandledRejection', (reason, promise) => {
        logger.error('-------------------- UNHANDLED REJECTION --------------------');
        logger.error(`Reason: ${reason}`);
        logger.error('-------------------------------------------------------------');
    });
}

setupGracefulShutdown();
startServer().catch(error => {
    logger.error('-------------------- FAILED TO START SERVER --------------------');
    logger.error(error);
    logger.error('----------------------------------------------------------------');
    process.exit(1);
});