const classicSettings = require('../classicSettings');
const winston = require('winston');
const path = require('path');
const EventEmitter = require('events');
const logsDirectory = classicSettings?.logsDirectory || path.join(__dirname, '../../logs');
if (classicSettings) {
    require('fs').mkdirSync(logsDirectory, { recursive: true, mode: 0o700 });
}

// Event emitter for real-time log streaming
const logEmitter = new EventEmitter();
logEmitter.setMaxListeners(100); // Allow many WebSocket connections

// Buffer for recent logs (sent to new connections)
const LOG_BUFFER_SIZE = 100;
const logBuffer = [];

const fileFormat = winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.printf(({ timestamp, level, message, stack }) => {
        return `${timestamp} [${level.toUpperCase()}]: ${stack || message}`;
    })
);

const consoleFormat = winston.format.combine(
    winston.format.timestamp({ format: 'HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.printf(({ timestamp, level, message, stack }) => {
        const colors = {
            error: '\x1b[31m',
            warn: '\x1b[33m',
            info: '\x1b[36m',
            debug: '\x1b[90m',
        };
        const reset = '\x1b[0m';
        const color = colors[level] || '';
        return `\x1b[90m${timestamp}${reset} ${color}[${level.toUpperCase()}]${reset}: ${stack || message}`;
    })
);

// Custom transport for real-time streaming
class StreamTransport extends winston.Transport {
    log(info, callback) {
        const logEntry = {
            timestamp: info.timestamp || new Date().toISOString(),
            level: info.level,
            message: info.stack || info.message
        };
        
        // Add to buffer (circular)
        logBuffer.push(logEntry);
        if (logBuffer.length > LOG_BUFFER_SIZE) {
            logBuffer.shift();
        }
        
        // Emit for real-time listeners
        logEmitter.emit('log', logEntry);
        
        callback();
    }
}

const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    transports: [
        new winston.transports.Console({ format: consoleFormat }),
        new winston.transports.File({
            filename: path.join(logsDirectory, 'error.log'),
            level: 'error',
            format: fileFormat,
            maxsize: 5242880,
            maxFiles: 5,
        }),
        new winston.transports.File({
            filename: path.join(logsDirectory, 'combined.log'),
            format: fileFormat,
            maxsize: 5242880,
            maxFiles: 5,
        }),
        new StreamTransport({
            format: winston.format.combine(
                winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
                winston.format.errors({ stack: true })
            )
        }),
    ],
});

// Export emitter and buffer for WebSocket handler
logger.logEmitter = logEmitter;
logger.getRecentLogs = () => [...logBuffer];

module.exports = logger;



