/**
 * Backup Service - automatic MongoDB backups with optional S3 upload
 */

const { execFile } = require('child_process');
const { promisify } = require('util');
const path = require('path');
const fs = require('fs').promises;
const fsSync = require('fs');
const config = require('../../config');
const logger = require('../utils/logger');
const cryptoService = require('./cryptoService');

const execFileAsync = promisify(execFile);

/**
 * Extract database name from MONGO_URI, fallback to 'hysteria'.
 */
function getDbName() {
    try {
        return new URL(config.MONGO_URI).pathname.replace(/^\//, '') || 'hysteria';
    } catch (_) {
        return 'hysteria';
    }
}

// Lazy-load S3 client (only when needed)
let s3Client = null;

function getS3Client(settings) {
    if (!s3Client && settings?.backup?.s3?.enabled) {
        try {
            const { S3Client } = require('@aws-sdk/client-s3');
            s3Client = new S3Client({
                region: settings.backup.s3.region || 'us-east-1',
                endpoint: settings.backup.s3.endpoint || undefined,
                credentials: {
                    accessKeyId: settings.backup.s3.accessKeyId,
                    secretAccessKey: cryptoService.decryptSafe(settings.backup.s3.secretAccessKey),
                },
                forcePathStyle: !!settings.backup.s3.endpoint, // for MinIO and similar
            });
        } catch (err) {
            logger.error(`[Backup] Failed to initialize S3 client: ${err.message}`);
            return null;
        }
    }
    return s3Client;
}

/**
 * Create MongoDB backup
 */
async function createBackup(settings) {
    const backupDir = path.join(__dirname, '../../backups');

    await fs.mkdir(backupDir, { recursive: true });

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const backupName = `hysteria-backup-${timestamp}`;
    const backupPath = path.join(backupDir, backupName);
    const archivePath = path.join(backupDir, `${backupName}.tar.gz`);

    try {
        const mongoUri = config.MONGO_URI;

        logger.info(`[Backup] Starting backup: ${backupName}`);
        await execFileAsync('mongodump', ['--uri', mongoUri, '--out', backupPath, '--gzip']);
        logger.info(`[Backup] Dump created: ${backupPath}`);

        await execFileAsync('tar', ['-czf', archivePath, '-C', backupDir, backupName]);
        logger.info(`[Backup] Archive created: ${archivePath}`);

        await fs.rm(backupPath, { recursive: true });

        const stats = await fs.stat(archivePath);
        const sizeMB = (stats.size / 1024 / 1024).toFixed(2);

        if (settings?.backup?.s3?.enabled) {
            await uploadToS3(archivePath, `${backupName}.tar.gz`, settings);
        }

        const keepLast = settings?.backup?.keepLast || 7;
        await rotateBackups(backupDir, keepLast);

        const Settings = require('../models/settingsModel');
        await Settings.update({ 'backup.lastBackup': new Date() });

        logger.info(`[Backup] Completed: ${backupName} (${sizeMB} MB)`);

        return {
            success: true,
            filename: `${backupName}.tar.gz`,
            path: archivePath,
            size: stats.size,
            sizeMB: parseFloat(sizeMB),
        };

    } catch (error) {
        logger.error(`[Backup] Error: ${error.message}`);

        try {
            await fs.rm(backupPath, { recursive: true }).catch(() => {});
        } catch (e) {}

        throw error;
    }
}

/**
 * Upload file to S3
 */
async function uploadToS3(filePath, fileName, settings) {
    const client = getS3Client(settings);
    if (!client) {
        logger.warn('[Backup] S3 client not available, skipping upload');
        return;
    }
    
    try {
        const { PutObjectCommand } = require('@aws-sdk/client-s3');
        const fileStream = fsSync.createReadStream(filePath);
        const stats = await fs.stat(filePath);
        
        const bucket = settings.backup.s3.bucket;
        const prefix = settings.backup.s3.prefix || 'backups';
        const key = `${prefix}/${fileName}`;
        
        logger.info(`[Backup] Uploading to S3: ${bucket}/${key}`);
        
        await client.send(new PutObjectCommand({
            Bucket: bucket,
            Key: key,
            Body: fileStream,
            ContentLength: stats.size,
            ContentType: 'application/gzip',
        }));
        
        logger.info(`[Backup] Uploaded to S3: ${key}`);
        
        // Rotate in S3 if configured
        if (settings.backup.s3.keepLast) {
            await rotateS3Backups(settings);
        }
        
    } catch (error) {
        logger.error(`[Backup] S3 upload error: ${error.message}`);
        // Do not abort - local backup was created
    }
}

/**
 * Rotate backups in S3
 */
async function rotateS3Backups(settings) {
    const client = getS3Client(settings);
    if (!client) return;
    
    try {
        const { ListObjectsV2Command, DeleteObjectCommand } = require('@aws-sdk/client-s3');
        
        const bucket = settings.backup.s3.bucket;
        const prefix = settings.backup.s3.prefix || 'backups';
        const keepLast = settings.backup.s3.keepLast || 7;
        
        // List objects
        const listResult = await client.send(new ListObjectsV2Command({
            Bucket: bucket,
            Prefix: `${prefix}/hysteria-backup-`,
        }));
        
        if (!listResult.Contents || listResult.Contents.length <= keepLast) {
            return;
        }
        
        // Sort by date (oldest first)
        const sorted = listResult.Contents
            .filter(obj => obj.Key.endsWith('.tar.gz'))
            .sort((a, b) => a.LastModified - b.LastModified);
        
        // Delete excess
        const toDelete = sorted.slice(0, sorted.length - keepLast);
        
        for (const obj of toDelete) {
            await client.send(new DeleteObjectCommand({
                Bucket: bucket,
                Key: obj.Key,
            }));
            logger.info(`[Backup] Deleted from S3: ${obj.Key}`);
        }
        
    } catch (error) {
        logger.error(`[Backup] S3 rotation error: ${error.message}`);
    }
}

/**
 * Rotate local backups (keep last N)
 */
async function rotateBackups(backupDir, keepLast) {
    try {
        const entries = await fs.readdir(backupDir, { withFileTypes: true });
        const files = await Promise.all(
            entries
                .filter(e => e.isFile() && e.name.startsWith('hysteria-backup-') && e.name.endsWith('.tar.gz'))
                .map(async (e) => {
                    const filePath = path.join(backupDir, e.name);
                    const stats = await fs.stat(filePath);
                    return { name: e.name, path: filePath, mtime: stats.mtime };
                })
        );
        files.sort((a, b) => a.mtime - b.mtime);

        if (files.length <= keepLast) {
            return;
        }

        const toDelete = files.slice(0, files.length - keepLast);

        for (const file of toDelete) {
            await fs.unlink(file.path);
            logger.info(`[Backup] Rotated old backup: ${file.name}`);
        }

        logger.info(`[Backup] Rotation complete. Kept ${keepLast} backups, deleted ${toDelete.length}`);

    } catch (error) {
        logger.error(`[Backup] Rotation error: ${error.message}`);
    }
}

/**
 * Get list of local backups
 */
async function listBackups() {
    const backupDir = path.join(__dirname, '../../backups');

    try {
        await fs.access(backupDir);
    } catch {
        return [];
    }

    const entries = await fs.readdir(backupDir, { withFileTypes: true });
    const files = await Promise.all(
        entries
            .filter(e => e.isFile() && e.name.startsWith('hysteria-backup-') && e.name.endsWith('.tar.gz'))
            .map(async (e) => {
                const filePath = path.join(backupDir, e.name);
                const stats = await fs.stat(filePath);
                return {
                    name: e.name,
                    path: filePath,
                    size: stats.size,
                    sizeMB: (stats.size / 1024 / 1024).toFixed(2),
                    created: stats.mtime,
                };
            })
    );
    files.sort((a, b) => b.created - a.created);
    return files;
}

/**
 * Check if backup should run
 */
async function shouldRunBackup(settings) {
    if (!settings?.backup?.enabled) {
        return false;
    }
    
    const intervalHours = settings.backup.intervalHours || 24;
    const lastBackup = settings.backup.lastBackup;
    
    if (!lastBackup) {
        return true; // Never backed up before
    }
    
    const hoursSinceLastBackup = (Date.now() - new Date(lastBackup).getTime()) / (1000 * 60 * 60);
    
    return hoursSinceLastBackup >= intervalHours;
}

/**
 * Scheduled backup (called from cron)
 */
async function scheduledBackup() {
    try {
        const Settings = require('../models/settingsModel');
        const settings = await Settings.get();
        
        if (await shouldRunBackup(settings)) {
            logger.info('[Backup] Starting scheduled backup');
            await createBackup(settings);
        }
    } catch (error) {
        logger.error(`[Backup] Scheduled backup failed: ${error.message}`);
    }
}

/**
 * Test S3 connection
 */
async function testS3Connection(s3Config) {
    try {
        const { S3Client, ListBucketsCommand } = require('@aws-sdk/client-s3');
        
        const client = new S3Client({
            region: s3Config.region || 'us-east-1',
            endpoint: s3Config.endpoint || undefined,
            credentials: {
                accessKeyId: s3Config.accessKeyId,
                secretAccessKey: s3Config.secretAccessKey,
            },
            forcePathStyle: !!s3Config.endpoint,
        });
        
        // Check bucket access
        const { HeadBucketCommand } = require('@aws-sdk/client-s3');
        await client.send(new HeadBucketCommand({ Bucket: s3Config.bucket }));
        
        return { success: true };
        
    } catch (error) {
        return { 
            success: false, 
            error: error.message,
        };
    }
}

/**
 * Get list of backups from S3
 */
async function listS3Backups(settings) {
    const client = getS3Client(settings);
    if (!client) {
        return [];
    }
    
    try {
        const { ListObjectsV2Command } = require('@aws-sdk/client-s3');
        
        const bucket = settings.backup.s3.bucket;
        const prefix = settings.backup.s3.prefix || 'backups';
        
        const result = await client.send(new ListObjectsV2Command({
            Bucket: bucket,
            Prefix: `${prefix}/hysteria-backup-`,
        }));
        
        if (!result.Contents) {
            return [];
        }
        
        return result.Contents
            .filter(obj => obj.Key.endsWith('.tar.gz'))
            .map(obj => ({
                name: obj.Key.split('/').pop(),
                key: obj.Key,
                size: obj.Size,
                sizeMB: (obj.Size / 1024 / 1024).toFixed(2),
                created: obj.LastModified,
                source: 's3',
            }))
            .sort((a, b) => b.created - a.created); // newest first
            
    } catch (error) {
        logger.error(`[Backup] List S3 backups error: ${error.message}`);
        return [];
    }
}

/**
 * Get a readable stream for an S3 backup object (for HTTP download).
 * Returns { stream, contentLength, contentType }.
 */
async function getS3BackupStream(settings, key) {
    const client = getS3Client(settings);
    if (!client) {
        throw new Error('S3 client not available');
    }

    const { GetObjectCommand } = require('@aws-sdk/client-s3');
    const bucket = settings.backup.s3.bucket;

    const response = await client.send(new GetObjectCommand({
        Bucket: bucket,
        Key: key,
    }));

    return {
        stream: response.Body,
        contentLength: response.ContentLength,
        contentType: response.ContentType || 'application/gzip',
    };
}

/**
 * Resolve absolute path of a local backup file by name (with safety checks).
 */
function getLocalBackupPath(name) {
    const backupDir = path.join(__dirname, '../../backups');
    const safeName = path.basename(name || '');
    if (!safeName || safeName === '.' || safeName === '..') {
        throw new Error('Invalid backup name');
    }
    if (!safeName.startsWith('hysteria-backup-') || !safeName.endsWith('.tar.gz')) {
        throw new Error('Invalid backup name');
    }
    return path.join(backupDir, safeName);
}

/**
 * Download backup from S3 for restore
 */
async function downloadFromS3(settings, key) {
    const client = getS3Client(settings);
    if (!client) {
        throw new Error('S3 client not available');
    }
    
    const { GetObjectCommand } = require('@aws-sdk/client-s3');
    const { Readable } = require('stream');
    
    const bucket = settings.backup.s3.bucket;
    const fileName = path.basename(key);
    if (!fileName || fileName === '.' || fileName === '..') {
        throw new Error('Invalid S3 key');
    }
    const localPath = path.join(__dirname, '../../backups', fileName);
    
    logger.info(`[Backup] Downloading from S3: ${key}`);
    
    const response = await client.send(new GetObjectCommand({
        Bucket: bucket,
        Key: key,
    }));
    
    const writeStream = fsSync.createWriteStream(localPath);
    
    await new Promise((resolve, reject) => {
        response.Body.pipe(writeStream);
        response.Body.on('error', reject);
        writeStream.on('finish', resolve);
        writeStream.on('error', reject);
    });
    
    logger.info(`[Backup] Downloaded: ${localPath}`);
    
    return localPath;
}

/**
 * Restore from backup (local or S3)
 */
async function restoreBackup(settings, source, identifier) {
    let archivePath;
    let tempDownload = false;

    if (source === 's3') {
        archivePath = await downloadFromS3(settings, identifier);
        tempDownload = true;
    } else {
        const safeName = path.basename(identifier);
        if (!safeName || safeName === '.' || safeName === '..') {
            throw new Error('Invalid backup identifier');
        }
        archivePath = path.join(__dirname, '../../backups', safeName);
        try {
            await fs.access(archivePath);
        } catch {
            throw new Error('Backup file not found');
        }
    }

    const extractDir = path.join('/tmp', `restore-${Date.now()}`);

    try {
        await fs.mkdir(extractDir, { recursive: true });

        await execFileAsync('tar', ['-xzf', archivePath, '-C', extractDir]);
        logger.info(`[Restore] Archive extracted to ${extractDir}`);

        const dbName = getDbName();

        const findDumpPath = async (dir) => {
            const items = await fs.readdir(dir);
            const dbPath = path.join(dir, dbName);
            try {
                const stat = await fs.stat(dbPath);
                if (stat.isDirectory()) return dir;
            } catch {}
            if (items.length === 1) {
                const subPath = path.join(dir, items[0]);
                const stat = await fs.stat(subPath);
                if (stat.isDirectory()) return findDumpPath(subPath);
            }
            return dir;
        };

        const dumpPath = await findDumpPath(extractDir);
        const dbDir = path.join(dumpPath, dbName);

        try {
            await fs.access(dbDir);
        } catch {
            throw new Error(`Invalid backup: ${dbName} database folder not found`);
        }

        const mongoUri = config.MONGO_URI;

        logger.info(`[Restore] Starting restore from ${source}: ${identifier}`);
        await execFileAsync('mongorestore', ['--uri', mongoUri, '--drop', '--gzip', '--db', dbName, dbDir]);
        logger.info(`[Restore] Database restored successfully`);

        await fs.rm(extractDir, { recursive: true });

        return { success: true };

    } catch (error) {
        try {
            await fs.rm(extractDir, { recursive: true }).catch(() => {});
        } catch (e) {}

        throw error;
    }
}

module.exports = {
    createBackup,
    listBackups,
    listS3Backups,
    downloadFromS3,
    getS3BackupStream,
    getLocalBackupPath,
    restoreBackup,
    shouldRunBackup,
    scheduledBackup,
    testS3Connection,
    rotateBackups,
    resetS3Client() { s3Client = null; },
};

