/**
 * Panel settings model
 */

const mongoose = require('mongoose');

const settingsSchema = new mongoose.Schema({
    _id: {
        type: String,
        default: 'settings',
    },
    
    loadBalancing: {
        enabled: { type: Boolean, default: false },
        hideOverloaded: { type: Boolean, default: false },
        // Hide nodes the health checker marked as offline/error (status-based filter).
        // Default true: one dead node can break HAPP/v2rayTun/sing-box urltest groups.
        hideOffline: { type: Boolean, default: true },
    },
    
    deviceGracePeriod: { type: Number, default: 15 },
    
    cache: {
        subscriptionTTL: { type: Number, default: 3600 },
        userTTL: { type: Number, default: 900 },
        onlineSessionsTTL: { type: Number, default: 10 },
        activeNodesTTL: { type: Number, default: 30 },
    },
    
    rateLimit: {
        subscriptionPerMinute: { type: Number, default: 100 },
        authPerSecond: { type: Number, default: 200 },
    },
    
    sshPool: {
        enabled: { type: Boolean, default: true },
        maxIdleTime: { type: Number, default: 120 },        // seconds
        keepAliveInterval: { type: Number, default: 30 },   // seconds
        connectTimeout: { type: Number, default: 15 },      // seconds
        maxRetries: { type: Number, default: 2 },
    },
    
    nodeAuth: {
        // Allow nodes to connect to panel auth API with self-signed/invalid SSL
        // Enable if panel uses HTTP or self-signed certificate
        insecure: { type: Boolean, default: true },
    },

    lastInitScript: { type: String, default: '' },
    
    backup: {
        enabled: { type: Boolean, default: false },
        intervalHours: { type: Number, default: 24 },       // interval in hours
        keepLast: { type: Number, default: 7 },             // how many to keep locally
        lastBackup: { type: Date, default: null },          // last backup timestamp
        
        // S3 settings (optional)
        s3: {
            enabled: { type: Boolean, default: false },
            endpoint: { type: String, default: '' },        // for MinIO and similar
            region: { type: String, default: 'us-east-1' },
            bucket: { type: String, default: '' },
            prefix: { type: String, default: 'backups' },   // prefix in bucket
            accessKeyId: { type: String, default: '' },
            secretAccessKey: { type: String, default: '' },
            keepLast: { type: Number, default: 30 },        // how many to keep in S3
        },
    },

    webhook: {
        enabled: { type: Boolean, default: false },
        url: { type: String, default: '' },
        secret: { type: String, default: '' },
        // empty = all events; non-empty = only listed events
        events: { type: [String], default: [] },
    },

    subscription: {
        supportUrl:     { type: String, default: '' },
        webPageUrl:     { type: String, default: '' },
        happProviderId: { type: String, default: '' },
        logoUrl:        { type: String, default: '' },
        pageTitle:      { type: String, default: '' },
        updateInterval: { type: Number, default: 12 },
        buttons: {
            type: [{
                _id: false,
                label: { type: String, default: '' },
                url:   { type: String, default: '' },
                icon:  { type: String, default: '' },
            }],
            default: [],
        },
        happ: {
            announce:     { type: String, default: '' },
            hideSettings: { type: Boolean, default: false },
            notifyExpire: { type: Boolean, default: false },
            alwaysHwid:   { type: Boolean, default: false },
            pingType:     { type: String, enum: ['', 'proxy', 'proxy-head', 'tcp', 'icmp'], default: '' },
            pingUrl:      { type: String, default: '' },
            colorProfile: { type: String, default: '' },
            hwid: {
                mode: { type: String, enum: ['off', 'permissive', 'strict'], default: 'off' },
                inactiveDeviceCleanupDays: { type: Number, default: 90 },
                upsertRateLimitPerMinute: { type: Number, default: 60 },
                // HAPP popup text shown when device limit is reached (HAPP only).
                maxDevicesAnnounce: { type: String, default: '' },
                // Fake server name shown to non-HWID clients in strict mode
                // (Hiddify, Clash, Shadowrocket, sing-box, v2rayNG without x-hwid, etc.).
                notSupportedRemark: { type: String, default: '' },
                // Fake server name shown to any client when its device limit is reached.
                maxDevicesRemark: { type: String, default: '' },
            },
        },
    },

    deployment: {
        completed:   { type: Boolean, default: false },
        profile:     { type: String, enum: ['', 'self-host', 'remote'], default: '' },
        completedAt: { type: Date, default: null },
    },

    homepage: {
        mode: { type: String, enum: ['nginx', 'custom'], default: 'nginx' },
    },

    routing: {
        enabled: { type: Boolean, default: false },
        rules: {
            type: [{
                _id: false,
                action:  { type: String, enum: ['direct', 'block'], default: 'direct' },
                type:    { type: String, enum: ['domain_suffix', 'domain_keyword', 'domain', 'geosite', 'geoip', 'ip_cidr'] },
                value:   { type: String },
                comment: { type: String, default: '' },
                enabled: { type: Boolean, default: true },
            }],
            default: [],
        },
        dns: {
            domestic: { type: String, default: '77.88.8.8' },
            remote:   { type: String, default: 'tls://1.1.1.1' },
        },
    },
    
}, { timestamps: true });

settingsSchema.statics.get = async function() {
    let settings = await this.findById('settings');
    if (!settings) {
        settings = await this.create({ _id: 'settings' });
    }
    return settings;
};

settingsSchema.statics.update = async function(updates) {
    return this.findByIdAndUpdate('settings', { $set: updates }, { 
        new: true, 
        upsert: true,
        setDefaultsOnInsert: true,
    });
};

module.exports = mongoose.model('Settings', settingsSchema);

