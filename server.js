const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const fs = require('fs');
const path = require('path');
const { lua } = require('fengari');
const { to_luastring } = require('fengari-interop');
const config = require('./config');

const app = express();
const PORT = config.port;

// In-memory storage for tracking IPs and requests
const requestTracker = new Map();
const blockedIPs = new Map();
const suspiciousIPs = new Set();

// Logging function
function log(level, message, data = null) {
  if (!config.logging.enabled) return;
  
  const timestamp = new Date().toISOString();
  const logMessage = `[${timestamp}] [${level.toUpperCase()}] ${message}`;
  
  console.log(logMessage);
  
  if (config.logging.logFile) {
    const logEntry = data ? 
      `${logMessage} - ${JSON.stringify(data)}\n` : 
      `${logMessage}\n`;
    
    fs.appendFileSync(config.logging.logFile, logEntry);
  }
}

// Load Lua scripts
function loadLuaScript(scriptPath) {
  try {
    const fullPath = path.join(__dirname, scriptPath);
    const scriptContent = fs.readFileSync(fullPath, 'utf8');
    return scriptContent;
  } catch (error) {
    log('error', `Failed to load script: ${scriptPath}`, { error: error.message });
    return null;
  }
}

// Execute Lua script
function executeLuaScript(script, params = {}) {
  try {
    const L = lua.lua_newstate();
    lua.luaopen_base(L);
    lua.luaopen_math(L);
    lua.luaopen_string(L);
    lua.luaopen_table(L);
    
    // Pass parameters to Lua
    Object.entries(params).forEach(([key, value]) => {
      lua.lua_pushstring(L, to_luastring(key));
      if (typeof value === 'number') {
        lua.lua_pushnumber(L, value);
      } else {
        lua.lua_pushstring(L, to_luastring(String(value)));
      }
      lua.lua_settable(L, -3);
    });
    
    const result = lua.luaL_dostring(L, to_luastring(script));
    
    if (result !== 0) {
      const error = lua.lua_tostring(L, -1);
      log('error', 'Script execution failed', { error });
      return null;
    }
    
    // Get return value
    const returnValue = lua.lua_tostring(L, -1);
    lua.lua_close(L);
    
    return returnValue;
  } catch (error) {
    log('error', 'Script execution error', { error: error.message }, '. Please contact @700service.exe on Discord if this happens all of the time.');
    return null;
  }
}

// Security headers
if (config.security.helmet) {
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "https:"]
      }
    }
  }));
}

// Rate limiting
const limiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.maxRequests,
  message: config.rateLimit.message,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    const ip = req.ip || req.connection.remoteAddress;
    log('warn', 'Rate limit exceeded', { ip, url: req.url });
    res.status(429).json({ error: config.rateLimit.message });
  }
});

// Slow down repeated requests
const speedLimiter = slowDown({
  windowMs: 15 * 60 * 1000,
  delayAfter: 50,
  delayMs: 500
});

app.use(limiter);
app.use(speedLimiter);

// DDoS protection middleware! Do not delete this, or else you will be vulnerable to DDoS attacks (ddos-protector does not work without this)
app.use((req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'];
  const currentTime = Date.now();
  
  // Checks if IP is whitelisted
  if (config.ddosProtection.whitelistedIPs.includes(ip)) {
    return next();
  }
  
  // Checks if IP is currently blocked
  if (blockedIPs.has(ip)) {
    const blockInfo = blockedIPs.get(ip);
    if (currentTime < blockInfo.until) {
      log('warn', 'Blocked IP, attempted access: ', { ip, url: req.url });
      return res.status(403).json({ 
        error: 'Your IP has been temporarily blocked due to suspicious activity',
        blockedUntil: new Date(blockInfo.until).toISOString()
      });
    } else {
      // Unblock expired IPs
      blockedIPs.delete(ip);
      suspiciousIPs.delete(ip);
    }
  }
  
  if (!requestTracker.has(ip)) {
    requestTracker.set(ip, {
      requests: [],
      totalRequests: 0
    });
  }
  
  const tracker = requestTracker.get(ip);
  const minute = Math.floor(currentTime / 60000);
  
  tracker.requests = tracker.requests.filter(req => req.minute >= minute - 5);
  
  // Add current requests to tracking
  tracker.requests.push({
    minute,
    url: req.url,
    method: req.method,
    userAgent: req.get('User-Agent'),
    timestamp: currentTime
  });
  
  tracker.totalRequests++;
  
  // Analyze request patterns using the scripts
  const luaAnalysis = loadLuaScript(config.luaScripts.analysisScript);
  if (luaAnalysis) {
    const analysisParams = {
      ip,
      requestCount: tracker.requests.length,
      totalRequests: tracker.totalRequests,
      url: req.url,
      method: req.method,
      userAgent: req.get('User-Agent') || '',
      urlLength: req.url.length,
      suspiciousThreshold: config.ddosProtection.suspiciousThreshold
    };
    
    const analysisResult = executeLuaScript(luaAnalysis, analysisParams);
    
    if (analysisResult && analysisResult.includes('SUSPICIOUS')) {
      suspiciousIPs.add(ip);
      log('warn', 'Suspicious activity detected.. Very suspicious.', { 
        ip, 
        url: req.url, 
        requestCount: tracker.requests.length,
        analysis: analysisResult
      });
    }
    
    if (analysisResult && analysisResult.includes('BLOCK')) {
      const blockUntil = currentTime + config.ddosProtection.blockDuration;
      blockedIPs.set(ip, { 
        blockedAt: currentTime, 
        until: blockUntil,
        reason: 'Protection triggered, an IP may have been blocked was blocked.'
      });
      
      log('error', 'IP blocked for DDoS activity.', { 
        ip, 
        requestCount: tracker.requests.length,
        blockUntil: new Date(blockUntil).toISOString()
      });
      
      return res.status(403).json({ 
        error: 'Your IP has been blocked due to suspicious activity.',
        blockedUntil: new Date(blockUntil).toISOString()
      });
    }
  }
  
  // Checks for request flood. If an IP makes too many requests in a short time, it gets blocked.
  const requestsPerMinute = tracker.requests.filter(req => req.minute === minute).length;
  if (requestsPerMinute > config.ddosProtection.suspiciousThreshold / 60) {
    const blockUntil = currentTime + config.ddosProtection.blockDuration;
    blockedIPs.set(ip, { 
      blockedAt: currentTime, 
      until: blockUntil,
      reason: 'REQUEST FLOOD DETECTED.'
    });
    
    log('error', 'Req Flood: IP blocked from the baseUrl.', { 
      ip, 
      requestsPerMinute,
      blockUntil: new Date(blockUntil).toISOString()
    });
    
    return res.status(429).json({ 
      error: 'Too many requests. Your IP has been temporarily blocked.',
      blockedUntil: new Date(blockUntil).toISOString()
    });
  }
  
  next();
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    protection: 'active',
    blockedIPs: blockedIPs.size,
    suspiciousIPs: suspiciousIPs.size
  });
});

// Protected routes
app.get('/', (req, res) => {
  res.json({ 
    message: 'ddos-protector is active.',
    timestamp: new Date().toISOString(),
    yourIP: req.ip || req.connection.remoteAddress
  });
});

// Admin endpoint to view protection status
app.get('/admin/status', (req, res) => {
  const stats = {
    activeConnections: requestTracker.size,
    blockedIPs: Array.from(blockedIPs.entries()).map(([ip, info]) => ({
      ip,
      blockedAt: new Date(info.blockedAt).toISOString(),
      until: new Date(info.until).toISOString(),
      reason: info.reason
    })),
    suspiciousIPs: Array.from(suspiciousIPs),
    totalTrackedIPs: requestTracker.size
  };
  
  res.json(stats);
});

// Cleanup function to remove old tracking data
setInterval(() => {
  const currentTime = Date.now();
  const cleanupThreshold = currentTime - (24 * 60 * 60 * 1000);
  
  for (const [ip, blockInfo] of blockedIPs.entries()) {
    if (currentTime >= blockInfo.until) {
      blockedIPs.delete(ip);
      suspiciousIPs.delete(ip);
    }
  }
  
  for (const [ip, tracker] of requestTracker.entries()) {
    if (tracker.requests.length === 0 || 
        tracker.requests[tracker.requests.length - 1].timestamp < cleanupThreshold) {
      requestTracker.delete(ip);
    }
  }
  
  log('debug', 'Cleanup ran, and finished.', {
    blockedIPs: blockedIPs.size,
    trackedIPs: requestTracker.size
  });
}, 60000);

app.use((err, req, res, next) => {
  log('error', 'Unhandled error:', { 
    error: err.message, 
    stack: err.stack,
    ip: req.ip,
    url: req.url
  });
  
  res.status(500).json({ 
    error: 'Internal server error',
    timestamp: new Date().toISOString()
  });
});

app.listen(PORT, () => {
  log('info', `ddos-protector has successfully started! v1.0.0`, { 
    port: PORT, 
    baseUrl: config.baseurl,
    timestamp: new Date().toISOString()
  });
  
  console.log(`ddos-protector is running on ${config.baseurl}:${PORT}`);
  console.log(`Admin status: ${config.baseurl}:${PORT}/admin/status`);
  console.log(`Health check: ${config.baseurl}:${PORT}/health`);
  console.log('Press Ctrl+C to stop the server when changing any files such as: config.js or server.js or whatever lua scripts you may have edited.');
  console.log('Made with 💗 by 700 :)')
});