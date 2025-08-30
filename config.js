// These are the configuration settings for the DDoS protection system.
// Adjust the parameters as needed to fit your security requirements.
// Made by @700service.exe on Discord. Feel free to contact me if you have any inquiries or need assistance with the setup.
// g

module.exports = {
  // Host configuration
  baseurl: 'http://localhost', // set this to localhost
  port: 3000, // set this to any port (make sure that it isnt already in use.)
  
  // Rate Limit configuration
  rateLimit: {
    windowMs: 15 * 60 * 1000,
    maxRequests: 100,
    message: 'Too many requests from this IP, please try again later.'
  },
  
  // Protector settings (the main deal)
  ddosProtection: {
    maxConcurrentRequests: 1000,
    suspiciousThreshold: 900, // req per minute. change this to a lower value if you want to be more strict, or higher if you want to be more lenient on security
    blockDuration: 30 * 60 * 1000,
    whitelistedIPs: ['127.0.0.1', '::1'],
    
    // Request pattern analysis
    patterns: {
      maxUrlLength: 2000,
      maxHeaderSize: 8192,
      suspiciousUserAgents: [
        'bot', 'crawler', 'spider', 'scraper',
        'curl', 'wget', 'python-requests'
      ],
      allowedMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
    }
  },
  
  // Logs configuration (open with a text editor to view any wanings or errors or whatever)
  logging: {
    enabled: true,
    level: 'info', // debug, info, warn, error
    logFile: 'ddos-protector.log',
    logAttacks: true
  },
  
  // Security headers and CORS settings (if your site doesnt have cors, disable cors)
  security: {
    helmet: true,
    cors: {
      enabled: true,
      origin: '*'
    }
  },
  
  // Lua scripts (do not change unless you know what you're tryna do)
  luaScripts: {
    protectionScript: './lua/ddos-protection.lua',
    analysisScript: './lua/request-analysis.lua',
    blockingScript: './lua/ip-blocking.lua'
  }
};