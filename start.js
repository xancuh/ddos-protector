#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

// The banner lol
const banner = `
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║                         ddos-protector                           ║
║                      coded in lua + node                         ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
`;

console.log(banner);

// Check if required directories exist
function ensureDirectories() {
    const directories = ['lua', 'logs'];
    
    directories.forEach(dir => {
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
            console.log(`Created directory: ${dir}`);
        }
    });
}

// Check if required files exist
function checkRequiredFiles() {
    const requiredFiles = [
        'config.js',
        'server.js',
        'package.json',
        'lua/ddos-protection.lua',
        'lua/request-analysis.lua',
        'lua/ip-blocking.lua'
    ];
    
    const missingFiles = requiredFiles.filter(file => !fs.existsSync(file));
    
    if (missingFiles.length > 0) {
        console.error('Missing required files:');
        missingFiles.forEach(file => console.error(`   - ${file}`));
        console.error('\nPlease ensure all required files are present before starting.');
        process.exit(1);
    }
    
    console.log('All required files found');
}

// Check if dependencies are installed
function checkDependencies() {
    if (!fs.existsSync('node_modules')) {
        console.log('Installing dependencies...');
        
        const npm = spawn('npm', ['install'], {
            stdio: 'inherit',
            shell: true
        });
        
        npm.on('close', (code) => {
            if (code === 0) {
                console.log('Dependencies installed successfully');
                startServer();
            } else {
                console.error('Failed to install dependencies');
                process.exit(1);
            }
        });
    } else {
        console.log('Dependencies already installed');
        startServer();
    }
}

// Validate configuration
function validateConfig() {
    try {
        const config = require('./config.js');
        
        // Check required config properties
        const requiredProps = ['baseurl', 'port', 'ddosProtection', 'logging'];
        const missingProps = requiredProps.filter(prop => !config[prop]);
        
        if (missingProps.length > 0) {
            throw new Error(`Missing config properties: ${missingProps.join(', ')}`);
        }
        
        // Validate port
        if (typeof config.port !== 'number' || config.port < 1 || config.port > 65535) {
            throw new Error('Invalid port number in config');
        }
        
        console.log('Configuration validated');
        console.log(`   Server will run on: ${config.baseurl}:${config.port}`);
        
        return config;
    } catch (error) {
        console.error('Configuration error:', error.message);
        process.exit(1);
    }
}

// Start the server
function startServer() {
    console.log('\nStarting...\n');
    
    const server = spawn('node', ['server.js'], {
        stdio: 'inherit',
        shell: true
    });
    
    server.on('error', (error) => {
        console.error('Failed to start server:', error.message);
        process.exit(1);
    });
    
    server.on('close', (code) => {
        if (code !== 0) {
            console.error(`Server exited with code ${code}`);
            process.exit(code);
        }
    });
    
    // Handle graceful shutdown
    process.on('SIGINT', () => {
        console.log('\n🛑 Shutting down...');
        server.kill('SIGINT');
        process.exit(0);
    });
    
    process.on('SIGTERM', () => {
        console.log('\n🛑 Shutting down...');
        server.kill('SIGTERM');
        process.exit(0);
    });
}

// Main startup sequence
function main() {
    console.log('Performing startup checks...\n');
    
    try {
        // Ensures all of the dirs are there.
        ensureDirectories();
        
        // Check in dirs for required files
        checkRequiredFiles();
        
        // Validates the config file
        const config = validateConfig();
        
        // Checks and installs dependencies needed
        checkDependencies();
        
    } catch (error) {
        console.error('Startup failed:', error.message);
        process.exit(1);
    }
}

// Display help information
function showHelp() {
    console.log(`
Usage: node start.js [options]

Options:
  --help, -h     Show this help message
  --version, -v  Show version info
  --check        Only perform checks without starting server (cool)

Examples:
  node start.js           Start ddos-protector
  node start.js --check   Check config and files
`);
}

// Parse command line arguments
const args = process.argv.slice(2);

if (args.includes('--help') || args.includes('-h')) {
    showHelp();
    process.exit(0);
}

if (args.includes('--version') || args.includes('-v')) {
    const package = require('./package.json');
    console.log(`ddos-protector / g / v${package.version} / made by @700service.exe`);
    process.exit(0);
}

if (args.includes('--check')) {
    console.log(' Running config checks..\n');
    ensureDirectories();
    checkRequiredFiles();
    validateConfig();
    console.log('\nAll checks passed! The protector is ready to start.');
    process.exit(0);
}

// Start the app
main();