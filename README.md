# ddos-protector
In Lua, protects you from any unwanted packets being sent to your local network or server.
This is open-source, feel free to fork this all you want.
Contact **@700service.exe** on discord if you want any more info or need help with something.

# How to setup:
1. **Install Dependencies**
   ```bash
   npm install
   ```
2. **Configure Settings**
   Edit `config.js` to customize protection parameters. This is important because it needs a proper port and baseUrl to actually run.

3. **Start Protection**
   ```bash
   npm start
   ```

5. **Access Endpoints:**
   - Main: http://localhost:thesetportinconfig
   - Health: http://localhost:thesetportinconfig/health  
   - Admin: http://localhost:thesetportinconfig/admin/status

## More access endpoints and what they do:

### GET /
Basic endpoint returning protection status

### GET /health
Health check with protection statistics

### GET /admin/status
Detailed protection status including:
- Active connections
- Blocked IPs list
- Suspicious IPs
- Real-time statistics










g
