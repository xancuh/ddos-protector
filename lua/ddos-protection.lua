
-- The Main Script
-- This script analyzes incoming requests and determines protection actions
-- Do not edit this if you dont know what you are doing.

local function analyze_request(ip, request_count, user_agent, url, method)
    local risk_score = 0
    local reasons = {}
    
    
    if request_count > 100 then
        risk_score = risk_score + 30
        table.insert(reasons, "High request frequency")
    elseif request_count > 50 then
        risk_score = risk_score + 15
        table.insert(reasons, "Moderate request frequency")
    end
    
    
    local suspicious_agents = {
        "bot", "crawler", "spider", "scraper", "curl", "wget", 
        "python", "go-http", "java", "perl", "ruby"
    }
    
    local user_agent_lower = string.lower(user_agent or "")
    for _, agent in ipairs(suspicious_agents) do
        if string.find(user_agent_lower, agent) then
            risk_score = risk_score + 20
            table.insert(reasons, "Suspicious user agent: " .. agent)
            break
        end
    end
    
    
    if not user_agent or user_agent == "" then
        risk_score = risk_score + 10
        table.insert(reasons, "Missing user agent")
    end
    
    
    local url_lower = string.lower(url or "")
    local suspicious_patterns = {
        "%.php", "%.asp", "%.jsp", "admin", "login", "wp%-admin",
        "xmlrpc", "phpmyadmin", "cpanel", "webmail"
    }
    
    for _, pattern in ipairs(suspicious_patterns) do
        if string.find(url_lower, pattern) then
            risk_score = risk_score + 15
            table.insert(reasons, "Suspicious URL pattern: " .. pattern)
        end
    end
    
    
    if string.len(url) > 1000 then
        risk_score = risk_score + 25
        table.insert(reasons, "Abnormally long URL")
    end
    
    
    local allowed_methods = {GET = true, POST = true, PUT = true, DELETE = true, PATCH = true, OPTIONS = true}
    if not allowed_methods[method] then
        risk_score = risk_score + 20
        table.insert(reasons, "Unusual HTTP method: " .. method)
    end
    
    
    local sql_patterns = {
        "union", "select", "insert", "update", "delete", "drop",
        "create", "alter", "exec", "script", "onload", "onerror"
    }
    
    for _, pattern in ipairs(sql_patterns) do
        if string.find(url_lower, pattern) then
            risk_score = risk_score + 30
            table.insert(reasons, "Potential SQL injection: " .. pattern)
        end
    end
    
    
    local action = "ALLOW"
    if risk_score >= 60 then
        action = "BLOCK"
    elseif risk_score >= 35 then
        action = "SUSPICIOUS"
    elseif risk_score >= 20 then
        action = "MONITOR"
    end
    
    
    local result = {
        action = action,
        risk_score = risk_score,
        reasons = reasons,
        ip = ip,
        timestamp = os.time()
    }
    
    local result_string = string.format(
        "%s|SCORE:%d|IP:%s|REASONS:%s", 
        action, 
        risk_score, 
        ip, 
        table.concat(reasons, ",")
    )
    
    return result_string
end


local function check_rate_limit(request_count, time_window, max_requests)
    local requests_per_second = request_count / time_window
    
    if requests_per_second > max_requests then
        return "RATE_LIMIT_EXCEEDED"
    end
    
    return "RATE_OK"
end


local function ddos_protection(params)
    local ip = params.ip or "unknown"
    local request_count = tonumber(params.requestCount) or 0
    local user_agent = params.userAgent or ""
    local url = params.url or "/"
    local method = params.method or "GET"
    local total_requests = tonumber(params.totalRequests) or 0
    
    local analysis_result = analyze_request(ip, request_count, user_agent, url, method)
    
    
    local rate_result = check_rate_limit(request_count, 60, 10) -- 10 requests per minute
    
    if rate_result == "RATE_LIMIT_EXCEEDED" then
        return "BLOCK|RATE_LIMIT|" .. analysis_result
    end
    
    return analysis_result
end

if ip and requestCount then
    local params = {
        ip = ip,
        requestCount = requestCount,
        userAgent = userAgent,
        url = url,
        method = method,
        totalRequests = totalRequests
    }
    
    local result = ddos_protection(params)
    return result
else
    return "ERROR|Missing required parameters"
end