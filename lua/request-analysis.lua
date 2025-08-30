-- Request Analysis Script
-- Advanced analysis of request patterns to detect DDoS attacks
-- Do not edit this if you dont know what you are doing.

local function analyze_request_patterns(ip, requests, user_agent, url, method)
    local anomaly_score = 0
    local alerts = {}
    
    if requests > 20 then
        local burst_score = math.min(requests / 5, 50)
        anomaly_score = anomaly_score + burst_score
        table.insert(alerts, string.format("Burst pattern detected: %d requests", requests))
    end
    
    local ua_lower = string.lower(user_agent or "")
    
    
    local bot_patterns = {
        "bot", "crawl", "spider", "scrape", "fetch", "curl", "wget",
        "python%-requests", "go%-http%-client", "java/", "apache%-httpclient"
    }
    
    for _, pattern in ipairs(bot_patterns) do
        if string.find(ua_lower, pattern) then
            anomaly_score = anomaly_score + 25
            table.insert(alerts, "Bot-like user agent detected")
            break
        end
    end
    
    
    if not user_agent or user_agent == "" or string.len(user_agent) < 10 then
        anomaly_score = anomaly_score + 15
        table.insert(alerts, "Suspicious or missing user agent")
    end
    
    
    local url_lower = string.lower(url or "/")
    
    
    local traversal_patterns = {"%.%./", "%%2e%%2e", "%%2f", "%%5c"}
    for _, pattern in ipairs(traversal_patterns) do
        if string.find(url_lower, pattern) then
            anomaly_score = anomaly_score + 40
            table.insert(alerts, "Directory traversal attempt detected")
            break
        end
    end
    
    
    local xss_patterns = {"<script", "javascript:", "onload=", "onerror=", "alert%("}
    for _, pattern in ipairs(xss_patterns) do
        if string.find(url_lower, pattern) then
            anomaly_score = anomaly_score + 35
            table.insert(alerts, "Potential XSS attack detected")
            break
        end
    end
    
    
    local sql_patterns = {
        "union.*select", "1=1", "' or ", "admin'--", "drop table",
        "insert into", "update.*set", "delete from"
    }
    for _, pattern in ipairs(sql_patterns) do
        if string.find(url_lower, pattern) then
            anomaly_score = anomaly_score + 45
            table.insert(alerts, "SQL injection attempt detected")
            break
        end
    end
    
    
    local uncommon_methods = {
        TRACE = 20, CONNECT = 25, PROPFIND = 30, PROPPATCH = 30,
        MKCOL = 30, COPY = 25, MOVE = 25, LOCK = 25, UNLOCK = 25
    }
    
    if uncommon_methods[method] then
        anomaly_score = anomaly_score + uncommon_methods[method]
        table.insert(alerts, string.format("Uncommon HTTP method: %s", method))
    end
    
    
    if string.len(url) > 500 then
        local length_penalty = math.min((string.len(url) - 500) / 100, 20)
        anomaly_score = anomaly_score + length_penalty
        table.insert(alerts, "Abnormally long URL detected")
    end
    
    
    local attack_targets = {
        "/wp%-admin", "/admin", "/phpmyadmin", "/cpanel", "/webmail",
        "/xmlrpc%.php", "/wp%-login%.php", "/.env", "/config%.php",
        "/database%.sql", "/backup", "/test", "/debug"
    }
    
    for _, target in ipairs(attack_targets) do
        if string.find(url_lower, target) then
            anomaly_score = anomaly_score + 20
            table.insert(alerts, "Attack target detected: " .. target)
        end
    end
    
    return anomaly_score, alerts
end

local function calculate_risk_level(anomaly_score)
    if anomaly_score >= 80 then
        return "CRITICAL", "BLOCK"
    elseif anomaly_score >= 50 then
        return "HIGH", "SUSPICIOUS"
    elseif anomaly_score >= 25 then
        return "MEDIUM", "MONITOR"
    else
        return "LOW", "ALLOW"
    end
end

local function perform_analysis()
    local ip_addr = ip or "unknown"
    local request_count = tonumber(requestCount) or 0
    local total_reqs = tonumber(totalRequests) or 0
    local user_agent_str = userAgent or ""
    local url_path = url or "/"
    local http_method = method or "GET"
    local suspicious_threshold = tonumber(suspiciousThreshold) or 100
    
    
    local anomaly_score, alerts = analyze_request_patterns(
        ip_addr, request_count, user_agent_str, url_path, http_method
    )
    
    
    if request_count > suspicious_threshold then
        anomaly_score = anomaly_score + 30
        table.insert(alerts, "Exceeded suspicious request threshold")
    end
    
    
    local risk_level, action = calculate_risk_level(anomaly_score)
    
    -- Create comprehensive result
    local timestamp = os.time()
    local result_data = {
        action = action,
        risk_level = risk_level,
        anomaly_score = anomaly_score,
        ip = ip_addr,
        request_count = request_count,
        total_requests = total_reqs,
        alerts = alerts,
        timestamp = timestamp,
        analysis_version = "1.0"
    }
    
    
    local alert_string = table.concat(alerts, "; ")
    local result = string.format(
        "%s|RISK:%s|SCORE:%d|ALERTS:%s|IP:%s|REQS:%d|TIME:%d",
        action,
        risk_level,
        anomaly_score,
        alert_string,
        ip_addr,
        request_count,
        timestamp
    )
    
    return result
end

return perform_analysis()