-- IP Blocking and Management Script
-- Handles IP blocking decisions, whitelist/blacklist management
-- Do not edit this if you dont know what you are doing. If you remove the is_private_ip function, every single ip will be blocked, including localhost and other private ips dedicated to your network.

local function is_private_ip(ip)
    -- Checks for private IP ranges
    local private_ranges = {
        "^127%.",          -- 127.0.0.0/8 (localhost)
        "^10%.",           -- 10.0.0.0/8 (private)
        "^192%.168%.",     -- 192.168.0.0/16 (private)
        "^172%.1[6-9]%.",  -- 172.16.0.0/12 (private)
        "^172%.2[0-9]%.",  -- 172.16.0.0/12 (private)
        "^172%.3[0-1]%.",  -- 172.16.0.0/12 (private)
        "^169%.254%.",     -- 169.254.0.0/16 (link-local)
        "^::1$",           -- IPv6 localhost
        "^fe80:",          -- IPv6 link-local
        "^fc00:",          -- IPv6 unique local
        "^fd00:"           -- IPv6 unique local
    }
    
    for _, pattern in ipairs(private_ranges) do
        if string.match(ip, pattern) then
            return true
        end
    end
    
    return false
end

local function is_whitelisted_ip(ip, whitelist)
    if not whitelist then return false end
    
    for _, whitelisted in ipairs(whitelist) do
        if ip == whitelisted then
            return true
        end
    end
    
    return false
end

local function calculate_block_duration(offense_count, base_duration)
    local multiplier = math.min(offense_count, 10)
    local duration = base_duration * multiplier
    
    -- Maximum block time: 24 hours
    local max_duration = 24 * 60 * 60 * 1000
    return math.min(duration, max_duration)
end

local function analyze_ip_reputation(ip, request_history)
    local reputation_score = 100
    local flags = {}
    
    if request_history then
        local total_requests = #request_history
        
        if total_requests > 1000 then
            reputation_score = reputation_score - 30
            table.insert(flags, "High volume requester")
        elseif total_requests > 500 then
            reputation_score = reputation_score - 15
            table.insert(flags, "Moderate volume requester")
        end
        
        local suspicious_count = 0
        for _, req in ipairs(request_history) do
            if req.suspicious then
                suspicious_count = suspicious_count + 1
            end
        end
        
        local suspicious_ratio = suspicious_count / total_requests
        if suspicious_ratio > 0.5 then
            reputation_score = reputation_score - 40
            table.insert(flags, "High suspicious activity ratio")
        elseif suspicious_ratio > 0.2 then
            reputation_score = reputation_score - 20
            table.insert(flags, "Moderate suspicious activity ratio")
        end
    end
    
    
    local reputation_level
    if reputation_score >= 80 then
        reputation_level = "GOOD"
    elseif reputation_score >= 60 then
        reputation_level = "NEUTRAL"
    elseif reputation_score >= 40 then
        reputation_level = "POOR"
    else
        reputation_level = "BAD"
    end
    
    return reputation_score, reputation_level, flags
end

local function should_block_ip(ip, request_count, anomaly_score, reputation_score)
    
    if is_private_ip(ip) then
        return false, "Private IP - not blocking"
    end
    
    local whitelist = {"127.0.0.1", "::1"}
    if is_whitelisted_ip(ip, whitelist) then
        return false, "Whitelisted IP"
    end
    
    
    local should_block = false
    local reason = ""
    

    if anomaly_score >= 80 then
        should_block = true
        reason = "High anomaly score: " .. anomaly_score
    
    elseif request_count > 100 and reputation_score < 50 then
        should_block = true
        reason = "High request rate with poor reputation"
    
    elseif request_count > 200 then
        should_block = true
        reason = "Excessive request count: " .. request_count
    
    elseif anomaly_score >= 50 and request_count > 50 then
        should_block = true
        reason = "Combined anomaly and volume indicators"
    end
    
    return should_block, reason
end

local function blocking_decision()
    local ip_addr = ip or "unknown"
    local req_count = tonumber(requestCount) or 0
    local anomaly_score = tonumber(anomalyScore) or 0
    local user_agent_str = userAgent or ""
    local url_path = url or "/"
    local http_method = method or "GET"
    
    local reputation_score, reputation_level, reputation_flags = analyze_ip_reputation(ip_addr, nil)
    
    local should_block, block_reason = should_block_ip(ip_addr, req_count, anomaly_score, reputation_score)
    
    local block_duration = 0
    if should_block then
        local offense_count = 1
        block_duration = calculate_block_duration(offense_count, 30 * 60 * 1000)
    end
    
    local action = should_block and "BLOCK" or "ALLOW"
    local timestamp = os.time()
    
    local result = string.format(
        "%s|IP:%s|REPUTATION:%s(%d)|REASON:%s|DURATION:%d|FLAGS:%s|TIME:%d",
        action,
        ip_addr,
        reputation_level,
        reputation_score,
        block_reason or "Clean request",
        block_duration,
        table.concat(reputation_flags, ","),
        timestamp
    )
    
    return result
end

return blocking_decision()