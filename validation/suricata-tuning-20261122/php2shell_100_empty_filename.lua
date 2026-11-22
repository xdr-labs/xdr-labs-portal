-- QA-ONLY Suricata 8 Lua detector. Not approved for operating Sensor installation.
-- Detects at least 100 distinct multipart sections whose file Content-Disposition
-- headers have filename="". It is NOT proof of CVE-2026-109618 exploitation.
-- Exact count depends on HTTP body inspection limits and Lua script deployment.

local http = require("suricata.http")

function init(args)
    return {}
end

function match(args)
    local tx = http.get_tx()
    if not tx then
        return 0
    end

    local request_line = tx:request_line()
    if type(request_line) ~= "string" or not string.find(request_line, "^POST%s") then
        return 0
    end
    local ct = tx:request_header("Content-Type")
    if type(ct) ~= "string" then
        return 0
    end
    local ct_low = string.lower(ct)
    if not string.find(ct_low, "multipart/form-data", 1, true) then
        return 0
    end
    local boundary = string.match(ct, "[bB][oO][uU][nN][dD][aA][rR][yY]%s*=%s*\"?([^\";%s]+)")
    if not boundary or #boundary < 1 or #boundary > 70 then
        return 0
    end

    local body = tx:request_body()
    if type(body) ~= "string" or #body < 1000 or #body > 2097152 then
        return 0
    end

    local marker = "--" .. boundary
    local position = 1
    local scanned = 0
    local empty_controls = 0
    local marker_len = #marker
    while scanned < 1100 do
        local begin_at = string.find(body, marker, position, true)
        if not begin_at then
            return 0
        end
        local next_at = string.find(body, marker, begin_at + marker_len, true)
        if not next_at then
            return 0
        end
        scanned = scanned + 1
        local part = string.sub(body, begin_at + marker_len, next_at - 1)
        local header_end = string.find(part, "\r\n\r\n", 1, true)
        if header_end and header_end <= 4096 then
            local headers = string.lower(string.sub(part, 1, header_end - 1))
            if string.find(headers, "content-disposition: form-data", 1, true)
                and string.find(headers, 'filename=""', 1, true) then
                empty_controls = empty_controls + 1
                if empty_controls >= 100 then
                    return 1
                end
            end
        end
        position = next_at
    end
    return 0
end
