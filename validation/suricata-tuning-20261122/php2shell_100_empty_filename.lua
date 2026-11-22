-- QA-ONLY Suricata 8 Lua detector. Not approved for operating Sensor installation.
-- Detects at least 100 distinct multipart sections whose file Content-Disposition
-- headers have filename="". It is NOT proof of CVE-2026-109618 exploitation.
-- Exact count depends on HTTP body inspection limits and Lua script deployment.

local http = require("suricata.http")

function init(args)
    return {}
end

-- Require actual MIME boundary framing rather than a marker inside form data.
local function next_mime_boundary(body, marker, from)
    local position = from
    while position <= #body do
        local start_at = string.find(body, marker, position, true)
        if not start_at then
            return nil
        end
        local prefix_ok = start_at == 1 or
            (start_at > 2 and string.sub(body, start_at - 2, start_at - 1) == "\r\n")
        local after = string.sub(body, start_at + #marker, start_at + #marker + 1)
        if prefix_ok and (after == "\r\n" or after == "--") then
            return start_at
        end
        position = start_at + #marker
    end
    return nil
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

    -- Suricata 8 exposes request_body() as a 1-based table of byte chunks,
    -- followed by optional offsets, NOT as a single string.
    local chunks = tx:request_body()
    if type(chunks) ~= "table" then
        return 0
    end
    local total = 0
    for _, chunk in ipairs(chunks) do
        if type(chunk) ~= "string" then
            return 0
        end
        total = total + #chunk
        if total > 2097152 then
            return 0
        end
    end
    if total < 1000 then
        return 0
    end
    local body = table.concat(chunks)
    if #body ~= total then
        return 0
    end

    local marker = "--" .. boundary
    local position = 1
    local scanned = 0
    local empty_controls = 0
    local marker_len = #marker
    while scanned < 1100 do
        local begin_at = next_mime_boundary(body, marker, position)
        if not begin_at then
            return 0
        end
        local next_at = next_mime_boundary(body, marker, begin_at + marker_len)
        if not next_at then
            return 0
        end
        scanned = scanned + 1
        local part = string.sub(body, begin_at + marker_len, next_at - 1)
        local header_end = string.find(part, "\r\n\r\n", 1, true)
        if header_end and header_end <= 4096 then
            local headers = string.lower(string.sub(part, 1, header_end - 1))
            -- Count only an empty filename parameter on the actual
            -- Content-Disposition header, never on unrelated X-* headers.
            local disposition = string.match(headers, "content%-disposition:%s*([^\r\n]+)")
            if disposition
                and string.find(disposition, "^form%-data[;%s]")
                and string.find(disposition, '[;%s]filename%s*=%s*""') then
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
