local function infer_type_and_tag(key, val)
  local function is_integer(s)
    return s:match("^0x[%x]+$") or s:match("^%d+$")
  end

  local function is_ipv4(ip)
    if type(ip) ~= "string" then return false end
    local octets = { ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$") }
    if #octets ~= 4 then return false end
    for _, octet in ipairs(octets) do
      local num = tonumber(octet)
      if not num or num < 0 or num > 255 then return false end
    end
    return true
  end

  local function is_ipv6(ip)
    if type(ip) ~= "string" then return false end

    local clean_ip = ip:match("^[^%s]+")
    if not clean_ip then return false end

    local colon_count = select(2, clean_ip:gsub(":", ""))
    if colon_count < 2 then return false end

    if not clean_ip:match("^[0-9a-fA-F:]+$") then return false end

    local first_double_colon = clean_ip:find("::", 1, true)
    if first_double_colon then
      local second_double_colon = clean_ip:find("::", first_double_colon + 1, true)
      if second_double_colon then return false end
    end

    local parts = {}
    for part in clean_ip:gmatch("([^:]+)") do
      table.insert(parts, part)
    end

    for _, part in ipairs(parts) do
      if #part > 4 or not part:match("^[0-9a-fA-F]+$") then
        return false
      end
    end

    if not first_double_colon and #parts ~= 8 then
      return false
    end

    if first_double_colon and #parts > 8 then
      return false
    end

    return true
  end

  if is_integer(val) then
    return key .. "_int", tonumber(val)
  elseif is_ipv4(val) then
    return key .. "_ipv", val
  elseif is_ipv6(val) then
    return key .. "_ipv", val
  else
    return key .. "_str", val
  end
end

local function is_valid_value(val)
  return val and val ~= "" and val ~= "-"
end


function parse_message_security(tag, timestamp, record)
  local message = record["Message"]
  local result = {}
  local simple_fields = {}

  if not message or type(message) ~= "string" then
    return 2, timestamp, record
  end

  local function normalize_key(key)
    if key then
      key = key:gsub(" ", "_")
    end
    return key
  end

  message = message .. "\r\n\r\n"

  for block in message:gmatch("(.-)\r\n\r\n") do
    local lines = {}
    for line in block:gmatch("([^\r\n]+)") do
      table.insert(lines, line)
    end

    local current_group = nil
    local i = 1

    while i <= #lines do
      local line = lines[i]
      local trimmed = line:match("^%s*(.-)%s*$")

      if trimmed:match("^[^:\t]+:$") then
        current_group = normalize_key(trimmed:match("^(.-):$"))
      elseif line:match("^\t+[^:\t]+:%s*%S") then
        local key, val = line:match("^\t+([^:]+):%s*(.+)$")
        if key and val and is_valid_value(val) and current_group then
          key = normalize_key(key)
          local new_key, new_val = infer_type_and_tag(key, val)
          result[current_group] = result[current_group] or {}
          result[current_group][new_key] = new_val
        end
      elseif line:match("^[^:\t]+:%s*%S") then
        local key, val = line:match("^([^:]+):%s*(.+)$")
        if key and val and is_valid_value(val) then
          key = normalize_key(key)
          local arr = { val }
          i = i + 1
          while i <= #lines do
            local next_line = lines[i]
            local trimmed_next = next_line:match("^%s*(.-)%s*$")

            if trimmed_next == "" or trimmed_next:match("^[^:\t]+:") or trimmed_next:match("^[^:\t]+:$") then
              i = i - 1
              break
            end

            if next_line:match("^\t") and is_valid_value(trimmed_next) then
              table.insert(arr, trimmed_next)
            end

            i = i + 1
          end

          if #arr == 1 and is_valid_value(arr[1]) then
            local new_key, new_val = infer_type_and_tag(key, arr[1])
            simple_fields[new_key] = new_val
            result[new_key] = new_val
          else
            local concatenated = table.concat(arr, "\n")
            if is_valid_value(concatenated) then
              local new_key, new_val = infer_type_and_tag(key, concatenated)
              simple_fields[new_key] = new_val
              result[new_key] = new_val
            end
          end
        end
      end

      i = i + 1
    end
  end

  for k, v in pairs(result) do
    if type(v) == "table" then
      local is_array = true
      local count = 0
      for kk, _ in pairs(v) do
        if type(kk) ~= "number" then
          is_array = false
          break
        else
          count = count + 1
        end
      end
      if is_array and count > 0 then
        result[k] = table.concat(v, "\n")
      end
    end
  end

  for k, v in pairs(simple_fields) do
    record[k] = v
  end

  record["messageJson"] = result

  return 2, timestamp, record
end

function parse_message(tag, timestamp, record)
  local message_field = record["Message"]
  if message_field and type(message_field) == "string" then
    local parsed_data = {}
    local is_first_line = true

    for line in message_field:gmatch("([^\r\n]+)") do
      if is_first_line then
        is_first_line = false
      else
        local key, value = line:match("([^:]+):%s*(.*)")
        if key and value then
          key = key:match("^%s*(.-)%s*$")
          value = value:match("^%s*(.-)%s*$")

          if is_valid_value(value) then
            local new_key, new_val = infer_type_and_tag(key, value)
            parsed_data[new_key] = new_val
          end
        end
      end
    end

    record["messageJson"] = parsed_data
  end
  return 2, timestamp, record
end

-- local example_security =
-- "An account was successfully logged on.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-0-0\r\n\tAccount Name:\t\t-\r\n\tAccount Domain:\t\t8.8.8.8\r\n\tLogon ID:\t\t0x0\r\n\r\nLogon Information:\r\n\tLogon Type:\t\t3\r\n\tRestricted Admin Mode:\t127.0.0.1\r\n\tVirtual Account:\t\tNo\r\n\tElevated Token:\t\tYes\r\n\r\nImpersonation Level:\t\tImpersonation\r\n\r\nNew Logon:\r\n\tSecurity ID:\t\t2001:0db8:85a3:0000:0000:8a2e:0370:7334\r\n\tAccount Name:\t\tKINGSLANDING$\r\n\tAccount Domain:\t\tSEVENKINGDOMS.LOCAL\r\n\tLogon ID:\t\t0x9CB491\r\n\tLinked Logon ID:\t\t-\r\n\tNetwork Account Name:\t-\r\n\tNetwork Account Domain:\tfe80::f2de:f1ff:fe6f:9c5a\r\n\tLogon GUID:\t\t{ba73e24a-85f6-865e-caab-da4c582ca829}\r\n\r\nProcess Information:\r\n\tProcess ID:\t\t0x0\r\n\tProcess Name:\t\t-\r\n\r\nNetwork Information:\r\n\tWorkstation Name:\t-\r\n\tSource Network Address:\t::1\r\n\tSource Port:\t\t60156\r\n\r\nDetailed Authentication Information:\r\n\tLogon Process:\t\t192.168.1.1\r\n\tAuthentication Package:\tKerberos\r\n\tTransited Services:\t::ffff:192.0.2.128  -- (IPv4-mapped IPv6 address)\r\n\tPackage Name (NTLM only):\t-\r\n\tKey Length:\t\t-\r\n\r\nThis event is generated when a logon session is created. It is generated on the computer that was accessed.\r\n\r\nThe subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\r\n\r\nThe logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).\r\n\r\nThe New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.\r\n\r\nThe network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\r\n\r\nThe impersonation level field indicates the extent to which a process in the logon session can impersonate.\r\n\r\nThe authentication information fields provide detailed information about this specific logon request.\r\n\t- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.\r\n\t- Transited services indicate which intermediate services have participated in this logon request.\r\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\r\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."

-- print("---- parse_message_security ----")
-- local _, _, parsed_record_security = parse_message_security("tag", os.time(), { Message = example_security })

-- print("\n--- Campos jerárquicos (messageJson) ---")
-- for k, v in pairs(parsed_record_security["messageJson"]) do
--   if type(v) == "table" then
--     print(k .. " = {")
--     for subk, subv in pairs(v) do
--       print("  " .. subk .. " = " .. subv)
--     end
--     print("}")
--   else
--     print(k .. " = " .. tostring(v))
--   end
-- end


-- -- Simulación de evento SYSMON
-- print("\n---- parse_message (Sysmon) ----")
-- local example_sysmon = [[
-- Process Create:
-- RuleName: -
-- UtcTime: 2023-06-16 20:41:37.815
-- ProcessGuid: -
-- ProcessId: 1337
-- Image: C:\Windows\System32\cmd.exe
-- CommandLine: cmd.exe /c whoami
-- CurrentDirectory: C:\Users\user\
-- User: SEVENKINGDOMS\user
-- ]]

-- local _, _, parsed_record_sysmon = parse_message("tag", os.time(), { Message = example_sysmon })
-- for k, v in pairs(parsed_record_sysmon["messageJson"]) do
--   print(k .. " = " .. v)
-- end
