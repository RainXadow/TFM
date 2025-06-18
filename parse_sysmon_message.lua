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
    local current_array_key = nil
    local i = 1

    while i <= #lines do
      local line = lines[i]
      local trimmed = line:match("^%s*(.-)%s*$")

      if trimmed:match("^[^:\t]+:$") then
        current_group = trimmed:match("^(.-):$")
        current_group = normalize_key(current_group)
        current_array_key = nil
      elseif line:match("^\t+[^:\t]+:%s*%S") then
        local key, val = line:match("^\t+([^:]+):%s*(.+)$")
        if key and val then
          key = normalize_key(key)
          if current_group then
            result[current_group] = result[current_group] or {}
            result[current_group][key] = val
          end
        end
      elseif line:match("^[^:\t]+:%s*%S") then
        local key, val = line:match("^([^:]+):%s*(.+)$")
        if key and val then
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

            if next_line:match("^\t") then
              table.insert(arr, trimmed_next)
            end

            i = i + 1
          end

          if #arr == 1 then
            simple_fields[key] = arr[1]
            result[key] = arr[1] 
          else
            simple_fields[key] = arr
            result[key] = arr
          end
        end
        current_array_key = nil
      else
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

          parsed_data[key] = value
        end
      end
    end
    record["messageJson"] = parsed_data
  end

  return 2, timestamp, record
end

-- local example_security =
-- "Special privileges assigned to new logon.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tKINGSLANDING$\r\n\tAccount Domain:\t\tSEVENKINGDOMS\r\n\tLogon ID:\t\t0x9062BC\r\n\r\nPrivileges:\t\tSeSecurityPrivilege\r\n\t\t\tSeBackupPrivilege\r\n\t\t\tSeRestorePrivilege\r\n\t\t\tSeTakeOwnershipPrivilege\r\n\t\t\tSeDebugPrivilege\r\n\t\t\tSeSystemEnvironmentPrivilege\r\n\t\t\tSeLoadDriverPrivilege\r\n\t\t\tSeImpersonatePrivilege\r\n\t\t\tSeDelegateSessionUserImpersonatePrivilege\r\n\t\t\tSeEnableDelegationPrivilege"

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
-- ProcessGuid: {abc123}
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
