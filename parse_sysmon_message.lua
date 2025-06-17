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
          else
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


-- local example_security = "An account failed to log on.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-21-3208247626-2009448666-1580989171-500\r\n\tAccount Name:\t\tAdministrator\r\n\tAccount Domain:\t\tWIN-FSE1B39DNO3\r\n\tLogon ID:\t\t0x54857\r\n\r\nLogon Type:\t\t\t2\r\n\r\nAccount For Which Logon Failed:\r\n\tSecurity ID:\t\tS-1-0-0\r\n\tAccount Name:\t\tAdministrator\r\n\tAccount Domain:\t\tWIN-FSE1B39DNO3\r\n\r\nFailure Information:\r\n\tFailure Reason:\t\tUnknown user name or bad password.\r\n\tStatus:\t\t\t0xC000006D\r\n\tSub Status:\t\t0xC000006A\r\n\r\nProcess Information:\r\n\tCaller Process ID:\t0x21f8\r\n\tCaller Process Name:\tC:\\Windows\\System32\\svchost.exe\r\n\r\nNetwork Information:\r\n\tWorkstation Name:\tWIN-FSE1B39DNO3\r\n\tSource Network Address:\t::1\r\n\tSource Port:\t\t0\r\n\r\nDetailed Authentication Information:\r\n\tLogon Process:\t\tseclogo\r\n\tAuthentication Package:\tNegotiate\r\n\tTransited Services:\t-\r\n\tPackage Name (NTLM only):\t-\r\n\tKey Length:\t\t0\r\n\r\nThis event is generated when a logon request fails. It is generated on the computer where access was attempted.\r\n\r\nThe Subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\r\n\r\nThe Logon Type field indicates the kind of logon that was requested. The most common types are 2 (interactive) and 3 (network).\r\n\r\nThe Process Information fields indicate which account and process on the system requested the logon.\r\n\r\nThe Network Information fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\r\n\r\nThe authentication information fields provide detailed information about this specific logon request.\r\n\t- Transited services indicate which intermediate services have participated in this logon request.\r\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\r\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested."

-- print("---- parse_message_security ----")
-- local _, _, parsed_record_security = parse_message_security("tag", os.time(), { Message = example_security })
-- for k, v in pairs(parsed_record_security["messageJson"]) do
--     print(k .. " = " .. v)
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
--     print(k .. " = " .. v)
-- end
