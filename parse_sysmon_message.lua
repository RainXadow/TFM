function parse_message(tag, timestamp, record)
    local message_field = record["Message"]

    if message_field and type(message_field) == "string" then
        local parsed_data = {}
        for line in message_field:gmatch("([^\r\n]+)") do
            local key, value = line:match("([^:]+):%s*(.*)")
            
            if key and value then
                key = key:match("^%s*(.-)%s*$")
                value = value:match("^%s*(.-)%s*$")

                parsed_data[key] = value
            end
        end
        record["messageJson"] = parsed_data
    end

    return 2, timestamp, record
end


-- if not _ENV then 
--     print("--- Ejecutando en modo de prueba ---")

--     local sample_record = {
--         ["@timestamp"] = "2025-05-30T07:59:51.700Z",
--         ["ProviderName"] = "Microsoft-Windows-Sysmon",
--         ["EventID"] = 10,
--         ["Message"] = "Process Create:\r\nRuleName: technique_id=T1018,technique_name=Remote System Discovery\r\nUtcTime: 2025-05-30 07:59:50.084\r\nProcessGuid: {3a93c15b-6576-6839-3109-000000000500}\r\nProcessId: 3872\r\nImage: C:\\Windows\\System32\\PING.EXE\r\nFileVersion: 10.0.17763.1 (WinBuild.160101.0800)\r\nDescription: TCP/IP Ping Command\r\nProduct: Microsoft® Windows® Operating System\r\nCompany: Microsoft Corporation\r\nOriginalFileName: ping.exe\r\nCommandLine: \"C:\\Windows\\system32\\PING.EXE\" theia-devenvironment.westeurope.cloudapp.azure.com\r\nCurrentDirectory: C:\\Users\\Administrator\\\r\nUser: WIN-FSE1B39DNO3\\Administrator\r\nLogonGuid: {3a93c15b-1930-6837-5748-050000000000}\r\nLogonId: 0x54857\r\nTerminalSessionId: 1\r\nIntegrityLevel: High\r\nHashes: SHA1=8757646428A176F76E6F38458A25902A8FEBA9C0,MD5=56633150D77AE242D07727B0564430BB,SHA256=741AD992403C78A8A7DBD97C74FDA06594A247E9E2FA05A40BB6945403A90056,IMPHASH=8C3BE1286CDAD6AC1136D0BB6C83FF41\r\nParentProcessGuid: {3a93c15b-2710-6838-7807-000000000500}\r\nParentProcessId: 4248\r\nParentImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\nParentCommandLine: \"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" \r\nParentUser: WIN-FSE1B39DNO3\\Administrator",
--     }

--     local original_record = {}
--     for k, v in pairs(sample_record) do
--         original_record[k] = v
--     end

--     local status, new_timestamp, modified_record = parse_message("winevtlog", "sample_timestamp", sample_record)

--     print("\n--- Registro Original ---")
--     for k, v in pairs(original_record) do
--         print("  " .. tostring(k) .. ": " .. tostring(v))
--     end

--     print("\n--- Registro Modificado ---")
--     if status == 2 then
--         print("  Status: OK")
--         for k, v in pairs(modified_record) do
--             if k == "Message" and type(v) == "table" then
--                 print("  Message (Parsed JSON): {")
--                 for sub_k, sub_v in pairs(v) do
--                     print("    " .. tostring(sub_k) .. ": \"" .. tostring(sub_v) .. "\"")
--                 end
--                 print("  }")
--             else
--                 print("  " .. tostring(k) .. ": " .. tostring(v))
--             end
--         end
--     else
--         print("  Status: Error (code " .. tostring(status) .. ")")
--         print("  Original record (not modified):")
--         for k, v in pairs(original_record) do
--             print("  " .. tostring(k) .. ": " .. tostring(v))
--         end
--     end
-- end