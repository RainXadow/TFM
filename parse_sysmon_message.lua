function clean_value(str)
    if str then
        str = str:gsub("^\t+", "")
        str = str:gsub("\r", "")  
        str = str:gsub("\n", "")  
        str = str:gsub("^%s+", "")
        str = str:gsub("%s+$", "")
        if str == "-" then return nil end
    end
    return str
end

function parse_message_security(tag, timestamp, record)
    -- Solo procesar si el Tag es de seguridad y si el campo 'Message' existe
    if not (tag == "winevtlog.security" and record.Message) then
        return 2, timestamp, record -- No coincidir, mantener el registro original
    end

    local message = record.Message
    local lines = {}
    for line in message:gmatch("[^\r\n]+") do
        table.insert(lines, line)
    end

    local parsed_data = {}
    local current_path = "Message" -- Prefijo base para los campos
    local path_stack = {}         -- Para manejar jerarquías anidadas
    local current_array_key = nil -- Para manejar arrays de privilegios

    local i = 1
    while i <= #lines do
        local line = lines[i]
        local trimmed_line = clean_value(line)

        if trimmed_line == "" or trimmed_line:match("This event is generated") then
            i = i + 1
            goto continue
        end

        local key_value_match = trimmed_line:match("^([^\t\r\n:]+):\t*(.*)$")

        if key_value_match then
            local key = clean_value(key_value_match[1])
            local value = clean_value(key_value_match[2])

            if value == "" or (i + 1 <= #lines and lines[i+1]:match("^\t\t%s*[^\t\s]")) then
                
                while #path_stack > 0 do
                    local last_indent_level = path_stack[#path_stack].indent_level
                    local current_indent_level = line:match("^\t*")
                    if #current_indent_level < last_indent_level then
                        table.remove(path_stack)
                    else
                        break
                    end
                end

                table.insert(path_stack, {key = key, indent_level = #line:match("^\t*")})
                current_path = "Message"
                for _, p_item in ipairs(path_stack) do
                    current_path = current_path .. "." .. p_item.key
                end
                current_array_key = nil 

            else
                local full_key = current_path .. "." .. key
                parsed_data[full_key] = value
                current_array_key = nil 
            end
        elseif current_array_key and trimmed_line ~= "" then
            local value_element = clean_value(trimmed_line)
            if not parsed_data[current_array_key] then
                parsed_data[current_array_key] = {}
            end
            table.insert(parsed_data[current_array_key], value_element)

        elseif trimmed_line:match("^Privileges:$") then
            local key = "Privileges"
            current_array_key = current_path .. "." .. key -- Establecer el modo array
            parsed_data[current_array_key] = {} -- Inicializar como una tabla para el array
            i = i + 1 -- Mover al siguiente elemento
            goto continue

        else
        end

        i = i + 1
        ::continue::
    end

    record.Message = nil

    for k, v in pairs(parsed_data) do
        record[k] = v
    end

    return 1, timestamp, record
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
