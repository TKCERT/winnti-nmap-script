local os = require "os"
local comm = require "comm"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"

description = [[
The winnti-detect script checks if the host is backdoored by winnti rootkit.  It
sends a winnti command to the first three open TCP ports and checks the
response. When the connection to one of these ports fails, the next port is
chosen until three successful tries are completed.  When a winnti infection is
found the script gathers basic host information by sending a query to the
backdoor and printing the response.

*** SECOPS-WARNING ***
Winnti only supports one connection at a time. If you scan a host for winnti
you will reset the current connection if there is one.

*** IMPORTANT ***
Winnti installations may use different encryption keys. The default value
included in this script is 0xABC18CBA (taken from a real sample).
You can set a custom key with --script-args key=0x........
The key must be given in big-endian.

Version 2017-05-31
]]

---
--@usage
--nmap --script winnti-detect.nse [--script-args key=0xCAFEBABE] <target>
--@args key The Winnti XOR key in big endian notation (optional. Default: 0xABC18CBA)
--@output
-- 
--Host script results:
--| winnti: 
--|   PORTS
--|       135 found WINNTI
--|       445 skipped
--|   HOSTINFO
--|     Hostname:  SRV1
--|     Winnti-ID: JKASK-AJEKL-QJSGH-AORPQ-KNCAL_
--|     Hostname2  SRV1-t
--|_    Domain     MYDOMAIN
--

author = "Stefan Ruester"
license = "Proprietary - TLP:WHITE"
categories = {"malware", "safe"}

local WINNTI_STATIC_KEY = 0xABC18CBA

--------------------------------------------------------------------------------
-- Convert string to its hex representation
--------------------------------------------------------------------------------
function tohex(buf)
  local ret=""
  for byte=1, #buf do
    ret = ret .. string.format("%02X", string.byte(buf:sub(byte, byte)))
  end
  return ret
end


--------------------------------------------------------------------------------
-- Remove trailing zeroes from string
--------------------------------------------------------------------------------
function rtrimzero(s)
  if s == nil then return nil end
  return s:match'^(.*[^\0])\0*$'
end


--------------------------------------------------------------------------------
-- Output a hexdump of the string s
--------------------------------------------------------------------------------
function hexdump(buf)
  for byte=1, #buf, 16 do
    local chunk = buf:sub(byte, byte+15)
    io.write(string.format('%08X  ',byte-1))
    chunk:gsub('.', function (c) io.write(string.format('%02X ',string.byte(c))) end)
    io.write(string.rep(' ',3*(16-#chunk)))
    io.write(' ',chunk:gsub('%c','.'),"\n") 
  end
end


--------------------------------------------------------------------------------
-- Check all hosts that are UP
--------------------------------------------------------------------------------
hostrule = function(host)
  return true
end


--------------------------------------------------------------------------------
-- Cycle over open ports and try to find winnti
--------------------------------------------------------------------------------
action = function(host)
  local continue_search = true
  local winnti_proven, winnti_refuted, data
  local num_ports_to_try=4
  local plugin_response={}
  local porttable={}
  local hostinfo=nil

  porttable['name'] = "PORTS"

  local winnti_custom_key = stdnse.get_script_args("key")
  if (winnti_custom_key ~= nil) then
    WINNTI_STATIC_KEY = winnti_custom_key
  end

  stdnse.debug("Using Winnti key 0x%08X", WINNTI_STATIC_KEY)

  local port = nmap.get_ports(host, nil, "tcp", "open")
  while port do

    stdnse.debug("---")

    if (continue_search == false or num_ports_to_try < 1) then
      stdnse.debug("Skipping port %i", port.number)
      table.insert(porttable, string.format("%5i skipped", port.number))
    else
      stdnse.debug("Checking port %i", port.number)
      winnti_proven, winnti_refuted, data = check_wnti(host, port)

      -- We found incidations that there is NO winnti on the host. But we try again ...
      if (winnti_refuted == true) then
        num_ports_to_try = num_ports_to_try - 1
        stdnse.debug(data)
        table.insert(porttable, string.format("%5i clean", port.number))
      end

      -- We found incidations that there IS winnti on the host. No need to try again
      if (winnti_proven == true) then
        continue_search = false
        table.insert(porttable, string.format("%5i found WINNTI", port.number))
        -- data now contains a table with information about the host
        hostinfo = data
      end

      -- Possibly connection problems. We cannot say whether there is winnti or not.
      if (winnti_proven == false and winnti_refuted == false) then
        stdnse.debug(data)
        table.insert(porttable, string.format("%5i unknown", port.number))
      end
    end

    port = nmap.get_ports(host, port, "tcp", "open")
  end
  
  table.insert(plugin_response, porttable)

  if hostinfo ~= nil then
    table.insert(plugin_response, hostinfo)
  end

  return stdnse.format_output(true, plugin_response)
end


--------------------------------------------------------------------------------
-- Connect to host:port and send WINNTI queries
--
-- returns winnti_proven(bool),winnti_refuted(bool),message(string, table when winnti_proven==true)
--------------------------------------------------------------------------------
function check_wnti(host, port)

  -- Create socket
  local socket = nmap.new_socket()
  if (socket == nil) then
    return false, false, "Could not create socket"
  end

  socket:set_timeout(5000)

  -- Connect to host:port
  stdnse.debug("Connecting to %s:%i", host.ip, port.number)
  local status, result = socket:connect(host.ip, port.number)
  if (status == false) then
    return false, false, "Could not connect to host"
  end

  -- Send winnti magic
  stdnse.debug("Sending WINNTI HELO")
  status, result = socket:send(wnti_get_helo_pkt())
  if (status == false) then
    return false, false, "Sending HELO failed"
  end

  -- Send Query-Host-Info
  stdnse.debug("Sending winnti get-host-info command")
  status, result = socket:send(wnti_get_queryhostinfo_pkt())
  if (status == false) then
    return false, false, "Sending Winnti-PING failed"
  end

  -- Receive command confirmation
  status, result = wnti_receive(socket, 16)
  if (status == false) then
    return false, false, string.format("Receiving failed: %s", result)
  end

  -- Check response
  if result == "" or result:sub(1,8) ~= "\x10\x24\x00\x00\x00\x00\x00\x00" then
    -- We got an answer and it reflects no winnti data
    -- or we got no answer due to the server service discarding the winnti command.
    -- Both cases indicate that there is no winnti active, hence set the winnti_refuted flag.
    return false, true, "Response is no winnti command confirmation"
  end

  -- At this point we have received a valid winnti response. Consequently the
  -- winnti_proven flag will be set when exiting the function. But before we return 
  -- we try to get additional information about the host as a *goodie*.

  local hostinfo_tbl={}
  hostinfo_tbl['name']="HOSTINFO"

  -- Just receive again to fetch the data from the previous issued gethostinfo command
  status, result = wnti_receive(socket)
  if (status == false) then
    table.insert(hostinfo_tbl, "Receiving query-host-info packet failed")
    goto endfunc
  end
  
  -- Read fields from answer
  wnti_fill_hostinfo(hostinfo_tbl, result)

  ::endfunc::
  -- winnti_proven=true, winnti_refuted=false
  return true, false, hostinfo_tbl
end


--------------------------------------------------------------------------------
-- Return the WINNTI query-host-info packet
--------------------------------------------------------------------------------
function wnti_get_queryhostinfo_pkt()
  -- The plain query packet
  local pkt_queryhostinfo="\x20\x24\x42\x00\x00\x00\x00\x00" ..
                          "\xBA\x8C\xC1\xAB\x0C\x59\x73\x09" ..
                          "\x01\x04\x42\x00\x00\x00\x03\x08" ..
                          "\x48\xE3\xDF\xE2\x63\x36\x8D\x70" ..
                          "\xAA\x00\x00\x00\x00\x00\x2B\x2B" ..
                          "\x00\x00\x00\x00\x28\x00\x00\x00" ..
                          "\x00\x00\x00\x00\x00\x00\x00\x00" ..
                          "\x00\x00\x00\x00\x01\x01\x00\x00" ..
                          "\x00\x00\x16\x00\x00\x00\x00\x00" ..
                          "\x00\x00\x00\x00\x00\x00\x00\x00" ..
                          "\x00\x00\x00\x00\x00\x00\x04\x00" ..
                          "\x00\x00\x00\x00\x00\x00\x00\x00"
  -- The last two bytes 0400 define a message handler (maybe ^^)
  local enc_pkt = wnti_encrypt(pkt_queryhostinfo) .. "\x04\x00"

  stdnse.debug("Constructed QueryHostInfo packet: %s", tohex(enc_pkt))
  return enc_pkt
end


--------------------------------------------------------------------------------
-- Return a WINNTI HELO packet
--------------------------------------------------------------------------------
function wnti_get_helo_pkt()
  local l1 = math.random(1, 0xffffffff);
  local l2 = math.random(1, 0xffffffff);
  local l3 = math.random(1, 0xffffffff);

  local t3 = ( ( (l3 & 0xffff) << 16) | ((l3 & 0xffff0000) >> 16) )
  local l0 = t3 ~ l2

  local pkt_helo = string.pack("<I4I4I4I4", l0, l1, l2, l3)

  stdnse.debug("Constructed HELO packet: %s", tohex(pkt_helo))

  return pkt_helo
end


--------------------------------------------------------------------------------
-- Extract host information from host-info datagram
--------------------------------------------------------------------------------
function wnti_fill_hostinfo(hostinfo_tbl, data)
  table.insert(hostinfo_tbl, string.format("Hostname:  %s", rtrimzero(data:sub(0x6A, 0x6A +0x3F))))
  table.insert(hostinfo_tbl, string.format("Winnti-ID: %s", rtrimzero(data:sub(0xAA, 0xAA +0x3F))))
  table.insert(hostinfo_tbl, string.format("Hostname2  %s", rtrimzero(data:sub(0x12A,0x12A+0x3F))))
  table.insert(hostinfo_tbl, string.format("Domain     %s", rtrimzero(data:sub(0x16A,0x16A+0x3E))))
end


--------------------------------------------------------------------------------
-- Wait for response and decrypt data
--
-- returns attempt_to_receive_successful(bool), data(string) if successful or error_message(string) if not successful
--------------------------------------------------------------------------------
function wnti_receive(socket, maxbytes)
  -- Wait for answer
  stdnse.debug("Waiting for data")
  local status, response

  if maxbytes then
    status, response = socket:receive(maxbytes)
  else
    status, response = socket:receive()
  end

  -- Check answer
  if (status == false) then
    return false, "Receiving data failed"
  end

  if (response == nil) then
    return false, "No response"
  end

  if response == "EOF" then -- Port may be closed
    return false, "No answer"
  end

  if response == "TIMEOUT" then -- No data received
    return true, ""
  end

  if string.len(response) < 16 then
    stdnse.debug(string.format("Answer too short for winnti packet: %s", tohex(response)))
    return true, ""
  end

  -- Decrypt answer
  local decrypted_answer = (wnti_decrypt(response))

  stdnse.debug("Decrypted answer: %s", tohex(decrypted_answer))

  return true, decrypted_answer
end


--------------------------------------------------------------------------------
-- Decrypt winnti message
--------------------------------------------------------------------------------
function wnti_decrypt(msg)
  -- A Winnti message is always at least 16 bytes long
  if msg:len() < 16 then
    return nil
  end

  -- Unpack the first four u32 values
  l0, l1, l2, l3 = string.unpack("<I4I4I4I4", msg:sub(1,16))
  -- Calculate the message key
  msgkey = l2 ~ WINNTI_STATIC_KEY

  -- Decrypt the entire message
  return _wnti_xor_message(msg, msgkey)
end


--------------------------------------------------------------------------------
-- Encrypt winnti message
--------------------------------------------------------------------------------
function wnti_encrypt(msg)
  -- Generate a random message key
  msgkey = math.random(0xffffffff)

  -- Encrypt the entire message
  return _wnti_xor_message(msg, msgkey)
end


--------------------------------------------------------------------------------
-- XOR a key on a message and return the result
--------------------------------------------------------------------------------
function _wnti_xor_message(msg, msgkey)
  -- Convert the key to string
  skey = string.pack("<I4", msgkey)
  -- Cycle over the message (hell, lua why are you starting to count at 1!?!!)
  local res=""
  for pos=1, #msg do
    res = res .. string.char(msg:byte(pos) ~ skey:byte(((pos-1) % 4) + 1))
  end
  return res
end

