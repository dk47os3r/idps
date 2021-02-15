--[[    lua script : ransomware_urls.lua
	purpose    : to check the url is matched in Ransomware file or not
	rule       : reject tcp any any -> any any (msg:"Ransomware URL"; luajit:ransomware_urls.lua; priority:1; sid: 100000000000; rev:1;)

	author     : samiux (https://samiux.github.io)
	project    : Croissants
	license    : GPLv3
	date       : FEB 15, 2021

	Remarks    : (1) https protocol will not be processed.
		     (2) google safe-browsing blacklisted is also not processed
		         as it is blocked by firefox before suricata processing.
]]

-- open files
if url_file_ransomware == nil then
	url_file_ransomware = io.open("/var/lib/suricata/rules/ransomwaretracker.url", "r")
end
if access_file_ransomware == nil then
	access_file_ransomware = io.open("/var/log/suricata/ransomware_urls.log", "a")
end

-- this gets called during rule parsing
function init(args)
	local needs = {}
 	needs["http.request_headers"] = tostring(true)
	return needs
end

-- this is a matcher function
function match(args)
	-- initalization
	-- verbose = 0 (false, default), 1 (true)
	local verbose = 0

        -- get host name
        http_host_hdr = HttpGetRequestHost()
        http_uri = HttpGetRequestUriRaw()

        if http_host_hdr == nil then
                http_host_hdr = ""
        end
        if http_uri == nil then
                http_uri = ""
        end

        -- combine together
        http_host = http_host_hdr .. http_uri

	if http_host == nil then
		http_host = ""
	end

	-- open files
  	-- local url_file = io.open("/var/lib/suricata/rules/ransomwaretracker.url", "r")
	-- local access_file = io.open("/var/log/suricata/ransomware_urls.log", "a")

	-- compare host name
	for line in url_file_ransomware:lines() do
		if #http_host > 0 then
			if string.find(line, http_host) then
				access_file_ransomware:write(os.date("[%x - %X] [**]" .. " [Match] " .. http_host .. " <@> Source : " .. line .. " \n"))
				url_file_ransomware:flush()
				access_file_ransomware:flush()
				-- url_file:close()
				-- access_file:close()
				return 1
			else
				if verbose == 1 then
					access_file_ransomware:write(os.date("[%x - %X] [--] " .. http_host .. " <@> Source : " .. line .. " \n"))
				end
			end
		end
	end
	url_file_ransomware:flush()
	access_file_ransomware:flush()
	-- url_file:close()
	-- access_file:close()
	return 0
end	

function deinit(args)
        url_file_ransomware:flush()
        access_file_ransomware:flush()
        url_file_ransomware:close()
        access_file_ransomware:close()
end

