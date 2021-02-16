--[[    lua script : malicious_urls.lua
	purpose    : to check the url is matched in malicious file or not
	rule       : reject tcp any any -> any any (msg:"Malicious URL"; luajit:malicious_urls.lua; priority:1; sid: 100000000000; rev:1;)

	author     : samiux (https://samiux.github.io)
	project    : Croissants
	license    : GPLv3
	date       : FEB 15, 2021

	Remarks    : (1) https protocol will not be processed.
		     (2) google safe-browsing blacklisted is also not processed
		         as it is blocked by firefox before suricata processing.
]]

-- open files
if url_file_malicious == nil then
	url_file_malicious = io.open("/var/lib/suricata/rules/malicious.url", "r")
end
if access_file_malicious == nil then
	access_file_malicious = io.open("/var/log/suricata/malicious_urls.log", "a")
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
        local http_host_hdr = HttpGetRequestHost()
        local http_uri = HttpGetRequestUriRaw()

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

	-- compare host name
	for line in url_file_malicious:lines() do
		if #http_host > 0 then
			if string.find(line, http_host) then
				access_file_malicious:write(os.date("[%x - %X] [**]" .. " [Match] " .. http_host .. " <@> Source : " .. line .. " \n"))
				url_file_malicious:flush()
				access_file_malicious:flush()
				return 1
			else
				if verbose == 1 then
					access_file_malicious:write(os.date("[%x - %X] [--] " .. http_host .. " <@> Source : " .. line .. " \n"))
				end
			end
		end
	end
	url_file_malicious:flush()
	access_file_malicious:flush()
	return 0
end	

function deinit(args)
        url_file_malicious:flush()
        access_file_malicious:flush()
        url_file_malicious:close()
        access_file_malicious:close()
end
