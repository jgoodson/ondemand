local user_map    = require 'ood.user_map'
local proxy       = require 'ood.proxy'
local http        = require 'ood.http'
local dnode       = require 'ood.dnode'

--[[
  dyn_setup_handler

  Maps an authenticated user to a system user. Then proxies user's traffic to a
  backend node with the host and port specified in the request URI or environment.
--]]
function dyn_setup_handler(r)
  -- read in OOD specific settings defined in Apache config
  local user_map_match  = r.subprocess_env['OOD_USER_MAP_MATCH']
  local user_map_cmd    = r.subprocess_env['OOD_USER_MAP_CMD']
  local user_env        = r.subprocess_env['OOD_USER_ENV']

  -- read in OOD dynamic proxy settings defined in Apache config
  local proxy_host      = r.subprocess_env['OOD_DNODE_HOSTNAME']
  local dnode_port_lo   = r.subprocess_env['OOD_DNODE_PORT_START']
  local dnode_port_hi   = r.subprocess_env['OOD_DNODE_PORT_END']

  -- read in <LocationMatch> regular expression captures
  local host = r.subprocess_env['MATCH_HOST']
  local port = r.subprocess_env['MATCH_PORT']

  -- get the system-level user name
  local user = user_map.map(r, user_map_match, user_map_cmd, user_env and r.subprocess_env[user_env] or r.user)
  if not user then
    return http.http404(r, "failed to map user (" .. r.user .. ")")
  end

  -- Set up the dynamic proxy backend
  local proxy_port = dnode.setup(r, user, host, port, dnode_port_lo, dnode_port_hi)
  
  if not proxy_port then
    -- Something went wrong, return error
    r:write("Failed to setup route")
    r.status = 503
    return apache2.DONE
  else 
    -- Return success with proxy host information
    r.status = 200
    
    r:write(proxy_host .. ":" .. proxy_port)
    
    return apache2.DONE
  end
end
