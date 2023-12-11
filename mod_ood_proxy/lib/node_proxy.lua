local user_map    = require 'ood.user_map'
local proxy       = require 'ood.proxy'
local http        = require 'ood.http'
local user_route = require 'ood.user_route'

--[[
  node_proxy_handler

  Maps an authenticated user to a system user. Then proxies user's traffic to a
  backend node with the host and port specified in the request URI or environment.
--]]
function node_proxy_handler(r)
  -- read in OOD specific settings defined in Apache config
  local user_map_match  = r.subprocess_env['OOD_USER_MAP_MATCH']
  local user_map_cmd    = r.subprocess_env['OOD_USER_MAP_CMD']
  local user_env        = r.subprocess_env['OOD_USER_ENV']
  local map_fail_uri    = r.subprocess_env['OOD_MAP_FAIL_URI']

  -- read in OOD dynamic proxy settings defined in Apache config
  local dbtype          = r.subprocess_env['OOD_DNODE_DBTYPE']
  local dbpath          = r.subprocess_env['OOD_DNODE_DBPATH']
  local dynamic_proxy   = r.subprocess_env['OOD_PROXY_DYNAMIC']

  -- read in <LocationMatch> regular expression captures
  local host = r.subprocess_env['MATCH_HOST']
  local port = r.subprocess_env['MATCH_PORT']
  local uri  = r.subprocess_env['MATCH_URI']

  -- get the system-level user name
  local user = user_map.map(r, user_map_match, user_map_cmd, user_env and r.subprocess_env[user_env] or r.user)
  if not user then
    if map_fail_uri then
      return http.http302(r, map_fail_uri .. "?redir=" .. r:escape(r.unparsed_uri))
    else
      return http.http404(r, "failed to map user (" .. r.user .. ")")
    end
  end

  -- generate connection object used in setting the reverse proxy
  
  local conn = {}
  conn.user = user

  -- Check if we are proxying based on route database
  if dynamic_proxy then
    
    conn.server = user_route.map(r, dbtype, dbpath, user)

    -- No route found, decline and let the next handler work
    if conn.server == "" then
      r:custom_response(404, "No tunnel found for user")
      return apache2.DECLINED
    end
  else
    -- Proxy based on information extracted from URI
    conn.server = host .. ":" .. port
  end
  
  conn.uri = uri and (r.args and (uri .. "?" .. r.args) or uri) or r.unparsed_uri

  -- last ditch effort to ensure that the uri is at least something
  -- because the request-line of an HTTP request _has_ to have something for a URL
  if conn.uri == '' then
    conn.uri = '/'
  end

  -- setup request for reverse proxy
  proxy.set_reverse_proxy(r, conn)

  -- handle if backend server is down
  r:custom_response(503, "Failed to connect to " .. conn.server)

  -- let the proxy handler do this instead
  return apache2.DECLINED
end
