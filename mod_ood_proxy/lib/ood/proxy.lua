--[[
  set_reverse_proxy

  Modify a given request to utilize mod_proxy for reverse proxying.
--]]
function set_reverse_proxy(r, conn)
function set_reverse_proxy(r, conn, node_proxy)
  -- find protocol used by parsing the request headers
  local protocol = (r.headers_in['Upgrade'] and "ws://" or "http://")


  -- define reverse proxy destination using connection object
  if conn.socket or node_proxy then
    r.handler = "proxy:unix:" .. conn.socket .. "|" .. protocol .. "localhost"
  else
    r.handler = "proxy:" .. protocol .. conn.server
  end

  r.filename = conn.uri

  -- include useful information for the backend server

  -- provide the protocol used
  r.headers_in['X-Forwarded-Proto'] = r.is_https and "https" or "http"

  -- provide the authenticated user name
  r.headers_in['X-Forwarded-User'] = conn.user or ""

  -- **required** by PUN when initializing app
  r.headers_in['X-Forwarded-Escaped-Uri'] = r:escape(conn.uri)

  -- pass requested target and URI when performing node proxy
  if node_proxy then
    r:info("Setting node proxy settings for PUN")
    r.headers_in['X-OOD-Upstream'] = conn.server
    r.headers_in['X-OOD-Req-Uri'] = conn.uri
    r.filename = "/proxy"
    if r.headers_in['Upgrade'] then
      r.headers_in['Upgrade'] = "websocket"
    end
  end

  -- set timestamp of reverse proxy initialization as CGI variable for later hooks (i.e., analytics)
  r.subprocess_env['OOD_TIME_BEGIN_PROXY'] = r:clock()
end

return {
  set_reverse_proxy = set_reverse_proxy
}
