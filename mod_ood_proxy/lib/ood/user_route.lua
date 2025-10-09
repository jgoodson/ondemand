--[[
  find_routes

  Get all current endpoints for specified user
--]]

function find_routes(r, database, user)
  
  local statement, err = database:prepare(r, "SELECT in_port, node, out_port, access_time FROM `routes` WHERE `user` IS %s")
  if not err then
    local result, errmsg = statement:select(user)
    if not errmsg then
      
      local routes = result(0)
      
      return routes
    end
  end
  return nil
end


--[[
  select_port

  Assign a port for a user, deleting the oldest if necessary
--]]

function select_port(r, database, user, min_port, max_port, node, out_port)

  -- Collect user routes
  local routes = find_routes(r, database, user)
  local used_ports = {}
  
  local oldest_port = {
    port = 0,
    age = r:clock()
  }

  -- Collect relevant information from user routes
  if routes then
    for i, tun in pairs(routes) do
      used_ports[string.format("%u", tun[1])] = {
        node = tun[2],
        out_port = tun[3],
        age = tonumber(tun[4]),
      }
    end
  else
    -- Assign first available port if no existing routes
    return min_port
  end

  -- Select an incoming port
  local empty_port
  for port=min_port,(max_port) do
    local sport = string.format("%u", port)
    if not used_ports[sport] then
      empty_port = sport
    end

    -- Check if user already has a routes to this node:port and return that
    if used_ports[sport] and (used_ports[sport].node == node ) and (used_ports[sport].out_port == out_port) then
      return sport
    end
    -- Otherwise, maintain a record of the currently-oldest routes to replace
    if used_ports[sport] and (used_ports[sport].age < oldest_port.age) then
      oldest_port.port = sport
      oldest_port.age = used_ports[sport].age
    end
  end

  -- Check for available ports
  if empty_port then
    return empty_port
  end

  -- No available ports we return the oldest to overwrite
  if not oldest_port.port then
    r:err("Error finding port for dynamic proxy")
  else
    return oldest_port.port
  end
end

--[[
  setup

  Create a port mapping entry for a user to a compute node
--]]

function dump(o)
  if type(o) == 'table' then
     local s = '{ '
     for k,v in pairs(o) do
        if type(k) ~= 'number' then k = '"'..k..'"' end
        s = s .. '['..k..'] = ' .. dump(v) .. ','
     end
     return s .. '} '
  else
     return tostring(o)
  end
end

function setup(r, user, node, out_port, min_port, max_port, secure)
  local dbpath = r.subprocess_env['OOD_DNODE_DBPATH']

  -- Open database for user-specific routes endpoints
  local database, err = r:dbacquire("sqlite3", dbpath)
  if err then
    r:err(err)
    return
  end

  -- Check inter-VM cache for whether the DB routes table exists
  local RDI = r:ivm_get("ROUTE_DATABASE_INITIALIZED")
  if not RDI then
    local table, err2 = database:select(r, "SELECT name FROM sqlite_master WHERE type='table' AND name='routes'")
    local res = table(0)
    if #res == 0 then
      r:debug("Route table not found, creating")
      local res, err = database:query(r, [[
        CREATE TABLE routes 
        (
          user TEXT,
          in_port INTEGER,
          node TEXT,
          out_port INTEGER,
          access_time REAL,
          secure INTEGER,
          UNIQUE(user, in_port) ON CONFLICT REPLACE,
          UNIQUE(user, node, out_port) ON CONFLICT REPLACE
        )
        ]])
    end
    --Record that route table is initialized to avoid checks on other setups
    r:ivm_set("ROUTE_DATABASE_INITIALIZED", "yes")
  end
  
  local insert, err = database:prepare(r, "INSERT INTO routes VALUES (%s, %u, %s, %u, %f, %u)")
  
  if not err then 
    -- Select incoming port for this routes, selected oldest existing if all are taken
    local in_port = select_port(r, database, user, min_port, max_port, node, out_port)
    

    -- If (user, in_port) exists, DB constraint will overwrite it, updating access time
    local _, errmsg = insert:query(user, in_port, node, out_port, r:clock(), secure)

    -- Close the database so we don't accumulate connections
    database:close()

    if not errmsg then
      return in_port
    else
      r:err(errmsg)
      return 0
    end
  end
end


--[[
  map

  Get destination endpoint for user's dynamic routes
--]]

function map(r, user, in_port)
  local dbpath = r.subprocess_env['OOD_DNODE_DBPATH']
  local now = r:clock()

  local route_dest = ""
  -- Open database for user-specific routes endpoints
  
  local database, err = r:dbacquire("sqlite3", dbpath)
  if err then
    r:err(err)
  end
  

  -- Collect user routes
  local routes = find_routes(r, database, user)

  -- Find the route matching this request's incoming port
  if routes then
    for i, row in pairs(routes) do
      if row[1] == tostring(in_port) then

        -- Construct host:port combo
        route_dest = row[2] .. ":" .. row[3]
        secure = row[4]
      end
    end
  end

  -- Close the database so we don't accumulate connections
  database:close()

  local time_route_map = (r:clock() - now)/1000.0
  r:debug("Mapped '" .. user .. " on " .. r.port .. "' => '" .. route_dest .. "' [" .. time_route_map .. " ms]")

  return route_dest, secure
end

return {
  map = map,
  setup = setup
}