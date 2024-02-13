local loaded, dnode = pcall(require, 'dnode')

if loaded then
    -- Native implementation, if available
    return {
        map   = dnode.map,
        setup = dnode.setup
    }
else
    -- Lua fallback with local sqlite3
    local user_route = require "ood.user_route"
    return {
        map   = user_route.map,
        setup = user_route.setup
    }
end
