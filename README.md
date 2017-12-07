# Name

lua-resty-sphinx - lua Sphinx/Coreseek client driver implement for the ngx_lua based on the cosocket API
# Status

This library is considered production ready.
# Description

This Lua library is a Sphinx/Coreseek client driver implement for the ngx_lua nginx module:
# Synopsis

```
local sphinxc = require "resty.sphinx"

local SPH_MATCH_ANY = sphinxc.SPH_MATCH_ANY
local sphinx = sphinxc.new()
sphinx:SetServer("host", port)
sphinx:SetFilter('attr', {val})
sphinx:SetMatchMode(SPH_MATCH_ANY)
sphinx:SetLimits(1,4)
sphinx:AddQuery("query", "index")
local result = sphinx:RunQueries()
local result = sphinx:Query("query", "index")
```
# Requires

1. Lua Bit Operations Module: [http://bitop.luajit.org/](http://bitop.luajit.org/ "http://bitop.luajit.org/")
2. struct: [http://www.inf.puc-rio.br/~roberto/struct/](http://www.inf.puc-rio.br/~roberto/struct/ "http://www.inf.puc-rio.br/~roberto/struct/")
# TODO

# See Also

