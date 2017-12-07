-- Copyright (C) 2015 Yunfeng Meng

-- usage:
-- local sphinxc = require "resty.sphinx"
-- local SPH_MATCH_ANY = sphinxc.SPH_MATCH_ANY
-- local sphinx = sphinxc.new()
-- sphinx:SetServer("host", port)
-- sphinx:SetFilter('attr', {val})
-- sphinx:SetMatchMode(SPH_MATCH_ANY)
-- sphinx:SetLimits(1,4)
-- sphinx:AddQuery("query", "index")
-- local result = sphinx:RunQueries()
-- local result = sphinx:Query("query", "index")

local struct       = require "struct"
local spack        = struct.pack
local sunpack      = struct.unpack
local bit          = require "bit"
local bor          = bit.bor
local tcp          = ngx.socket.tcp
local ngx_log      = ngx.log
local ngx_ERR      = ngx.ERR
local str_sub      = string.sub
local str_gsub     = string.gsub
local str_format   = string.format
local str_byte     = string.byte
local setmetatable = setmetatable
local assert       = assert
local type         = type
local table_insert = table.insert
local table_concat = table.concat
local ipairs       = ipairs
local pairs        = pairs
local tostring     = tostring


-- Sphinx常量
local _CONSTS = {
    -- known searchd commands
    SEARCHD_COMMAND_SEARCH     = 0,
    SEARCHD_COMMAND_EXCERPT    = 1,
    SEARCHD_COMMAND_UPDATE     = 2,
    SEARCHD_COMMAND_KEYWORDS   = 3,
    SEARCHD_COMMAND_PERSIST    = 4,
    SEARCHD_COMMAND_STATUS     = 5,
    SEARCHD_COMMAND_FLUSHATTRS = 7,
    
    -- current client-side command implementation versions
    VER_COMMAND_SEARCH     = 0x119,
    VER_COMMAND_EXCERPT    = 0x103,
    VER_COMMAND_UPDATE     = 0x102,
    VER_COMMAND_KEYWORDS   = 0x100,
    VER_COMMAND_STATUS     = 0x100,
    VER_COMMAND_QUERY      = 0x100,
    VER_COMMAND_FLUSHATTRS = 0x100,
    
    -- known searchd status codes
    SEARCHD_OK      = 0,
    SEARCHD_ERROR   = 1,
    SEARCHD_RETRY   = 2,
    SEARCHD_WARNING = 3,
    
    -- known match modes
    SPH_MATCH_ALL       = 0,
    SPH_MATCH_ANY       = 1,
    SPH_MATCH_PHRASE    = 2,
    SPH_MATCH_BOOLEAN   = 3,
    SPH_MATCH_EXTENDED  = 4,
    SPH_MATCH_FULLSCAN  = 5,
    SPH_MATCH_EXTENDED2 = 6, -- extended engine V2 (TEMPORARY, WILL BE REMOVED)

    -- known ranking modes (ext2 only)
    SPH_RANK_PROXIMITY_BM25 = 0, -- < default mode, phrase proximity major factor and BM25 minor one
    SPH_RANK_BM25           = 1, -- < statistical mode, BM25 ranking only (faster but worse quality)
    SPH_RANK_NONE           = 2, -- < no ranking, all matches get a weight of 1
    SPH_RANK_WORDCOUNT      = 3, -- < simple word-count weighting, rank is a weighted sum of per-field keyword occurence counts
    SPH_RANK_PROXIMITY      = 4,
    SPH_RANK_MATCHANY       = 5,
    SPH_RANK_FIELDMASK      = 6,
    SPH_RANK_SPH04          = 7,
    SPH_RANK_EXPR           = 8,
    SPH_RANK_TOTAL          = 9,

    -- known sort modes
    SPH_SORT_RELEVANCE     = 0,
    SPH_SORT_ATTR_DESC     = 1,
    SPH_SORT_ATTR_ASC      = 2,
    SPH_SORT_TIME_SEGMENTS = 3,
    SPH_SORT_EXTENDED      = 4,
    SPH_SORT_EXPR          = 5,

    -- known filter types
    SPH_FILTER_VALUES     = 0,
    SPH_FILTER_RANGE      = 1,
    SPH_FILTER_FLOATRANGE = 2,

    -- known attribute types
    SPH_ATTR_INTEGER   = 1,
    SPH_ATTR_TIMESTAMP = 2,
    SPH_ATTR_ORDINAL   = 3,
    SPH_ATTR_BOOL      = 4,
    SPH_ATTR_FLOAT     = 5,
    SPH_ATTR_BIGINT    = 6,
    SPH_ATTR_STRING    = 7,
    SPH_ATTR_MULTI     = 0x40000001,
    SPH_ATTR_MULTI64   = 0x40000002,


    -- known grouping functions
    SPH_GROUPBY_DAY      = 0,
    SPH_GROUPBY_WEEK     = 1,
    SPH_GROUPBY_MONTH    = 2,
    SPH_GROUPBY_YEAR     = 3,
    SPH_GROUPBY_ATTR     = 4,
    SPH_GROUPBY_ATTRPAIR = 5,
}

-- unsigned
local function uint16_pack(i)
    return spack(">H", i)
end


local function unint16_upack(s, p)
   p = p or 1
   local v, pos = sunpack(">H", str_sub(s, p, p + 1))
   return v
end


local function uint32_pack(i)
   return spack(">I", i)
end


local function uint32_unpack(s, p)
   p = p or 1
   local v, pos = sunpack(">I", str_sub(s, p, p + 3))
   return v
end


local function uint64_pack(i)
    return spack(">L", i)
end


local function uint64_unpack(s, p)
   p = p or 1
   local v, pos = sunpack(">L", str_sub(s, p, p + 7))
   return v
end


local function int64_pack(i)
    return spack(">l", i)
end


local function int64_unpack(s, p)
    p = p or 1
    local v, pos = sunpack(">l", str_sub(s, p, p + 7))
    return v
end


local function float2uint32_pack(f)
    return uint32_pack(sunpack("<I", spack("f", f)))
end


local function uint32_to_float(i)
    local v, pos = sunpack(">f", spack(">I", i))
    return v
end


-- binary string to hex
local function hex(s)
    s = str_gsub(s,"(.)", function (x) return str_format("%02x", str_byte(x)) end)
    return s
end


-- build request helper
local function uint32_req(req_tbl, i)
    table_insert(req_tbl, uint32_pack(i))
end
   

local function string_req(req_tbl, s)
    uint32_req(req_tbl, #s)
    table_insert(req_tbl, s)
end


local function uint64_req(req_tbl, i)
    table_insert(req_tbl, uint64_pack(i))
end
   

local function int64_req(req_tbl, i)
    table_insert(req_tbl, int64_pack(i))
end
   

local function float_req(req_tbl, f)
    table_insert(req_tbl, float2uint32_pack(f))
end


-- parse response helper
local function uint32_resp(response, p)
    local v = uint32_unpack(response, p)
    p = p + 4
    return v, p
end


local function uint64_resp(response, p)
    local v = uint64_unpack(response, p)
    p = p + 8
    return v, p
end
   

local function int64_resp(response, p)
    local v = int64_unpack(response, p)
    p = p + 8
    return v, p
end


local _M = {}
for k, v in pairs(_CONSTS) do
    _M[k] = v
end


local mt = { __index = _M } -- metatable


function _M.new()
    
    local sock, err = tcp()
    if not sock then
        return nil, err
    end
    
    local obj = {
         host           = "localhost",             -- searchd host (default is "localhost")
         port           = 9312,                    -- searchd port (default is 9312)
         sock           = sock,
         
         offset         = 0,                       -- how many records to seek from result-set start (default is 0)
         limit          = 20,                      -- how many records to return from result-set starting at offset (default is 20)
         mode           = _CONSTS.SPH_MATCH_ALL,   -- query matching mode (default is SPH_MATCH_ALL)
         weights        = {},                      -- per-field weights (default is 1 for all fields)
         sort           = _CONSTS.SPH_SORT_RELEVANCE, -- match sorting mode (default is SPH_SORT_RELEVANCE)
         sortby         = "",                      -- attribute to sort by (defualt is "")
         min_id         = 0,                       -- min ID to match (default is 0, which means no limit)
         max_id         = 0,                       -- max ID to match (default is 0, which means no limit)
         filters        = {},                      -- search filters
         groupby        = "",                      -- group-by attribute name
         groupfunc      = _CONSTS.SPH_GROUPBY_DAY, -- group-by function (to pre-process group-by attribute value with)
         groupsort      = "@group desc",           -- group-by sorting clause (to sort groups in result set with)
         groupdistinct  = "",                      -- group-by count-distinct attribute
         maxmatches     = 1000,                    -- max matches to retrieve
         cutoff         = 0,                       -- cutoff to stop searching at (default is 0)
         retrycount     = 0,                       -- distributed retries count
         retrydelay     = 0,                       -- distributed retries delay
         anchor         = {},                      -- geographical anchor point
         indexweights   = {},                      -- per-index weights
         ranker         = _CONSTS.SPH_RANK_PROXIMITY_BM25, -- ranking mode (default is SPH_RANK_PROXIMITY_BM25)
         rankexpr       = "",                      -- ranking mode expression (for SPH_RANK_EXPR)
         maxquerytime   = 0,                       -- max query time, milliseconds (default is 0, do not limit)
         fieldweights   = {},                      -- per-field-name weights
         overrides      = {},                      -- per-query attribute values overrides
         select         = "*",                     -- select-list (attributes or expressions, with optional aliases)
        
         error          = "",                      -- last error message
         warning        = "",                      -- last warning message
         connerror      = false,                   -- connection error vs remote error flag
         
         reqs           = {},                      -- requests array for multi-query
         mbenc          = "",                      -- stored mbstring encoding
         arrayresult    = false,                   -- whether $result["matches"] should be a hash or an array
         timeout        = 0,                       -- connect timeout
    }

    return setmetatable(obj, mt)
end


-- set searchd host name (string) and port (integer)
function _M.SetServer(self, host, port)
   host = host or self.host
   port = port or self.port
   
   assert(type(host) == "string", "Sphinx:SetServer require a string for host")
   assert(type(port) == "number", "Sphinx:SetServer require a number for port")
   
   self.host = host
   self.port = port
end


-- Sphinx not supported now
function _M.set_keepalive(self, ...)
    local sock = self.sock
    if not sock then
        return nil, "not initialized"
    end
    
    return sock:setkeepalive(...)
end


function _M.set_timeout(self, timeout)
    local sock = self.sock
    if not sock then
        return nil, "not initialized"
    end

    sock:settimeout(timeout)
    return 1
end


-- connect to searchd server
local function _Connect(self)
    local sock = self.sock
    if not sock then
        return nil, "not initialized"
    end

    self.connerror = false
    local ok, err = sock:connect(self.host, self.port)
    if not ok then
       self.error = "Sphinx: cannot connect to " ..self.host .. ":" .. self.port .. "," .. err
       self.connerror = true
       return nil, err
    end
   
    -- send my version
    -- this is a subtle part. we must do it before (!) reading back from searchd.
    -- because otherwise under some conditions (reported on FreeBSD for instance)
    -- TCP stack could throttle write-write-read pattern because of Nagle.
   local bytes, err = sock:send(uint32_pack(1))
   if not bytes then
        self.error = "Sphinx: failed to send client protocol version"
        return nil, err
   end
   
   -- check version
   local line, err, partial = sock:receive(4)
   if not line then
       if err == "timeout" then
           sock:close()
       end
       self.error = "Sphinx: failed to read a line: " .. err
       return nil, err
   end
   
   local v = uint32_unpack(line)
   if v < 1 then
       sock:close()
       self.error = 'expected searchd protocol version 1+, got version ' .. v
       return nil
   end
   
   return sock
end


-- add query to multi-query batch
-- returns index into results array from RunQueries() call
local function _AddQuery(self, query, index, comment)
    index   = index or "*"
    comment = comment or ""
    assert(type(query) == "string")
    
    -- build request
    local req = {}
    
    uint32_req(req, self.offset)
    uint32_req(req, self.limit)
    uint32_req(req, self.mode)
    uint32_req(req, self.ranker)
    
    if self.ranker == _CONSTS.SPH_RANK_EXPR then
        string_req(req, self.rankexpr)
    end
    uint32_req(req, self.sort) -- (deprecated) sort mode
    string_req(req, self.sortby)
    string_req(req, query) -- query itself
       
    uint32_req(req, #self.weights) -- weights
    for _, v in ipairs(self.weights) do
        uint32_req(req, v)
    end
    
    string_req(req, index) -- indexes
    uint32_req(req, 1) -- id64 range marker
    uint64_req(req, self.min_id)
    uint64_req(req, self.max_id)
    
    -- filters
    uint32_req(req, #self.filters)
    for _, f in ipairs(self.filters) do
        string_req(req, f.attr)
        uint32_req(req, f.type)
        if f.type == _CONSTS.SPH_FILTER_VALUES then
            uint32_req(req, #f.values)
            for _, v in ipairs(f.values) do
                int64_req(req, v)
            end
        elseif f.type == _CONSTS.SPH_FILTER_RANGE then
            int64_req(req, f.min)
            int64_req(req, f.max)
        elseif f.type == _CONSTS.SPH_FILTER_FLOATRANGE then
            float_req(req, f.min)
            float_req(req, f.max)
        end
        if f.exclude then
            uint32_req(req, 1)
        else
            uint32_req(req, 0)
        end
    end
    
    -- group-by clause, max-matches count, group-sort clause, cutoff count
    uint32_req(req, self.groupfunc)
    string_req(req, self.groupby)
    uint32_req(req, self.maxmatches)
    string_req(req, self.groupsort)
    uint32_req(req, self.cutoff)
    uint32_req(req, self.retrycount)
    uint32_req(req, self.retrydelay)
    string_req(req, self.groupdistinct)
    
    if not self.anchor.attrlat and not self.anchor.attrlong then
        uint32_req(req, 0)
    else
        local anc = self.anchor
        uint32_req(req, 1)
        string_req(req, anc.attrlat)
        string_req(req, anc.attrlong)
        float_req(req, anc.lat)
        float_req(req, anc.long)
    end
    
    -- per-index weights
    uint32_req(req, #self.indexweights)
    for idx, w in pairs(self.indexweights) do
        string_req(req, idx)
        uint32_req(req, w)
    end
    
    -- max query time
    uint32_req(req, self.maxquerytime)
    
    -- per-field weights
    uint32_req(req, #self.fieldweights)
    for field, w in pairs(self.fieldweights) do
        string_req(req, field)
        uint32_req(req, w)
    end
    
    -- comment
    string_req(req, comment)
    
    
    -- attribute overrides
    uint32_req(req, #self.overrides)
    for key, entry in pairs(self.overrides) do
        string_req(req, entry.attr)
        uint32_req(req, entry.type)
        uint32_req(req, #entry.values)
        for id, val in pairs(entry.values) do
            assert(type(id) == "number")
            assert(type(val) == "number")
          
            uint64_req(req, id)
            if entry.type == _CONSTS.SPH_ATTR_FLOAT then
                float_req(req, val)
            elseif entry.type == _CONSTS.SPH_ATTR_BIGINT then
                int64_req(req, val)
            else
                uint32_req(req, val)
            end
        end
    end
   
    -- select-list
    string_req(req, self.select)
    
    
    req = table_concat(req) -- join together as a string
   
    -- store request to requests array
    table_insert(self.reqs, req)
    return #self.reqs
end
_M.AddQuery = _AddQuery


-- get and check response packet from searchd server
local function _GetReponse(self, sock, client_ver)
    
    local response = ""
    local len = 0
    local status, ver
     
    local header = sock:receive(8)
    if #header == 8 then
        status = unint16_upack(header)
        ver    = unint16_upack(header, 3)
        len    = uint32_unpack(header, 5)
    end
    
    if len > 0 then 
        response = sock:receive(len)
    end
   
    -- check response
    local read = #response
    if response == "" or read ~= len then
        if len == 0 then
            self.error = str_format("failed to read searchd response" .. " (status=%s, ver=%s, len=%s, read=%s)", status, ver, len, read)
        else
            self.error = "received zero-sized searchd response"
        end
        return false
    end
    
    -- check status
    if status == _CONSTS.SEARCHD_WARNING then
        local wlen = 4 + uint32_unpack(str_sub(response, 1, 4))
        self.warning = str_sub(response, 5, wlen)
        return str_sub(response, wlen + 1)
    end
    
    if status == _CONSTS.SEARCHD_ERROR then
        self.error = "searchd error: " .. str_sub(response, 5)
        return false
    end
    
    if status == _CONSTS.SEARCHD_RETRY then
        self.error = "temporary searchd error: " .. str_sub(response, 5)
        return false
    end
    
    if status ~= _CONSTS.SEARCHD_OK then
        self.error = "unknown status code " .. status
        return false
    end
    
    if ver < client_ver then
        self.warning = str_format("searchd command v.%d.%d older than" .." client\'s v.%d.%d, some options might not work", ver/256, ver%256, client_ver/256, client_ver%256)
    end
    
    return response
end


-- parse and return search query (or queries) response
local function _ParseSearchResponse(response, nreqs)

    local p   = 1 -- current position, lua starting with 1
    local max = #response + 1
   
    local results = {}
    
    local ires = 1
    while ires < (nreqs + 1) and p < max do
        table_insert(results, {})
        local result = results[ires]
       
        result.status  = 0
        result.error   = ""
        result.warning = ""
        result.matches = {}
        result.words   = {}
        
        -- extract status
        local status
        status, p = uint32_resp(response, p)
        result.status = status
        
        -- search not ok message
        local message = ""
        if status ~= _CONSTS.SEARCHD_OK then
            local len
            len, p = uint32_resp(response, p)
            message = str_sub(response, p, p + len)
            p = p + len
        end
        
        -- not fatal error
        if (status == _CONSTS.SEARCHD_OK) or (status == _CONSTS.SEARCHD_WARNING) then
           
            if status == _CONSTS.SEARCHD_WARNING then
                result.warning = message
            end
            
            -- read schema
            local fields, attrs = {}, {}
           
            -- fields
            local nfields
            nfields, p = uint32_resp(response, p)
            while nfields > 0 and p < max  do
                local len
                len, p = uint32_resp(response, p)
                table_insert(fields, str_sub(response, p, p + len - 1)) -- \u0000
                p = p + len
                
                nfields = nfields - 1
            end
            result.fields = fields
            
            -- attrs
            local nattrs
            nattrs, p  = uint32_resp(response, p)
            local iattrs = {}
            while nattrs > 0 and p < max  do
                
                local len
                len, p = uint32_resp(response, p)
                local attr = str_sub(response, p, p + len - 1) -- \u0000
                p = p + len
                
                attrs[attr], p = uint32_resp(response, p)
                table_insert(iattrs, attr) -- paris unspecified order, but we need order
                
                nattrs = nattrs - 1
            end
            result.attrs = attrs
            
            -- read match count
            local count
            count,p = uint32_resp(response, p)
            local id64
            id64, p = uint32_resp(response, p)
            
            -- read matches
            local idx = 0
            while count > 0 and p < max do
               
                -- index into result array
                idx = idx + 1
                
                -- parse document id and weight
                local doc, weight
                if id64 > 0 then
                    doc, p = uint64_resp(response, p)
                    weight, p = uint32_resp(response, p)
                else
                    doc, p    = uint32_resp(response, p)
                    weight, p = uint32_resp(response, p)
                end
                weight = str_format("%u", weight)
               
                -- create match entry, array
                result["matches"][idx] = {id = doc, weight = weight}
               
                -- parse and create attributes
                local attrvals = {}
                for _, attr in ipairs(iattrs) do
                    local type = attrs[attr]
                    -- handle 64bit ints signed
                    if type == _CONSTS.SPH_ATTR_BIGINT then
                        attrvals[attr], p = int64_resp(response, p)
                    -- handle floats    
                    elseif type == _CONSTS.SPH_ATTR_FLOAT then 
                        local uval
                        uval, p = uint32_resp(response, p)
                        local fval = uint32_to_float(uval)
                        attrvals[attr] = fval
                    -- handle everything else as unsigned ints
                    else
                        local val
                        val, p = uint32_resp(response, p)
                        if type == _CONSTS.SPH_ATTR_MULTI then 
                            attrvals[attr] = {}
                            local nvalues = val
                            while nvalues > 0 and p < max do
                                val, p = uint32_resp(response, p)
                                table_insert(attrvals[attr], val)
                               
                                nvalues = nvalues - 1 -- while
                            end
                        elseif type == _CONSTS.SPH_ATTR_MULTI64 then
                            attrvals[attr] = {}
                            local nvalues = val
                            while nvalues > 0 and p < max do
                                val, p = uint32_resp(response, p)
                                table_insert(attrvals[attr], tostring(val))
                               
                                nvalues = nvalues - 2 -- while
                            end
                        elseif type == _CONSTS.SPH_ATTR_STRING then
                            attrvals[attr] = str_sub(response, p, p + val - 1) -- \u0000
                            p = p + val
                        else
                            attrvals[attr] = val
                        end
                    end
                end
               
                result["matches"][idx]["attrs"] = attrvals
               
                count = count - 1 -- while
            end
           
            local total, total_found, msecs, words
            total, p = uint32_resp(response, p)
            total_found, p = uint32_resp(response, p)
            msecs, p = uint32_resp(response, p)
            words, p = uint32_resp(response, p)
            
            result.total = str_format("%u", total)
            result.total_found = str_format("%u", total_found)
            result.time = str_format("%.3f", msecs / 1000)
            
            while words > 0 and p < max do
                local len
                len, p = uint32_resp(response, p)
                local word = str_sub(response, p, p + len - 1) -- \u0000
                p = p + len
                local docs
                docs, p = uint32_resp(response, p)
                docs = str_format("%u", docs)
                local hits
                hits, p = uint32_resp(response, p)
                hits = str_format("%u", hits)
                result["words"][word] = {docs = docs, hits = hits}
               
                words = words - 1 -- while
            end
        else -- fatal error
            result.error = message
        end
       
        ires = ires + 1 -- while
    end
    
    return results
end


-- connect to searchd, run queries batch, and return an array of result sets
local function _RunQueries(self)
    if #self.reqs == 0 then 
        self.error = "no queries defined, issue AddQuery() first";
        return false
    end
    
    local sock = _Connect(self)
    if not sock then
       return false
    end
    
    -- send query, get response
    local nreqs  = #self.reqs
    local req    = table_concat(self.reqs)
    local length = 8 + #req
   
    req = uint16_pack(_CONSTS.SEARCHD_COMMAND_SEARCH) ..
          uint16_pack(_CONSTS.VER_COMMAND_SEARCH) ..
          uint32_pack(length) ..
          uint32_pack(0) ..
          uint32_pack(nreqs) ..
          req
         
    local bytes, err = sock:send(req)
    if not bytes then
        if err == "timeout" then
            sock:close()
        end
        self.error = "Sphinx: failed to send queries"
        return false
    end
   
    local response = _GetReponse(self, sock, _CONSTS.VER_COMMAND_SEARCH)
   
    if not response then
        return false
    end
    
    -- query sent ok; we can reset reqs now
    self.reqs = {}
   
    return _ParseSearchResponse(response, nreqs)
end
_M.RunQueries = _RunQueries


-- connect to searchd server, run given search query through given indexes,
-- and return the search results
function _M.Query(self, query, index, comment)

    assert(#self.reqs == 0)
    
    _AddQuery(self, query, index, comment)
    
    local results = _RunQueries(self)
    self.reqs = {} -- just in case it failed too early
    
    if type(results) ~= "table" then
        return false -- probably network error; error message should be already filled
    end
   
    self.error   = results[1]["error"]
    self.warning = results[1]["warning"]
   
    if results[1]["status"] == _CONSTS.SEARCHD_ERROR then
        return false
    else
        return results[1]
    end
end


-- get last error message (string)
function _M.GetLastError(self)
    return self.error
end


-- get last warning message (string)
function _M.GetLastWarning(self)
    return self.warning
end


-- set distributed retries count and delay
function _M.SetRetries(self, count, delay)

    assert(type(count) == "number" and count >= 0)
    assert(type(delay) == "number" and delay >= 0)
    
    self.retrycount = count
    self.retrydelay = delay
end


-- set server connection timeout (0 to remove)
function _M.SetConnectTimeout(self, timeout)
    assert(type(timeout) == "number")
    
    self.timeout = timeout
end


-- set offset and count into result set,
-- and optionally set max-matches and cutoff limits
function _M.SetLimits(self, offset, limit, max, cutoff)
    max    = max or 0
    cutoff = cutoff or 0
    
    assert(type(offset) == "number")
    assert(type(limit) == "number")
    assert(offset >= 0)
    assert(limit > 0)
    assert(max >= 0)
    
    self.offset = offset
    self.limit  = limit
    
    if max > 0 then
        self.maxmatches = max
    end
    
    if cutoff > 0 then
        self.cutoff = cutoff
    end
end


-- set maximum query time, in milliseconds, per-index
-- integer, 0 means "do not limit"
function _M.SetMaxQueryTime(self, max)
    assert(type(max) == "number")
    assert(max >= 0)
    
    self.maxquerytime = max
end


-- set attribute values override
-- there can be only one override per attribute
-- values must be a hash that maps document IDs to attribute values
function _M.SetOverride(self, attrname, attrtype, values)
    assert(type(attrname) == "string")
    assert(type(values) == "table")
    
    assert( attrtype ==  _CONSTS.SPH_ATTR_INTEGER
         or attrtype ==  _CONSTS.SPH_ATTR_TIMESTAMP
         or attrtype ==  _CONSTS.SPH_ATTR_BOOL
         or attrtype ==  _CONSTS.SPH_ATTR_FLOAT
         or attrtype ==  _CONSTS.SPH_ATTR_BIGINT
    )

    self.overrides[attrname] = {attr = attrname, type = attrtype, values = values}
end


-- set select-list (attributes or expressions), SQL-like syntax
function _M.SetSelect(self, select)
    assert(type(select) == "string")
    
    self.select = select
end


-- set matching mode
function _M.SetMatchMode(self, mode)
    assert( mode ==  _CONSTS.SPH_MATCH_ALL
         or mode ==  _CONSTS.SPH_MATCH_ANY
         or mode ==  _CONSTS.SPH_MATCH_PHRASE
         or mode ==  _CONSTS.SPH_MATCH_BOOLEAN
         or mode ==  _CONSTS.SPH_MATCH_EXTENDED
         or mode ==  _CONSTS.SPH_MATCH_FULLSCAN
         or mode ==  _CONSTS.SPH_MATCH_EXTENDED2
    )
    self.mode = mode
end


-- set ranking mode
function _M.SetRankingMode(self, ranker, rankexpr)
    rankexpr = rankexpr or ""
    
    assert(ranker >= 0 and ranker < _CONSTS.SPH_RANK_TOTAL)
    assert(type(rankexpr) == "string")
    
    self.ranker   = ranker
    self.rankexpr = rankexpr
end


-- set matches sorting mode
function _M.SetSortMode(self, mode, sortby)
    sortby = sortby or ""

    assert( mode ==  _CONSTS.SPH_SORT_RELEVANCE
         or mode ==  _CONSTS.SPH_SORT_ATTR_DESC
         or mode ==  _CONSTS.SPH_SORT_ATTR_ASC
         or mode ==  _CONSTS.SPH_SORT_TIME_SEGMENTS
         or mode ==  _CONSTS.SPH_SORT_EXTENDED
         or mode ==  _CONSTS.SPH_SORT_EXPR
    )
    
    assert(type(sortby) == "string")
    assert(mode == _CONSTS.SPH_SORT_RELEVANCE or #sortby > 0)
    
    self.sort   = mode
    self.sortby = sortby
    
end


-- bind per-field weights by order
-- DEPRECATED; use SetFieldWeights() instead
function _M.SetWeights(self, weights)

    assert(type(weights) == "table")
    
    for _, weight in pairs(weights) do
        assert(type(weight) == "number")
    end
    
    self.weights = weights
    
end


-- bind per-field weights by name
function _M.SetFieldWeights(self, weights)
    assert(type(weights) == "table")
    
    for name, weight in pairs(weights) do
        assert(type(name) == "string")
        assert(type(weight) == "number")
    end
    
    self.fieldweights = weights
end


-- bind per-index weights by name
function _M.SetIndexWeights(self, weights)
    assert(type(weights) == "table")
    
    for index, weight in pairs(weights) do
        assert(type(index) == "string")
        assert(type(weight) == "number")
    end
    
    self.indexweights = weights
end


-- set IDs range to match
-- only match records if document ID is beetwen $min and $max (inclusive)
function _M.SetIDRange(self, min, max)
    assert(type(min) == "number")
    assert(type(max) == "number")
    assert(min <= max)
    
    self.min_id = min
    self.max_id = max
end


-- set values set filter
-- only match records where attribute value is in given set
function _M.SetFilter(self, attribute, values, exclude)
    exclude = exclude or false
    
    assert(type(exclude) == "boolean")
    assert(type(attribute) == "string")
    assert(type(values) == "table")
    assert(#values > 0)
    
    if type(values) == "table" and #values > 0 then
        for _, value in pairs(values) do
            assert(type(value) == "number")
        end
        local filters = {
            type = _CONSTS.SPH_FILTER_VALUES,
            attr = attribute,
            exclude = exclude,
            values = values
        }
        table_insert(self.filters, filters)
    end
end


-- set range filter
-- only match records if attribute value is beetwen min and max (inclusive)
function _M.SetFilterRange(self, attribute, min, max, exclude)
    exclude = exclude or false
    
    assert(type(exclude) == "boolean")
    assert(type(attribute) == "string")
    assert(type(min) == "number")
    assert(type(max) == "number")
    assert(min <= max)
    
    local filters = {
        type = _CONSTS.SPH_FILTER_RANGE,
        attr = attribute,
        exclude = exclude,
        min = min,
        max = max
    }
    table_insert(self.filters, filters)
end


-- set float range filter
-- only match records if $attribute value is beetwen $min and $max (inclusive)
function _M.SetFilterFloatRange(self, attribute, min, max, exclude)
    exclude = exclude or false
    
    assert(type(exclude) == "boolean")
    assert(type(attribute) == "string")
    assert(type(min) == "number")
    assert(type(max) == "number")
    assert(min <= max)
    
    local filters = {
        type = _CONSTS.SPH_FILTER_FLOATRANGE,
        attr = attribute,
        exclude = exclude,
        min = min,
        max = max
    }
    table_insert(self.filters, filters)
end


-- setup anchor point for geosphere distance calculations
-- required to use @geodist in filters and sorting
-- latitude and longitude must be in radians
function _M.SetGeoAnchor(self, attrlat, attrlong, lat, long)
    assert(type(attrlat) == "string")
    assert(type(attrlong) == "string")
    assert(type(lat) == "number")
    assert(type(long) == "number")
    
    self.anchor = {
        attrlat = attrlat,
        attrlong = attrlong,
        lat = lat,
        long = long
    }
end


-- set grouping attribute and function
function _M.SetGroupBy(self, attribute, func, groupsort)
    groupsort = groupsort or "@group desc"
    
    assert(type(attribute) == "string")
    assert(type(groupsort) == "string")
    assert( func ==  _CONSTS.SPH_GROUPBY_DAY
         or func ==  _CONSTS.SPH_GROUPBY_WEEK
         or func ==  _CONSTS.SPH_GROUPBY_MONTH
         or func ==  _CONSTS.SPH_GROUPBY_YEAR
         or func ==  _CONSTS.SPH_GROUPBY_ATTR
         or func ==  _CONSTS.SPH_GROUPBY_ATTRPAIR
    )
    
    self.groupby   = attribute
    self.groupfunc = func
    self.groupsort = groupsort
end


-- set count-distinct attribute for group-by queries
function _M.SetGroupDistinct(self, attribute)
    assert(type(attribute) == "string")
    self.groupdistinct = attribute
end


-- clear all filters (for multi-queries)
function _M.ResetFilters(self)
    self.filters = {}
    self.anchor  = {}
end


-- clear groupby settings (for multi-queries)
function _M.ResetGroupBy(self)
    self.groupby       = ""
    self.groupfunc     = _CONSTS.SPH_GROUPBY_DAY
    self.groupsort     = "@group desc"
    self.groupdistinct = ""
end


-- clear all attribute value overrides (for multi-queries)
function _M.ResetOverrides(self)
    self.override = {}
end


--[[
-- connect to searchd server, and generate exceprts (snippets)
-- of given documents for given query. returns false on failure,
-- an array of snippets on success
--]]
-- docs likes: {"xx string", "xx string"} 
function _M.BuildExcerpts(self, docs, index, words, opts)
    opts = opts or {}
    
    assert(type(docs) == "table")
    assert(type(index) == "string")
    assert(type(words) == "string")
    assert(type(opts) == "table")
    
    local sock = _Connect(self)
    if not sock then
        return false
    end
    
    opts.before_match = opts.before_match or "<b>"
    opts.after_match = opts.after_match or "</b>"
    opts.chunk_separator = opts.chunk_separator or " ... "
    opts.limit = opts.limit or 256
    opts.limit_passages = opts.limit_passages or 0
    opts.limit_words = opts.limit_words or 0
    opts.around = opts.around or 5
    opts.exact_phrase = opts.exact_phrase or false
    opts.single_passage = opts.single_passage or false
    opts.use_boundaries = opts.use_boundaries or false
    opts.weight_order = opts.weight_order or false
    opts.query_mode = opts.query_mode or false
    opts.force_all_words = opts.force_all_words or false
    opts.start_passage_id = opts.start_passage_id or 1
    opts.load_files = opts.load_files or false
    opts.html_strip_mode = opts.html_strip_mode or "index"
    opts.allow_empty = opts.allow_empty or false
    opts.passage_boundary = opts.passage_boundary or "none"
    opts.emit_zones = opts.emit_zones or false
    
    -- build request
    
    --v.1.2 req
    local flags = 1 -- remove spaces
    if opts.exact_phrase then
        flags = bor(flags, 2)
    end
    if opts.single_passage then
        flags = bor(flags, 4)
    end
    if opts.use_boundaries then
        flags = bor(flags, 8)
    end
    if opts.weight_order then
        flags = bor(flags, 16)
    end
    if opts.query_mode then
        flags = bor(flags, 32)
    end
    if opts.force_all_words then
        flags = bor(flags, 64)
    end
    if opts.load_files then
        flags = bor(flags, 128)
    end
    if opts.allow_empty then
        flags = bor(flags, 256)
    end
    if opts.emit_zones then
        flags = bor(flags, 512)
    end
    
    local req = {}
   
    uint32_req(req, 0)
    uint32_req(req, flags) --  mode=0, flags=$flags
    string_req(req, index) -- req index
    string_req(req, words) -- req words
    
    -- options
    string_req(req, opts.before_match)
    string_req(req, opts.after_match)
    string_req(req, opts.chunk_separator)
    uint32_req(req, opts.limit)
    uint32_req(req, opts.around)
    uint32_req(req, opts.limit_passages)
    uint32_req(req, opts.limit_words)
    uint32_req(req, opts.start_passage_id) -- v.1.2
    string_req(req, opts.html_strip_mode)
    string_req(req, opts.passage_boundary)
    
    -- documents
    uint32_req(req, #docs)
    for _, doc in pairs(docs) do
        assert(type(doc) == "string")
        string_req(req, doc)
    end
    
    -- send query, get response
   
    req = table_concat(req)
    local len = #req
    
    req = uint16_pack(_CONSTS.SEARCHD_COMMAND_EXCERPT) ..
          uint16_pack(_CONSTS.VER_COMMAND_EXCERPT) ..
          uint32_pack(len) ..
          req
         
    local bytes, err = sock:send(req)
    if not bytes then
        if err == "timeout" then
            sock:close()
        end
        self.error = "Sphinx: failed to send queries"
        return false
    end
     
    local response = _GetReponse(self, sock, _CONSTS.VER_COMMAND_EXCERPT)
    if not response then
        return false
    end
   
    -- parse response
    local p  = 1
    local res  = {}
    local rlen = #response
     
    for i = 1, #docs do
        local len
        len, p = uint32_resp(response, p)
        if (p + len) > (rlen + 1) then
            self.error = "incomplete reply"
            return false
        end
        if len > 0 then
            table_insert(res, str_sub(response, p, p + len - 1))
        else
            table_insert(res, "")
        end
        p = p + len
    end
    
    return res
end


--[[
-- batch update given attributes in given rows in given indexes
-- returns amount of updated documents (0 or more) on success, or -1 on failure
--]]
function _M.UpdateAttributes(self, index, attrs, values, mva)
    mva = mva or false
    
    -- verify everything
    assert(type(index) == "string")
    assert(type(mva) == "boolean")
    
    assert(type(attrs) == "table")
    for _, attr in pairs(attrs) do
        assert(type(attr) == "string")
    end
    
    assert(type(values) == "table")
    for id, entry in pairs(values) do
        assert(type(id) == "number")
        assert(type(entry) == "table")
        assert(#entry == #attrs)
        for _, v in pairs(entry) do
            if mva then
                assert(type(v) == "table")
                for _, vv in pairs(v) do
                    assert(type(vv) == "number")
                end
            else
                assert(type(v) == "number")
            end
        end
    end
    
    -- build request
    local req = {}
   
    string_req(req, index)
    uint32_req(req, #attrs)
    for _, attr in ipairs(attrs) do
        string_req(req, attr)
        if mva then
            uint32_req(req, 1)
        else
            uint32_req(req, 0)
        end
    end
    
    uint32_req(req, #values)
    for id, entry in pairs(values) do
        uint64_req(req, id)
        for _, v in ipairs(entry) do
            if mva then
                uint32_req(req, #v)
                for _, vv in ipairs(v) do
                    uint32_req(req, vv)
                end
            else
                uint32_req(req, v)
            end
        end
    end
    
    -- connect, send query, get response
    local sock = _Connect(self)
    if not sock then
        return -1
    end
   
    req = table_concat(req)
    local len = #req
   
    req = uint16_pack(_CONSTS.SEARCHD_COMMAND_UPDATE) ..
          uint16_pack(_CONSTS.VER_COMMAND_UPDATE) ..
          uint32_pack(len) ..
          req
         
    local bytes, err = sock:send(req)
    if not bytes then
        if err == "timeout" then
            sock:close()
        end
        self.error = "Sphinx: failed to send queries"
        return -1
    end
   
    local response = _GetReponse(self, sock, _CONSTS.VER_COMMAND_UPDATE)
    if not response then
        return -1
    end
     
    -- parse response
    local updated = uint32_unpack(response, 1)
    return updated
end


--[[
-- connect to searchd server, and generate keyword list for a given query
-- returns false on failure,
-- an array of words on success
--]]
function _M.BuildKeywords(self, query, index, hits)
    hits = hits or false
    assert(type(query) == "string")
    assert(type(index) == "string")
    assert(type(hits) == "boolean")
    
    local sock = _Connect(self)
    if not sock then
        return false
    end
    
    -- build request
    
    local req = {}
    
    -- v.1.0 req
    string_req(req, query)
    string_req(req, index)
    local ihits = (hits and 1) or 0
    uint32_req(req, ihits)
    
    -- send query, get response
    
    req = table_concat(req)
    local len = #req
    
    req = uint16_pack(_CONSTS.SEARCHD_COMMAND_KEYWORDS) ..
          uint16_pack(_CONSTS.VER_COMMAND_KEYWORDS) ..
          uint32_pack(len) ..
          req
         
    local bytes, err = sock:send(req)
    if not bytes then
        if err == "timeout" then
            sock:close()
        end
        self.error = "Sphinx: failed to send queries"
        return false
    end
   
   local response = _GetReponse(self, sock, _CONSTS.VER_COMMAND_KEYWORDS)
   if not response then
       return false
   end
   
   -- parse response
   
   local p  = 1
   local res  = {}
   local rlen = #response
   
   local nwords
   nwords, p = uint32_resp(response, p)
   for i = 1, nwords do
       local len
       len, p = uint32_resp(response, p)
       local tokenized
       if len > 0 then
           tokenized = str_sub(response, p, p + len - 1)
       else
           tokenized = ""
       end
       p = p + len
       
       len, p = uint32_resp(response, p)
       local normalized
       if len > 0 then
           normalized = str_sub(response, p, p + len - 1)
       else
           normalized = ""
       end
       p = p + len
       
       table_insert(res, {tokenized = tokenized, normalized = normalized})
       
       if hits then
           local ndocs
           ndocs, p = uint32_resp(response, p)
           local nhits
           nhits, p = uint32_resp(response, p)
           res[i].docs = ndocs
           res[i].hits = nhits
       end
       
       if p > rlen + 1 then
           self.error = "incomplete reply"
           return false
       end
   end
   
   return res
end


function _M.EscapeString(self, str)
    local pattern = '[\\()|-!@~"&/^$=]'
    local repl = {
        ["\\"] = "\\\\",
        ["("] = "\\(",
        [")"] = "\\)",
        ["|"] = "\\|",
        ["-"] = "\\-",
        ["!"] = "\\!",
        ["@"] = "\\@'",
        ["~"] = "\\~",
        ['"'] = '\\"',
        ["&"] = "\\&",
        ["/"] = "\\/",
        ["^"] = "\\^",
        ["$"] = "\\$",
        ["="] = "\\=",
    }
    return (str_gsub(str, pattern, repl))
end


-- flush
function _M.FlushAttributes(self)
    local sock = _Connect(self)
    if not sock then
        return -1
    end
    
    local req = uint16_pack(_CONSTS.SEARCHD_COMMAND_FLUSHATTRS) ..
                uint16_pack(_CONSTS.VER_COMMAND_FLUSHATTRS) ..
                uint32_pack(0) -- len=0
         
    local bytes, err = sock:send(req)
    if not bytes then
        if err == "timeout" then
            sock:close()
        end
        self.error = "Sphinx: failed to send queries"
        return -1
    end
   
    local response = _GetReponse(self, sock, _CONSTS.VER_COMMAND_FLUSHATTRS)
    if not response then
        return -1
    end
    
    local tag = -1
    if #response == 4 then
        tag = uint32_unpack(response, 1)
    else
        self.error = "unexpected response length"
    end
    return tag
end


return _M

