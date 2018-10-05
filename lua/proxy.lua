local mysql = require "resty.mysql"
local db, err = mysql:new()
if not db then
  ngx.log(ngx.ERR, "failed to instantiate mysql: ", err)
  return
end
local ok, err, errno, sqlstate = db:connect{
  host = "127.0.0.1",
  port = 3306,
  database = "lua",
  user = "lua",
  password = "datasection",
  max_packet_size = 1024 * 1024 }

if not ok then
  ngx.log(ngx.ERR, "failed to connect: ", err, ": ", errno, " ", sqlstate)
  return
end

res, err, errno, sqlstate = db:query(string.format("select domain.vhost, domain.phost, path.src, path.dest, domain.deny from path inner join domain on path.domain_id = domain.id where vhost='%s' and src='%s'", ngx.var.host, ngx.var.document_uri))
if not res then
  ngx.log(ngx.ERR, "bad result: ", err, ": ", errno, ": ", sqlstate, ".")
  return
end

ngx.var.upstream = (res[1] ~= nil) and res[1]['phost'] or ngx.var.host
ngx.req.set_uri((res[1] ~= nil) and res[1]['dest'] or ngx.var.document_uri)

local ok, err = db:set_keepalive(10000, 100)
if not ok then
  ngx.log(ngx.ERR, "failed to set keepalive: ", err)
  return
end
