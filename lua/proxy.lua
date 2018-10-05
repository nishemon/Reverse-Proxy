-- str1がstr2に前方一致するか検証
function regexp(str1, str2)
  pattern = "^"..str2.."[/\\?]+.*"
  result = string.match(str1, pattern)
  if str1 == str2 or result ~= nil then return true end
  return false
end

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

res, err, errno, sqlstate = db:query(string.format("select domain.vhost, domain.phost, path.src, path.dest, domain.deny from path inner join domain on path.domain_id = domain.id where vhost='%s';", ngx.var.host))
if not res then
  ngx.log(ngx.ERR, "bad result: ", err, ": ", errno, ": ", sqlstate, ".")
  return
end

flag = false
for k, v in pairs(res) do
  if v ~= nil and v.vhost == ngx.var.host then
    ngx.var.upstream = v.phost

    -- DBにindexされている場合
    if regexp(ngx.var.document_uri, v.src) then
      out_path = (string.format("%s", v.dest) ~= 'userdata: NULL') and v.dest or v.src
      if v.src ~= out_path and out_path ~= ngx.var.document_uri then ngx.req.set_uri(out_path) end
      flag = true
      break
    end
  end
end

  -- DBにindexされていない場合
if not flag then
  if res[1] ~= nil and res[1]['deny'] == 0 or res[1] == nil then
    ngx.var.upstream = "www.datasection.co.jp"
    ngx.req.set_uri("/")
  end
end

local ok, err = db:set_keepalive(10000, 100)
if not ok then
  ngx.log(ngx.ERR, "failed to set keepalive: ", err)
  return
end
