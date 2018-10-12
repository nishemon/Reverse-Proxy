local cjson = require 'cjson'
-- str1がstr2に前方一致するか検証
function regexp(str1, str2)
  pattern = "^"..str2.."[/\\?]+.*"
  result = string.match(str1, pattern)
  if str1 == str2 or result ~= nil then return true end
  return false
end

function basic_authentication(v)
  if not ngx.var.http_authorization then
    return false
  end
  local basic_auth = ngx.decode_base64(string.match(ngx.var.http_authorization, "^Basic (.*)"))
  return basic_auth == (v.username .. ":" .. v.password)
end

function ldap_authentication(v)
  local allow = false
  if ngx.var.cookie_hash then
    local hash_list = ngx.shared.hash_list
    local value, flags = hash_list:get("hash_list")
    if not value then
      allow = false
    else
      json = cjson.decode(value)
      for index, value in pairs(json) do
        if tonumber(value) == tonumber(ngx.var["cookie_hash"]) then
          allow = true
          break
        end
      end
    end
  end
  return allow
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

res, err, errno, sqlstate = db:query(string.format("select domain.vhost, domain.phost, domain.deny, path.src, path.dest, path.auth_type, auth_user.username, auth_user.password from domain left join path on domain.id=path.domain_id left join path_user on path.id=path_user.path_id left join auth_user on path_user.user_id=auth_user.id where vhost='%s'", ngx.var.host))
if not res then
  ngx.log(ngx.ERR, "bad result: ", err, ": ", errno, ": ", sqlstate, ".")
  return
end

-- upstremを設定
if res[1] ~= nil then ngx.var.upstream = res[1].phost
else ngx.var.upstream = ngx.var.host end

local allow_unindexed_path = false

for k, v in pairs(res) do
  if v ~= nil and regexp(ngx.var.document_uri, v.src) then
    allow_unindexed_path = true
    -- pathを更新
    out_path = (v.dest ~= ngx.null) and v.dest or v.src
    if v.src ~= out_path and out_path ~= ngx.var.document_uri then ngx.req.set_uri(out_path) end

    if v.auth_type == 'basic' then
      ngx.header['WWW-Authenticate'] = 'Basic realm="Secret Zone"'
      if not basic_authentication(v) then ngx.exit(ngx.HTTP_UNAUTHORIZED) end

    elseif v.auth_type == 'ldap' then
      -- cookieが無かったら'/ldap-auth'へ飛ばす
      if not ldap_authentication(v) then
        ngx.log(ngx.ERR, "NO cookie !!!!!!")
        ngx.var.args = ngx.encode_args({redirect = ngx.escape_uri(ngx.var.request_uri)})
        ngx.log(ngx.ERR, "ngx.var.args: ", ngx.var.args)
        ngx.var.upstream = 'localhost'
        ngx.req.set_uri('/ldap-auth')
      end
    end
  end
end

if not allow_unindexed_path then
  ngx.var.upstream = "www.datasection.co.jp"
  ngx.req.set_uri("/")
end

local ok, err = db:set_keepalive(10000, 100)
if not ok then
  ngx.log(ngx.ERR, "failed to set keepalive: ", err)
  return
end
