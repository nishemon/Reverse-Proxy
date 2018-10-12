local cjson = require 'cjson'
var expire = ngx.var.login_expire or 86400
var args = ngx.decode_args(ngx.var.args)
ngx.log(ngx.ERR, "ngx.var.args(clean): ", ngx.var.args)

hash = math.random(1000000000000)

-- TODO "Path="を設定しないといけない気がする
ngx.header['Set-Cookie'] = "hash=" .. hash .. "; Expires=" .. ngx.cookie_time(ngx.time() + expire)
ngx.log(ngx.ERR, "cookie get !!!!!!")
local hash_list = ngx.shared.hash_list
local value, flags = hash_list:get("hash_list")
local json = {}
if not value then
	json = {hash}
else
json = cjson.decode(value)
table.insert(json, hash)
end
hash_list:set("hash_list", cjson.encode(json), expire)
ngx.log(ngx.ERR, "hash_list: ", cjson.encode(json))
return ngx.redirect(args.redirect or ngx.var.on_fatal)
