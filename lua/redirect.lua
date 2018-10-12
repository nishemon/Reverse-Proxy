local cjson = require 'cjson'
if ngx.var.arg_domain and ngx.var.arg_path then
	ngx.var.upstream = ngx.var.arg_domain
	ngx.req.set_uri(ngx.var.arg_path)
	ngx.var.args = ""
	ngx.log(ngx.ERR, "ngx.var.args(clean): ", ngx.var.args)
	ngx.log(ngx.ERR, "ngx.var.upstream: ", ngx.var.upstream, ", ngx.var.document_uri: ", ngx.var.document_uri)

	hash = math.random(1000000000000)

	ngx.header['Set-Cookie'] = "hash=" .. hash
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
	hash_list:set("hash_list", cjson.encode(json))
	ngx.log(ngx.ERR, "hash_list: ", cjson.encode(json))
else
	ngx.var.upstream = "www.datasection.co.jp"
	ngx.req.set_uri("/")
end
