-- Copyright (C) 2016-2017 Jian Chang <aa65535@live.com>
-- Licensed to the public under the GNU General Public License v3.

local m, s, o
local shadowsocks = "shadowsocks"
local sid = arg[1]
local encrypt_methods = {
	"none",
	"rc4-md5",
	"rc4-md5-6",
	"aes-128-cfb",
	"aes-192-cfb",
	"aes-256-cfb",
	"aes-128-ctr",
	"aes-192-ctr",
	"aes-256-ctr",
	"aes-128-gcm",
	"aes-192-gcm",
	"aes-256-gcm",
	"camellia-128-cfb",
	"camellia-192-cfb",
	"camellia-256-cfb",
	"bf-cfb",
	"salsa20",
	"chacha20",
	"chacha20-ietf",
	"chacha20-ietf-poly1305",
	"xchacha20-ietf-poly1305",
}
local protocol_plugins = {
	"origin",
	"auth_sha1_v4",
	"auth_aes128_md5",
	"auth_aes128_sha1",
	"auth_chain_a"
}
local obfs_plugins = {
	"plain",
	"http_simple",
	"http_post",
	"tls1.2_ticket_auth"
}

local function has_bin(name)
	return luci.sys.call("command -v %s >/dev/null" %{name}) == 0
end

local has_ssr_redir = has_bin("ssr-redir")

m = Map(shadowsocks, "%s - %s" %{translate("ShadowSocks"), translate("Edit Server")})
m.redirect = luci.dispatcher.build_url("admin/services/shadowsocks/servers")

if m.uci:get(shadowsocks, sid) ~= "servers" then
	luci.http.redirect(m.redirect)
	return
end

-- [[ Edit Server ]]--
s = m:section(NamedSection, sid, "servers")
s.anonymous = true
s.addremove = false

o = s:option(Value, "alias", translate("Alias(optional)"))
o.rmempty = true

o = s:option(Flag, "fast_open", translate("TCP Fast Open"))
o.rmempty = false

o = s:option(Value, "server", translate("Server Address"))
o.datatype = "ipaddr"
o.rmempty = false

o = s:option(Value, "server_port", translate("Server Port"))
o.datatype = "port"
o.rmempty = false

o = s:option(Value, "timeout", translate("Connection Timeout"))
o.datatype = "uinteger"
o.default = 60
o.rmempty = false

o = s:option(Value, "password", translate("Password"))
o.password = true

o = s:option(Value, "key", translate("Directly Key"))

o = s:option(ListValue, "encrypt_method", translate("Encrypt Method"))
for _, v in ipairs(encrypt_methods) do o:value(v, v:upper()) end
o.rmempty = false

if not has_ssr_redir then
	o = s:option(Value, "plugin", translate("Plugin Name"))
	o.placeholder = "eg: obfs-local"

	o = s:option(Value, "plugin_opts", translate("Plugin Arguments"))
	o.placeholder = "eg: obfs=http;obfs-host=www.bing.com"
else
	-- [[ ShadowSocksR ]]--
	o = s:option(ListValue, "protocol_plugin", translate("Protocol Plugin"))
	for _, v in ipairs(protocol_plugins) do o:value(v, v:upper()) end
	o.rmempty = false

	o = s:option(Value, "protocol_param", translate("Protocol Param"), translate("Parameter for protocol plugins. Leave blank if you're not sure."))
	o.password = true
	o.placeholder = "(for auth_chain_a) eg: <port>:<key>"

	o = s:option(ListValue, "obfs_plugin", translate("Obfuscation Plugin"))
	for _, v in ipairs(obfs_plugins) do o:value(v, v:upper()) end
	o.rmempty = false

	o = s:option(Value, "obfs_param", translate("Obfuscation Param"), translate("HTTP host header for HTTP obfuscation plugins. Leave blank if you're not sure."))
	o.placeholder = "eg: cloudflare.com,cloudfront.net"
end

return m
