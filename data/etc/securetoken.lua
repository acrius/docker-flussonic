secure_token = "mySharedSecret"

if extra and extra.key then
  secure_token = extra.key
end

function to_s(s)
  if not s then
    return ""
  end
  if type(s) == "string" then
    return s
  end
  return "not_a_string"
end

http_handler = {}

http_handler.sign = function(r, extra)
  qs = r.query
  if extra.key then
    secure_token = extra.key
  end
  if extra.password and not (qs.password == extra.password) then
    return "http", 403, {}, "invalid_password\n"
  end
  if qs.ip then
    ip = qs.ip
  else
    ip = r.ip
  end

  hashstr = to_s(qs.name) .. to_s(ip) .. to_s(qs.starttime) .. to_s(qs.endtime) .. to_s(secure_token) .. to_s(qs.salt)

  hash = crypto.sha1(hashstr) .. "-" .. to_s(qs.salt) .. "-" .. to_s(qs.endtime) .. "-" .. to_s(qs.starttime)
  return "http", 200, {}, hash.."\n"
end

http_handler.embed = function(r, extra)
  qs = r.query
  if extra.key then
    secure_token = extra.key
  end
  if extra.password and not (qs.password == extra.password) then
    return "http", 403, {}, "invalid_password\n"
  end

  if qs.ip then
    ip = qs.ip
  else
    ip = r.ip
  end
  hashstr = to_s(qs.name) .. to_s(ip) .. to_s(qs.starttime) .. to_s(qs.endtime) .. to_s(secure_token) .. to_s(qs.salt)

  hash = crypto.sha1(hashstr) .. "-" .. to_s(qs.salt) .. "-" .. to_s(qs.endtime) .. "-" .. to_s(qs.starttime)

  return "http", 200, {["Content-Type"] = "text/html"}, "<html><body><embed src='/"..qs.name.."/embed.html?token="..hash..
    "' width='100%' height='100%'></embed></body></html>"
end

if (not req) then
  return false, {}
end



qs = http.qs_decode(req.qs)

parts = {}
r = req.token
while true do
  i = r:find("-")
  if i then
    table.insert(parts, r:sub(1,i-1))
    r = r:sub(i+1)
  else
    table.insert(parts, r)
    break
  end
end
user_hash = parts[1]
user_salt = parts[2]
user_endtime = parts[3]
user_starttime = parts[4]

hashstr = req.name .. req.ip .. to_s(user_starttime) .. to_s(user_endtime) .. secure_token .. to_s(user_salt)

hash = crypto.sha1(hashstr)

-- flussonic.log("Hashstr: '"..hashstr.."', hash: '"..hash.."', your hash: '"..to_s(user_hash).."'")

if not (user_hash == hash) then
  -- flussonic.log("Hashstr: '"..hashstr.."', hash: '"..hash.."', your hash: '"..to_s(req.token).."'")
  return false, {["code"] = 403, ["message"] = "invalid hash"}
end

now = flussonic.now()

starttime = tonumber(user_starttime)
endtime = tonumber(user_endtime)

if not (starttime == nil) and now < starttime then
  -- flussonic.log("False1 Hashstr: '"..hashstr.."', hash: '"..hash.."', your hash: '"..to_s(req.token).."'")
  return false, {["code"] = 403, ["message"] = "too early"}
end

if not (endtime == nil) and now > endtime then
  -- flussonic.log("False2 Hashstr: '"..hashstr.."', hash: '"..hash.."', your hash: '"..to_s(req.token).."'")
  return false, {["code"] = 403, ["message"] = "too late"}
end

return true, {}

