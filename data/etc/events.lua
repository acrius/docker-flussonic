-- This is an example of filtering script
-- It will route events and send to http only part of them
--

good_events = {["session.open"] = true, ["stream.source_ready"] = true, ["stream.source_lost"] = true, ["file.opened"] = true}

url = "http://localhost:8080/tv/events"

if good_events[event.event] then
  -- http.post(url, {["content-type"] = "application/json"}, json.encode(event))
  flussonic.log(event.event.." "..json.encode(event))
end


