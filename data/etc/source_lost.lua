if not new_dead_streams then
  new_dead_streams = {}
end

if not new_restored_streams then
  new_restored_streams = {}
end

if not old_streams then
  old_streams = {}
end

local now = flussonic.now()

local event_count = 0
for k,evt in pairs(events) do
  if evt.event == "stream_stopped" or evt.event == "source_lost" then
    if not old_streams[evt.media] then
      new_dead_streams[evt.media] = now
    end
    new_restored_streams[evt.media] = nil
  end
  if evt.event == "source_ready" then
    if old_streams[evt.media] then
      new_restored_streams[evt.media] = now
    end
    new_dead_streams[evt.media] = nil
  end
  event_count = event_count + 1
end

flussonic.log("events "..event_count)

if not notify_timer then
  notify_timer = flussonic.timer(10000, "handle_timer", "go")
end


function handle_timer(arg)
  flussonic.log("handle_timer")
  if notify_timer then
    flussonic.cancel_timer(notify_timer)
    notify_timer = nil
  end

  
  local body = ""..flussonic.now().."\n"
  local dead_body = ""
  local dead_count = 0
  for name,flag in pairs(new_dead_streams) do
    dead_body = dead_body.."  "..name.."\n"
    old_streams[name] = flag
    dead_count = dead_count + 1
  end

  if dead_count > 0 then
    dead_body = "\nSource lost on following streams: \n"..dead_body
  end

  local restored_body = ""
  local restored_count = 0
  for name,flag in pairs(new_restored_streams) do
    delay = flag - old_streams[name]
    restored_body = restored_body.."  "..name.."  was down "..delay.."s\n"
    old_streams[name] = nil
    restored_count = restored_count + 1
  end

  if restored_count > 0 then
    restored_body = "\nSource restored on following streams: \n"..restored_body
  end

  new_dead_streams = {}
  new_restored_streams = {}

  url = "https://hooks.slack.com/services/M52ABDEC3/H9KC2POQV/KSA5b3QDn9kSJE7a"

  flussonic.log("notify about "..(restored_count+dead_count).." streams")

  if dead_count + restored_count > 0 then
    local delay = ""
    if last_notified_at then
      delay = (flussonic.now() - last_notified_at).." s since last notification\n"
    end
    local body = delay..dead_body..restored_body
    last_notified_at = flussonic.now()
    n = {text= body, username= "s04.peeklio.net" }
    http.post(url, {["content-type"] = "application/json"}, json.encode(n))
  end
end
