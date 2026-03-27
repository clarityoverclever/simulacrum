-- responder_demo.lua

local key = request.key

-- Look up any existing record for this key
local rec = Get(key)

print("using default rule")
if rec == nil then
  print("no existing record for:", key)

  -- Record a first observation
  local ok, err = Observe(
    request.kind,
    request.source,
    request.target,
    {
      note = "first sighting",
      mode = "demo"
    }
  )

  if not ok then
    print("observe failed:", err)
    return {
      decision = "error",
      reason = err
    }
  end

  return {
    decision = "recorded",
    key = key
  }
else
  print("existing record found for:", rec.key)
  print("dns queries:", rec.dns_queries)

  -- Add another observation using the same request context
  local ok, err = Observe(
    request.kind,
    request.source,
    request.target,
    {
      note = "repeat sighting",
      previous_dns_queries = tostring(rec.dns_queries)
    }
  )

  if not ok then
    print("observe failed:", err)
    return {
      decision = "error",
      reason = err
    }
  end

  return {
    decision = "seen_before",
    key = rec.key,
    dns_queries = rec.dns_queries
  }
end