-- rules/default.lua

-- create local variables
local key = request.key
local target = request.target
local type = request.meta["qtype"]

-- check the memory store for an existing record for request
local rec = Get(key)

-- log the first observance in the memory store
if rec == nil then
	local ok, err = Observe(
		request.kind,
		request.source,
		request.target,
		{
			note = "observed new contact",
		}
	)

	-- pass api errors back to the response manager
	if not ok then
		print("observe failed:", err)
		return {
			mode = "error",
			actions = {
				{ type = "log", args = { error = err, key = key, target = target }, },
				{ type = "print", args = { error = err, key = key, target = target }, },
			}
		}
	end

	-- return the default dynamic spoof response with a log entry
	return {
		mode = "spoof",
		response = {
			rcode = "NOERROR",
			rtype = type,
			provisioning = "dynamic"
		},
		actions = {
			{
				type = "log",
				args = {
					rule = "default",
					message = "first sighting",
					key = key,
					target = target,
					type = type,
				},
			},
			{
				type = "print",
				args = {
					rule = "default",
					message = "observed new contact",
					key = key,
					target = target,
					type = type,
				}
			},
		}
	}
else
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
			mode = "error",
			actions = {
				{ type = "log", args = { error = err, key = key, target = target }, },
				{ type = "print", args = { error = err, key = key, target = target }, },
			}
		}
	end

	-- return the default dynamic spoof response with a log entry
	return {
		mode = "spoof",
		response = {
			rcode = "NOERROR",
			rtype = type,
			provisioning = "dynamic"
		},
		actions = {
			{
				type = "log",
				args = {
					rule = "default",
					message = "repeat sighting",
					times_seen = rec.dns_queries,
					key = key,
					target = target
				},
			},
		}
	}
end