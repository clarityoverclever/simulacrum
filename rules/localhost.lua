-- rules/localhost.lua

local target = request.target
local key = request.key

print("using localhost rule")

if target == "ignore.localhost" then
	return {
		mode = "ignore",
		actions = {
		{
			type = "print",
			args = {
				message = "intentionally ignoring this record",
				key = key,
				target = target
			}
		}
	}
}
elseif target == "proxy.localhost" then
	return {
		mode = "proxy",
	}
elseif target == "txt.localhost" then
	return {
		mode = "spoof",
		response = {
			rcode = "NOERROR",
			rtype = "TXT",
			value = "hello from txt.localhost",
			provisioning = "none"
		},
		actions = {
			{
				type = "log",
				args = {
					message = "this is a tailored logged message",
					key = key,
					target = target
				},
			},
			{
				type = "print",
				args = {
					message = "this is a tailored printed message",
					key = key,
					target = target
				},
			},
		}
	}
elseif target == "static.localhost" then
	return {
		mode = "spoof",
		response = {
			rcode = "NOERROR",
			rtype = "A",
			provisioning = "static"
		},
		actions = {
			{
				type = "log",
				args = {
					message = "returned static A response",
					key = key,
					target = target
				}
			}
		}
	}
elseif target == "error.localhost" then
	print("observe failed:", err)
	return {
		mode = "error",
		actions = {
			{ type = "log", args = { error = err, key = key, target = target }, },
			{ type = "print", args = { error = err, key = key, target = target }, },
		}
	}
else
	return {
		mode = "spoof",
		response = {
			rcode = "NOERROR",
			rtype = "A",
			provisioning = "dynamic"
		},
		actions = {
			{
				type = "log",
				args = {
					message = "default localhost response is dynamic spoofing",
					key = key,
					target = target
				}
			}
		}
	}
end