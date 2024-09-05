package app.abac

import rego.v1

default allow := false

allow if {
	input.action == "read"
	entitlement_exists
	# 	entitlement_is_valid
}

entitlement_exists if {
	some i
	print(data.entitlement_assignments[claims.sub])
	entitlement := data.entitlement_assignments[claims.sub][i].entitlement
	entitlement.product.type == input.resource
}

# entitlement_is_valid if {
# 	now := time.now_ns() / 1000000
# 	some i
# 	entitlement2 := data.entitlement_assignments[claims.sub][i].entitlement == entitlement2
# 	exp := parse_time(entitlement2.exp)
# 	exp > now
# }

parse_time(time_string) := t if {
	t := time.parse_rfc3339_ns(time_string) / 1000000
}

claims := payload if {

	io.jwt.verify_hs256(bearer_token, "qwfdqqwdqwdq")
	[_, payload, _] := io.jwt.decode(bearer_token)
}

bearer_token := t if {
	v := input.request.headers.authorization
	startswith(v, "Bearer ")
	t := substring(v, count("Bearer "), -1)
}
