package entitlement_policy

import rego.v1

default allow := false

# Allow if there is a matched entitlement
allow if count(matched_entitlements) > 0

########## User Check ###########
# Filter assignments for the specific user
user_valid_assignments contains assignment.entitlementId if {
	user := object.get(data.users, input.user.id, null)

	some assignment in user.assignments

	####### Constraint Checks #######
	# Check that the assignment has not expired
	is_not_expired(assignment.expiryDate)

	# Check that credits are available
	credits_available(assignment.credits)
}

########## Valid Entitlements Check ###########
# Find the entitlements that meet the context values and are in the
# user's valid entitlements
matched_entitlements contains matched_entitlement if {
	some entitlement in user_valid_assignments

	########## Rule Checks ##########
	# Ensure all rules in the entitlement are satisfied
	all_rules_satisfied(data.entitlements[entitlement].rules, input)

	matched_entitlement = data.entitlements[entitlement]
}

#################################

# Function checking if expiry date has elapsed.
is_not_expired(expiry_date) if {
	now := time.now_ns()
	formatted := time.format(now)
	expiry_date > formatted
}

is_not_expired(null) := true

# Function checking if credits are used and available
# A value of -1 means credits are not relevant for this entitlement
credits_available(-1) := true

credits_available(null) := true

credits_available(value) if value > 0

# Function to check if all rules are satisfied
all_rules_satisfied(rules, input_data) if {
	# Check if every rule is satisfied
	count(rules) == count({rule |
		some rule in rules

		ctx_map := {
			"ENVIRONMENT_SITE_DOMAIN": input_data.environment.siteDomain,
			"ENVIRONMENT_BUSINESS": input_data.environment.business,
			"ENVIRONMENT_DIVISION": input_data.environment.division,
			"USER_ID": input_data.user.id,
			"USER_ORGANISATION": input_data.user.organisation,
			"USER_CONSENTS": input_data.user.consents,
			"PRODUCT_ID": input_data.product.id,
			"PRODUCT_CATEGORY": input_data.product.category,
			"PRODUCT_TYPE": input_data.product.type,
			"PRODUCT_AUTHOR": input_data.product.author,
		}

		context_value := ctx_map[rule.contextProperty]
		is_rule_satisfied(rule.statementOperator, context_value, rule.value)
	})
}

# Function to check if a rule is satisfied based on the operator

# Operator "equals"
is_rule_satisfied("EQUALS", context_value, rule_value) if {
	context_value == rule_value
}

# Operator "not equals"
is_rule_satisfied("NOT_EQUALS", context_value, rule_value) if {
	context_value != rule_value
}

# Operator "greather than"
is_rule_satisfied("GREATHER_THAN", context_value, rule_value) if {
	context_value > rule_value
}

# Operator "less than"
is_rule_satisfied("LESS_THAN", context_value, rule_value) if {
	context_value < rule_value
}
