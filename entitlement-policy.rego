package entitlement_policy

import rego.v1

default allow := false

# Allow if all rules are satisfied
allow if {
	some entitlement in data.static.entitlements

	########## Rule Checks ##########
	# Ensure all rules in the entitlement are satisfied
	all_rules_satisfied(entitlement.rules, input)

	#################################

	########## User Check ###########
	# Filter assignments for the specific user
	some assignment in entitlement.assignments
	assignment.userId == input.user.id

	####### Constraint Checks #######
	# Check that the assignment has not expired
	is_not_expired(assignment.constraintSet.expirydate)

	# Check that credits are available
	credits_available(assignment.constraintSet.credits)
	#################################
}

# Function checking if expiry date has elapsed.
is_not_expired(expiry_date) if {
	now := time.now_ns()
	formatted := time.format(now)
	expiry_date > formatted
}

# Function checking if credits are used and available
# A value of -1 means credits are not relevant for this entitlement
credits_available(-1) := true

credits_available(value) if value > 0

# Function to check if all rules are satisfied
all_rules_satisfied(rules, input_data) if {
	# Check if every rule is satisfied
	count(rules) == count({rule |
		some rule in rules

		ctx_map := {
			0: input_data.environment.siteDomain,
			1: input_data.environment.business,
			2: input_data.environment.division,
			3: input_data.user.id,
			4: input_data.user.organisation,
			5: input_data.user.consents,
			6: input_data.product.id,
			7: input_data.product.category,
			8: input_data.product.type,
			9: input_data.product.author,
		}

		context_value := ctx_map[rule.contextProperty]
		is_rule_satisfied(rule.statementOperator, context_value, rule.value)
	})
}

# Function to check if a rule is satisfied based on the operator

# Operator "equals"
is_rule_satisfied(0, context_value, rule_value) if {
	context_value == rule_value
}

# Operator "not equals"
is_rule_satisfied(1, context_value, rule_value) if {
	context_value != rule_value
}

# Operator "greather than"
is_rule_satisfied(2, context_value, rule_value) if {
	context_value > rule_value
}

# Operator "less than"
is_rule_satisfied(3, context_value, rule_value) if {
	context_value < rule_value
}
