# Admin Authorization Policy
# Rego policy for admin operations
# Rules:
# - AdminOnly: only admin role can execute
# - UserScoped: BearerToken is sufficient

package rbs.auth.admin

import future.keywords.if

default policy_matched = false

# AdminOnly: only admin can execute
policy_matched = true {
    input.token_type == "Bearer"
    input.required_role == "AdminOnly"
    input.role == "admin"
}

# UserScoped: BearerToken is sufficient
policy_matched = true {
    input.token_type == "Bearer"
    input.required_role == "UserScoped"
}

# Output result
result = {"policy_matched": policy_matched}
