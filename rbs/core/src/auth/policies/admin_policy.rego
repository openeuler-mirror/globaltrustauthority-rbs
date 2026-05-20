# Admin Authorization Policy
# Rego policy for admin operations

package verification

default allow = false

# Owner field absent → no ownership check needed
check_owner {
    not input.owner
}

# Owner field present → sub must match
check_owner {
    input.owner
    input.sub == input.owner
}

allow {
    input.token_type == "Bearer"
    input.required_role == "AdminOnly"
    input.role == "admin"
    input.sub == "Administrator"
    check_owner
}

allow {
    input.token_type == "Bearer"
    input.required_role == "UserScoped"
    check_owner
}

result = {"policy_matched": allow}
