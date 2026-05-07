# Admin Authorization Policy
# Rego policy for admin operations

package verification

default allow = false

allow {
    input.token_type == "Bearer"
    input.required_role == "AdminOnly"
    input.role == "admin"
}

allow {
    input.token_type == "Bearer"
    input.required_role == "UserScoped"
}

result = {"policy_matched": allow}