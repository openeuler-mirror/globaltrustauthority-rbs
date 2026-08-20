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

# role/sub consistency: the `role` claim is attacker-controllable (it is
# signed with the subject's own per-user key), so a non-Administrator subject
# could mint role="admin" to reach Rust handlers that branch on
# `bearer.role == "admin"`. Reject any admin role that is not bound to the
# bootstrap Administrator principal. A non-admin role is always consistent.
check_role_admin_consistency {
    input.role != "admin"
}

check_role_admin_consistency {
    input.role == "admin"
    input.sub == "Administrator"
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
    check_role_admin_consistency
}

result = {"policy_matched": allow}
