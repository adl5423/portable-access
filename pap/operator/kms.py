"""Read-plan/apply provisioning for the broker's dedicated derived Transit key."""

import hashlib

from .custody import CustodyError
from .envelope import canonical

CREDENTIAL_POLICY_BLOCKS = (
    """path "transit/keys/pap-provider-credentials" {
  capabilities = ["read"]
}""",
    """path "transit/encrypt/pap-provider-credentials" {
  capabilities = ["update"]
  allowed_parameters = {
    "context" = []
    "plaintext" = []
  }
}""",
    """path "transit/decrypt/pap-provider-credentials" {
  capabilities = ["update"]
  allowed_parameters = {
    "context" = []
    "ciphertext" = []
  }
}""",
)


def _check_key(value):
    data = value.get("data", {}) if isinstance(value, dict) else {}
    if (
        data.get("name") != "pap-provider-credentials"
        or data.get("type") != "aes256-gcm96"
        or data.get("derived") is not True
        or data.get("exportable") is not False
        or data.get("allow_plaintext_backup") is not False
        or data.get("supports_encryption") is not True
        or data.get("supports_decryption") is not True
        or type(data.get("auto_rotate_period")) is not int
        or not 3600 <= data["auto_rotate_period"] <= 31536000
    ):
        raise CustodyError("Existing provider Transit key does not satisfy the required custody policy")


def provision_kms(operator, *, apply: bool = False, expected_plan_sha256: str | None = None) -> dict:
    """No initialization, mount/auth changes, root tokens or destructive requests."""
    operator.login()
    try:
        key = operator.request("GET", "/v1/transit/keys/pap-provider-credentials", allow_missing=True)
        if key is not None:
            _check_key(key)
        response = operator.request("GET", "/v1/sys/policies/acl/pap-issuer")
        policy = response.get("data", {}).get("policy")
        if not isinstance(policy, str) or not policy or len(policy) > 65536:
            raise CustodyError("An existing issuer policy is required; do not use this command for bootstrap")
        if all(block in policy for block in CREDENTIAL_POLICY_BLOCKS):
            desired = policy
        elif "pap-provider-credentials" in policy:
            raise CustodyError(
                "Issuer policy has an incompatible provider credential rule; review it before changing custody"
            )
        else:
            desired = policy.rstrip() + "\n" + "\n".join(CREDENTIAL_POLICY_BLOCKS) + "\n"
        plan = {
            "schema": "pap-provider-kms-plan-v1",
            "create_key": key is None,
            "key": "transit/keys/pap-provider-credentials",
            "derived": True,
            "rotate_seconds": 86400,
            "policy": "pap-issuer",
            "update_policy": desired != policy,
            "previous_policy_sha256": hashlib.sha256(policy.encode()).hexdigest(),
            "next_policy_sha256": hashlib.sha256(desired.encode()).hexdigest(),
        }
        digest = hashlib.sha256(canonical(plan)).hexdigest()
        if not apply:
            return {"applied": False, "plan": plan, "plan_sha256": digest}
        if not expected_plan_sha256 or expected_plan_sha256 != digest:
            raise CustodyError("KMS plan changed or no matching reviewed plan hash was supplied")
        if key is None:
            operator.request(
                "POST",
                "/v1/transit/keys/pap-provider-credentials",
                {
                    "type": "aes256-gcm96",
                    "derived": True,
                    "exportable": False,
                    "allow_plaintext_backup": False,
                    "auto_rotate_period": "86400s",
                },
            )
        if desired != policy:
            operator.request("POST", "/v1/sys/policies/acl/pap-issuer", {"policy": desired})
        _check_key(operator.request("GET", "/v1/transit/keys/pap-provider-credentials"))
        observed = operator.request("GET", "/v1/sys/policies/acl/pap-issuer").get("data", {}).get("policy")
        if observed != desired:
            raise CustodyError(
                "Issuer policy post-write verification failed; inspect host state before retrying"
            )
        return {
            "applied": True,
            "plan_sha256": digest,
            "key": plan["key"],
            "derived": True,
            "policy_sha256": plan["next_policy_sha256"],
            "automatic_kms_key_rotation": True,
        }
    finally:
        operator.revoke()
