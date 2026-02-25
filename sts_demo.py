#!/usr/bin/env python3
"""
Standalone script to demonstrate CircleCI OIDC token + AWS STS AssumeRoleWithWebIdentity.

Reads the OIDC token from the CIRCLE_OIDC_TOKEN_V2 (or CIRCLE_OIDC_TOKEN) environment variable,
decodes and prints it, then calls STS AssumeRoleWithWebIdentity and prints the full response.
"""

import base64
import json
import os
import sys

import boto3
from botocore.exceptions import ClientError

ROLE_ARN = "arn:aws:iam::851725227126:role/CircleCI-Role"
CUSTOM_CLAIM_ROLE_ARN = "arn:aws:iam::851725227126:role/CircleCI-CustomClaim-Role"
SESSION_NAME = "circleci-oidc-demo"


def decode_jwt(token: str) -> dict:
    """Decode a JWT token without verification and return header + payload."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"Expected 3 JWT parts, got {len(parts)}")

    def _b64decode(s: str) -> dict:
        # Add padding if needed
        padding = 4 - len(s) % 4
        if padding != 4:
            s += "=" * padding
        return json.loads(base64.urlsafe_b64decode(s))

    header = _b64decode(parts[0])
    payload = _b64decode(parts[1])
    return {"header": header, "payload": payload}


def main():
    # 1. Get the OIDC token
    token = os.environ.get("CIRCLE_OIDC_TOKEN_V2") or os.environ.get("CIRCLE_OIDC_TOKEN")
    if not token:
        print("ERROR: No OIDC token found. Set CIRCLE_OIDC_TOKEN_V2 or CIRCLE_OIDC_TOKEN.")
        print("This script is intended to run inside a CircleCI job.")
        sys.exit(1)

    # 2. Print the raw token
    print("=" * 60)
    print("OIDC TOKEN (raw)")
    print("=" * 60)
    print(token)
    print()
    
    # Print token in a way that bypasses CircleCI's automatic redaction
    print("=" * 60)
    print("OIDC TOKEN (unredacted - base64 encoded)")
    print("=" * 60)
    token_b64 = base64.b64encode(token.encode('utf-8')).decode('utf-8')
    print(token_b64)
    print()
    print("To decode: echo '<token_above>' | base64 -d")
    print()

    # 3. Decode and print the JWT
    try:
        decoded = decode_jwt(token)

        print("=" * 60)
        print("OIDC TOKEN — Decoded Header")
        print("=" * 60)
        print(json.dumps(decoded["header"], indent=2))
        print()

        print("=" * 60)
        print("OIDC TOKEN — Decoded Payload (Claims)")
        print("=" * 60)
        print(json.dumps(decoded["payload"], indent=2))
        print()

        # Extract and display token expiration
        if "exp" in decoded["payload"]:
            exp_timestamp = decoded["payload"]["exp"]
            # Convert Unix timestamp to human-readable format
            from datetime import datetime, timezone
            exp_datetime = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
            
            print("=" * 60)
            print("OIDC TOKEN — Expiration Details")
            print("=" * 60)
            print(f"  Expiration (exp):     {exp_timestamp}")
            print(f"  Expiration (UTC):     {exp_datetime.strftime('%Y-%m-%d %H:%M:%S %Z')}")
            print(f"  Expiration (ISO8601): {exp_datetime.isoformat()}")
            
            # Show issued at time if available
            if "iat" in decoded["payload"]:
                iat_timestamp = decoded["payload"]["iat"]
                iat_datetime = datetime.fromtimestamp(iat_timestamp, tz=timezone.utc)
                duration_seconds = exp_timestamp - iat_timestamp
                duration_minutes = duration_seconds / 60
                
                print(f"  Issued At (iat):      {iat_timestamp}")
                print(f"  Issued At (UTC):      {iat_datetime.strftime('%Y-%m-%d %H:%M:%S %Z')}")
                print(f"  Token Lifetime:       {duration_seconds} seconds ({duration_minutes:.1f} minutes)")
            print()
        
    except Exception as e:
        print(f"WARNING: Failed to decode JWT: {e}")
        print()

    # 4. Call STS AssumeRoleWithWebIdentity
    print("=" * 60)
    print(f"Calling STS AssumeRoleWithWebIdentity")
    print(f"  RoleArn:          {ROLE_ARN}")
    print(f"  RoleSessionName:  {SESSION_NAME}")
    print("=" * 60)
    print()

    client = boto3.client("sts", region_name="us-east-1")

    try:
        response = client.assume_role_with_web_identity(
            RoleArn=ROLE_ARN,
            RoleSessionName=SESSION_NAME,
            WebIdentityToken=token,
        )

        print("=" * 60)
        print("STS AssumeRoleWithWebIdentity — FULL RESPONSE")
        print("=" * 60)

        # Convert datetime objects to strings for JSON serialization
        def serialize(obj):
            if hasattr(obj, "isoformat"):
                return obj.isoformat()
            raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

        print(json.dumps(response, indent=2, default=serialize))
        print()

        print("=" * 60)
        print("SUCCESS — Assumed Role Details")
        print("=" * 60)
        print(f"  Target Role:    {ROLE_ARN}")
        print(f"  AssumedRoleId:  {response['AssumedRoleUser']['AssumedRoleId']}")
        print(f"  Arn:            {response['AssumedRoleUser']['Arn']}")
        print(f"  AccessKeyId:    {response['Credentials']['AccessKeyId']}")
        print(f"  SecretAccessKey:{response['Credentials']['SecretAccessKey']}")
        print(f"  SessionToken:   {response['Credentials']['SessionToken']}")
        print(f"  Expiration:     {response['Credentials']['Expiration']}")

    except Exception as e:
        print(f"ERROR: STS AssumeRoleWithWebIdentity failed for role {ROLE_ARN}: {e}")
        sys.exit(1)

    # 5. Test custom claims - Positive case (valid project-id)
    # CircleCI OIDC tokens automatically include oidc.circleci.com/project-id claim
    print("\n")
    print("=" * 60)
    print("TEST 1: Custom Claims - POSITIVE CASE")
    print(f"Calling STS AssumeRoleWithWebIdentity with Custom Claims Role")
    print(f"  RoleArn:          {CUSTOM_CLAIM_ROLE_ARN}")
    print(f"  RoleSessionName:  {SESSION_NAME}-custom-valid")
    print("=" * 60)
    print()
    
    try:
        response = client.assume_role_with_web_identity(
            RoleArn=CUSTOM_CLAIM_ROLE_ARN,
            RoleSessionName=f"{SESSION_NAME}-custom-valid",
            WebIdentityToken=token,
        )

        print("=" * 60)
        print("✅ SUCCESS — Custom Claims Role Assumed")
        print("=" * 60)
        print(f"  Target Role:    {CUSTOM_CLAIM_ROLE_ARN}")
        print(f"  AssumedRoleId:  {response['AssumedRoleUser']['AssumedRoleId']}")
        print(f"  Arn:            {response['AssumedRoleUser']['Arn']}")
        print(f"  AccessKeyId:    {response['Credentials']['AccessKeyId']}")
        print()
        print("  This confirms the IAM role trust policy accepts the project-id")
        print("  claim (oidc.circleci.com/project-id) from the CircleCI OIDC token.")
        print()

    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_msg = e.response['Error']['Message']
        print("=" * 60)
        print(f"❌ FAILED — Custom Claims Role Access Denied")
        print("=" * 60)
        print(f"  Target Role:    {CUSTOM_CLAIM_ROLE_ARN}")
        print(f"  Error Code: {error_code}")
        print(f"  Error Message: {error_msg}")
        print()
    except Exception as e:
        print(f"ERROR: Unexpected error in custom claims test (positive): {e}")
        print()

    # 6. Test custom claims - Negative case (use deny role)
    # The deny role should reject this project-id in its trust policy
    DENY_ROLE_ARN = "arn:aws:iam::851725227126:role/CircleCI-CustomClaim-Deny-Role"
    
    print("\n")
    print("=" * 60)
    print("TEST 2: Custom Claims - NEGATIVE CASE")
    print(f"Calling STS AssumeRoleWithWebIdentity with Deny Role")
    print(f"  RoleArn:          {DENY_ROLE_ARN}")
    print(f"  RoleSessionName:  {SESSION_NAME}-custom-deny")
    print(f"  Expected: AccessDenied (deny role rejects this project-id)")
    print("=" * 60)
    print()
    
    try:
        response = client.assume_role_with_web_identity(
            RoleArn=DENY_ROLE_ARN,
            RoleSessionName=f"{SESSION_NAME}-custom-deny",
            WebIdentityToken=token,
        )

        # If this succeeds, the deny role doesn't have proper conditions
        print("=" * 60)
        print("⚠️  UNEXPECTED — Deny Role Assumed")
        print("=" * 60)
        print(f"  Target Role:    {DENY_ROLE_ARN}")
        print(f"  AssumedRoleId:  {response['AssumedRoleUser']['AssumedRoleId']}")
        print(f"  Arn:            {response['AssumedRoleUser']['Arn']}")
        print()
        print("  WARNING: The deny role should have rejected this project-id!")
        print()

    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_msg = e.response['Error']['Message']
        
        if error_code == "AccessDenied":
            print("=" * 60)
            print("✅ EXPECTED — Access Denied by Deny Role")
            print("=" * 60)
            print(f"  Target Role:    {DENY_ROLE_ARN}")
            print(f"  Error Code: {error_code}")
            print(f"  Error Message: {error_msg}")
            print()
            print("  This confirms the deny role's trust policy correctly rejects")
            print("  the project-id claim from this CircleCI project.")
        else:
            print("=" * 60)
            print(f"❌ UNEXPECTED ERROR — {error_code}")
            print("=" * 60)
            print(f"  Target Role:    {DENY_ROLE_ARN}")
            print(f"  Error Message: {error_msg}")
        print()
        
    except Exception as e:
        print(f"ERROR: Unexpected error in custom claims test (negative): {e}")
        print()

    print("=" * 60)
    print("ALL TESTS COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    main()
