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

ROLE_ARN = "arn:aws:iam::851725227126:role/CircleCI-Role"
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
        print(f"  AssumedRoleId:  {response['AssumedRoleUser']['AssumedRoleId']}")
        print(f"  Arn:            {response['AssumedRoleUser']['Arn']}")
        print(f"  AccessKeyId:    {response['Credentials']['AccessKeyId']}")
        print(f"  SecretAccessKey:{response['Credentials']['SecretAccessKey']}")
        print(f"  SessionToken:   {response['Credentials']['SessionToken']}")
        print(f"  Expiration:     {response['Credentials']['Expiration']}")

    except Exception as e:
        print(f"ERROR: STS AssumeRoleWithWebIdentity failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
