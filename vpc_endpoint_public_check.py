#!/usr/bin/env python3

"""
Control:
    VPC endpoint policy allows access only from trusted AWS accounts

Purpose:
    The endpoint policy is recorded separately.

    The main NetworkComplianceStatus answers:
        Can an untrusted account or external network practically reach
        and use this VPC endpoint based on network configuration?

Gateway endpoint checks:
    - S3 and DynamoDB gateway endpoints
    - Endpoint-associated route tables
    - Subnets actually using those route tables
    - AWS RAM shared-subnet participant accounts
    - Peering/TGW/VPN/DX are NOT treated as gateway-endpoint paths

Interface endpoint checks:
    - Endpoint ENI subnets
    - Actual route table for each endpoint subnet
    - Active cross-account VPC peering
    - Transit Gateway cross-account connectivity
    - AWS RAM shared subnets
    - VPN / virtual private gateway routes
    - Cloud WAN and Local Gateway route indicators
    - Endpoint security-group inbound rules
    - Matching route + matching security-group source correlation

Outputs:
    vpc_endpoint_network_access_<account>.csv
    vpc_endpoint_network_evidence_<account>.csv
"""

import argparse
import csv
import ipaddress
import json
import os
import re
import sys
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import unquote

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from tqdm import tqdm


# ============================================================
# CONSTANTS
# ============================================================

CONTROL_NAME = (
    "VPC endpoint policy allows access only from trusted AWS accounts"
)

ACTIVE_ENDPOINT_STATES = {
    "available",
    "pending",
    "pendingAcceptance",
}

ACCOUNT_ID_RE = re.compile(r"^\d{12}$")

ARN_ACCOUNT_RE = re.compile(
    r"^arn:(?:aws|aws-us-gov|aws-cn):[^:]*:[^:]*:(\d{12}):"
)

TRUST_CONDITION_KEYS = {
    "aws:principalaccount",
    "aws:principalarn",
    "aws:sourceaccount",
}

SUMMARY_FIELDS = [
    "Account",
    "Region",
    "Control",

    # Main result columns
    "NetworkComplianceStatus",
    "AccessibleByUntrustedSource",
    "NonComplianceReason",
    "RecommendedAction",

    # Endpoint identity
    "VpcEndpointId",
    "VpcEndpointArn",
    "EndpointName",
    "EndpointType",
    "GatewayService",
    "State",
    "VpcId",
    "ServiceName",

    # Clear network evidence
    "NetworkPathType",
    "UntrustedSourceAccount",
    "UntrustedSourceNetwork",
    "MatchingRoute",
    "PermittingSecurityGroupRule",
    "RouteValidationStatus",
    "SecurityGroupValidationStatus",
    "NetworkConfidence",

    # Gateway endpoint details
    "GatewayEndpointRouteTableIds",
    "GatewayEndpointEffectiveSubnetIds",
    "GatewayEndpointSharedSubnetAccounts",

    # Interface endpoint details
    "InterfaceEndpointSubnetIds",
    "InterfaceEndpointSecurityGroupIds",
    "InterfaceEndpointEniIds",

    # Policy shown separately
    "PolicyTechnicalStatus",
    "PolicyContainsWildcard",
    "PolicyUntrustedPrincipals",
    "PolicyFinding",

    # Supporting result
    "NetworkFinding",
    "EvaluationStatus",
    "Error",
]

EVIDENCE_FIELDS = [
    "Account",
    "Region",
    "VpcEndpointId",
    "EndpointType",
    "ServiceName",
    "NetworkComplianceStatus",
    "EvidenceType",
    "ResourceId",
    "SourceAccount",
    "SourceNetwork",
    "RouteTableId",
    "RouteDestination",
    "RouteTarget",
    "SecurityGroupId",
    "SecurityGroupRule",
    "Result",
    "Detail",
]


# ============================================================
# AUTHENTICATION
# ============================================================

def get_session(role_arn: Optional[str]) -> boto3.Session:
    if not role_arn:
        return boto3.Session()

    base_session = boto3.Session()
    sts = base_session.client("sts")

    response = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName="vpc-endpoint-network-access-audit",
    )

    credentials = response["Credentials"]

    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )


def get_account_id(session: boto3.Session) -> str:
    return session.client("sts").get_caller_identity()["Account"]


def get_partition(session: boto3.Session) -> str:
    region = session.region_name or "us-east-1"

    if region.startswith("cn-"):
        return "aws-cn"

    if region.startswith("us-gov-"):
        return "aws-us-gov"

    return "aws"


# ============================================================
# BASIC HELPERS
# ============================================================

def error_text(error: Exception) -> str:
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code", "ClientError")
        message = error.response.get("Error", {}).get(
            "Message",
            str(error),
        )
        return f"{code}: {message}"

    return f"{type(error).__name__}: {error}"


def normalize_list(value: Any) -> List[Any]:
    if value is None:
        return []

    if isinstance(value, list):
        return value

    return [value]


def unique_strings(values: Iterable[Any]) -> List[str]:
    output: List[str] = []
    seen: Set[str] = set()

    for value in values:
        if value is None:
            continue

        text = str(value).strip()

        if not text or text in seen:
            continue

        seen.add(text)
        output.append(text)

    return output


def join_values(values: Iterable[Any]) -> str:
    return "; ".join(unique_strings(values))


def json_text(value: Any) -> str:
    return json.dumps(
        value,
        separators=(",", ":"),
        sort_keys=True,
        default=str,
    )


def get_name_tag(resource: Dict[str, Any]) -> str:
    for tag in resource.get("Tags", []) or []:
        if tag.get("Key") == "Name":
            return tag.get("Value", "")

    return ""


def endpoint_arn(
    partition: str,
    region: str,
    account_id: str,
    endpoint_id: str,
) -> str:
    return (
        f"arn:{partition}:ec2:{region}:{account_id}:"
        f"vpc-endpoint/{endpoint_id}"
    )


def paginate_items(
    client: Any,
    operation_name: str,
    result_key: str,
    **kwargs: Any,
) -> List[Dict[str, Any]]:
    paginator = client.get_paginator(operation_name)
    output: List[Dict[str, Any]] = []

    for page in paginator.paginate(**kwargs):
        output.extend(page.get(result_key, []))

    return output


def get_enabled_regions(session: boto3.Session) -> List[str]:
    ec2 = session.client("ec2", region_name="us-east-1")

    response = ec2.describe_regions(AllRegions=True)

    return sorted(
        region["RegionName"]
        for region in response.get("Regions", [])
        if region.get("OptInStatus") in {
            "opt-in-not-required",
            "opted-in",
        }
    )


def parse_network(cidr: str) -> Optional[ipaddress._BaseNetwork]:
    try:
        return ipaddress.ip_network(cidr, strict=False)
    except (ValueError, TypeError):
        return None


def network_contains(
    covering_cidr: str,
    source_cidr: str,
) -> bool:
    covering = parse_network(covering_cidr)
    source = parse_network(source_cidr)

    if not covering or not source:
        return False

    return (
        covering.version == source.version
        and (
            source.subnet_of(covering)
            or source.overlaps(covering)
        )
    )


def is_broad_cidr(cidr: str) -> bool:
    network = parse_network(cidr)

    if not network:
        return False

    return (
        network == ipaddress.ip_network("0.0.0.0/0")
        or network == ipaddress.ip_network("::/0")
    )


def extract_account_from_arn(value: str) -> Optional[str]:
    value = value.strip()

    if ACCOUNT_ID_RE.fullmatch(value):
        return value

    match = ARN_ACCOUNT_RE.match(value)

    if match:
        return match.group(1)

    return None


def principal_is_trusted(
    principal: str,
    trusted_accounts: Set[str],
) -> bool:
    principal = principal.strip()

    if ACCOUNT_ID_RE.fullmatch(principal):
        return principal in trusted_accounts

    account = extract_account_from_arn(principal)

    if account:
        return account in trusted_accounts

    # Organization or OU ARNs cannot be safely resolved into all member
    # accounts without Organizations permissions.
    return False


# ============================================================
# POLICY INFORMATION
# ============================================================

def decode_policy(policy: Any) -> Dict[str, Any]:
    if not policy:
        return {}

    if isinstance(policy, dict):
        return policy

    if not isinstance(policy, str):
        raise ValueError(
            f"Unsupported policy type: {type(policy).__name__}"
        )

    candidates = [policy]

    decoded = unquote(policy)

    if decoded != policy:
        candidates.append(decoded)

    for candidate in candidates:
        try:
            value = json.loads(candidate)

            if isinstance(value, dict):
                return value
        except json.JSONDecodeError:
            continue

    raise ValueError("Endpoint policy could not be decoded as JSON")


def flatten_principal(principal: Any) -> List[Tuple[str, str]]:
    output: List[Tuple[str, str]] = []

    if principal is None:
        return output

    if isinstance(principal, str):
        return [("AWS", principal)]

    if isinstance(principal, list):
        for item in principal:
            output.extend(flatten_principal(item))

        return output

    if isinstance(principal, dict):
        for principal_type, values in principal.items():
            for value in normalize_list(values):
                output.append(
                    (str(principal_type), str(value))
                )

        return output

    return [("UNKNOWN", str(principal))]


def condition_account_restrictions(
    condition: Any,
) -> Tuple[Set[str], bool]:
    accounts: Set[str] = set()
    recognized = False

    if not isinstance(condition, dict):
        return accounts, recognized

    for operator, condition_block in condition.items():
        operator_text = str(operator).lower()

        # Negative conditions are not treated as a trusted allow-list.
        if "not" in operator_text:
            continue

        if not isinstance(condition_block, dict):
            continue

        for key, values in condition_block.items():
            key_lower = str(key).lower()

            if key_lower not in TRUST_CONDITION_KEYS:
                continue

            recognized = True

            for value in normalize_list(values):
                text = str(value)

                if key_lower in {
                    "aws:principalaccount",
                    "aws:sourceaccount",
                }:
                    if ACCOUNT_ID_RE.fullmatch(text):
                        accounts.add(text)

                elif key_lower == "aws:principalarn":
                    account = extract_account_from_arn(text)

                    if account:
                        accounts.add(account)

    return accounts, recognized


def evaluate_policy_information(
    policy_document: Dict[str, Any],
    trusted_accounts: Set[str],
) -> Dict[str, Any]:
    statements = normalize_list(
        policy_document.get("Statement")
    )

    wildcard = False
    untrusted_principals: List[str] = []
    complex_elements: List[str] = []
    allow_statement_seen = False

    for index, statement in enumerate(statements, start=1):
        if not isinstance(statement, dict):
            complex_elements.append(
                f"Statement {index} is not an object"
            )
            continue

        if str(statement.get("Effect", "")).lower() != "allow":
            continue

        allow_statement_seen = True

        if "NotPrincipal" in statement:
            complex_elements.append(
                f"Statement {index} uses NotPrincipal"
            )
            continue

        condition_accounts, recognized_condition = (
            condition_account_restrictions(
                statement.get("Condition", {})
            )
        )

        for principal_type, principal_value in flatten_principal(
            statement.get("Principal")
        ):
            if principal_type.lower() == "service":
                continue

            if principal_value == "*":
                wildcard = True

                if not (
                    recognized_condition
                    and condition_accounts
                    and condition_accounts.issubset(
                        trusted_accounts
                    )
                ):
                    untrusted_principals.append(
                        "Wildcard principal without a recognized "
                        "trusted-account restriction"
                    )

                continue

            account = extract_account_from_arn(
                principal_value
            )

            if account and account not in trusted_accounts:
                untrusted_principals.append(
                    principal_value
                )

            elif not account:
                complex_elements.append(
                    f"Principal could not be mapped to an account: "
                    f"{principal_value}"
                )

    if not allow_statement_seen:
        status = "REVIEW"
        finding = "No readable Allow statement was identified"

    elif untrusted_principals:
        status = "NON_COMPLIANT"
        finding = (
            "Policy permits wildcard or untrusted principals"
        )

    elif complex_elements:
        status = "REVIEW"
        finding = (
            "No confirmed untrusted principal found, but policy "
            "contains elements requiring manual review"
        )

    else:
        status = "COMPLIANT"
        finding = (
            "Policy principals are restricted to trusted accounts"
        )

    return {
        "Status": status,
        "Wildcard": wildcard,
        "UntrustedPrincipals": untrusted_principals,
        "ComplexElements": complex_elements,
        "Finding": finding,
    }


# ============================================================
# REGIONAL INVENTORY
# ============================================================

def load_inventory(
    ec2: Any,
) -> Tuple[Dict[str, Any], List[str]]:
    inventory: Dict[str, Any] = {
        "vpcs": {},
        "subnets": {},
        "route_tables": [],
        "security_groups": {},
        "peerings": [],
        "tgw_attachments": [],
        "tgw_vpc_attachments": [],
        "network_interfaces": {},
    }

    errors: List[str] = []

    operations = [
        ("describe_vpcs", "Vpcs", "vpcs"),
        ("describe_subnets", "Subnets", "subnets"),
        (
            "describe_route_tables",
            "RouteTables",
            "route_tables",
        ),
        (
            "describe_security_groups",
            "SecurityGroups",
            "security_groups",
        ),
        (
            "describe_vpc_peering_connections",
            "VpcPeeringConnections",
            "peerings",
        ),
        (
            "describe_transit_gateway_attachments",
            "TransitGatewayAttachments",
            "tgw_attachments",
        ),
        (
            "describe_transit_gateway_vpc_attachments",
            "TransitGatewayVpcAttachments",
            "tgw_vpc_attachments",
        ),
        (
            "describe_network_interfaces",
            "NetworkInterfaces",
            "network_interfaces",
        ),
    ]

    for operation, result_key, inventory_key in operations:
        try:
            items = paginate_items(
                ec2,
                operation,
                result_key,
            )

            if inventory_key == "vpcs":
                inventory[inventory_key] = {
                    item["VpcId"]: item
                    for item in items
                }

            elif inventory_key == "subnets":
                inventory[inventory_key] = {
                    item["SubnetId"]: item
                    for item in items
                }

            elif inventory_key == "security_groups":
                inventory[inventory_key] = {
                    item["GroupId"]: item
                    for item in items
                }

            elif inventory_key == "network_interfaces":
                inventory[inventory_key] = {
                    item["NetworkInterfaceId"]: item
                    for item in items
                }

            else:
                inventory[inventory_key] = items

        except (ClientError, BotoCoreError) as error:
            errors.append(
                f"{operation}: {error_text(error)}"
            )

    return inventory, errors


# ============================================================
# AWS RAM SHARED SUBNETS
# ============================================================

def get_shared_subnet_principals(
    session: boto3.Session,
    region: str,
) -> Tuple[Dict[str, Set[str]], List[str]]:
    output: Dict[str, Set[str]] = defaultdict(set)
    errors: List[str] = []

    try:
        ram = session.client("ram", region_name=region)

        shares = paginate_items(
            ram,
            "get_resource_shares",
            "resourceShares",
            resourceOwner="SELF",
            resourceShareStatus="ACTIVE",
        )

        for share in shares:
            share_arn = share.get("resourceShareArn")

            if not share_arn:
                continue

            try:
                resources = paginate_items(
                    ram,
                    "list_resources",
                    "resources",
                    resourceOwner="SELF",
                    resourceShareArns=[share_arn],
                )

                principals = paginate_items(
                    ram,
                    "list_principals",
                    "principals",
                    resourceOwner="SELF",
                    resourceShareArns=[share_arn],
                )

                principal_ids = {
                    str(principal.get("id"))
                    for principal in principals
                    if principal.get("id")
                }

                for resource in resources:
                    arn = resource.get("arn", "")

                    if ":subnet/" not in arn:
                        continue

                    subnet_id = arn.rsplit("/", 1)[-1]
                    output[subnet_id].update(principal_ids)

            except (ClientError, BotoCoreError) as error:
                errors.append(
                    f"RAM share {share_arn}: "
                    f"{error_text(error)}"
                )

    except (ClientError, BotoCoreError) as error:
        errors.append(
            f"AWS RAM: {error_text(error)}"
        )

    return dict(output), errors


# ============================================================
# ROUTE TABLE HELPERS
# ============================================================

def route_destination(route: Dict[str, Any]) -> str:
    return (
        route.get("DestinationCidrBlock")
        or route.get("DestinationIpv6CidrBlock")
        or route.get("DestinationPrefixListId")
        or ""
    )


def route_target(
    route: Dict[str, Any],
) -> Tuple[str, str]:
    if route.get("VpcPeeringConnectionId"):
        return (
            "VPC_PEERING",
            route["VpcPeeringConnectionId"],
        )

    if route.get("TransitGatewayId"):
        return (
            "TRANSIT_GATEWAY",
            route["TransitGatewayId"],
        )

    gateway_id = route.get("GatewayId", "")

    if gateway_id.startswith("vgw-"):
        return (
            "VIRTUAL_PRIVATE_GATEWAY",
            gateway_id,
        )

    if route.get("CoreNetworkArn"):
        return (
            "CLOUD_WAN",
            route["CoreNetworkArn"],
        )

    if route.get("LocalGatewayId"):
        return (
            "LOCAL_GATEWAY",
            route["LocalGatewayId"],
        )

    if route.get("VpcEndpointId"):
        return (
            "VPC_ENDPOINT",
            route["VpcEndpointId"],
        )

    if gateway_id == "local":
        return ("LOCAL", "local")

    return ("OTHER", gateway_id)


def resolve_main_route_table(
    route_tables: List[Dict[str, Any]],
    vpc_id: str,
) -> Optional[Dict[str, Any]]:
    for route_table in route_tables:
        if route_table.get("VpcId") != vpc_id:
            continue

        for association in route_table.get(
            "Associations",
            [],
        ) or []:
            if association.get("Main"):
                return route_table

    return None


def resolve_subnet_route_table(
    route_tables: List[Dict[str, Any]],
    vpc_id: str,
    subnet_id: str,
) -> Optional[Dict[str, Any]]:
    for route_table in route_tables:
        if route_table.get("VpcId") != vpc_id:
            continue

        for association in route_table.get(
            "Associations",
            [],
        ) or []:
            if association.get("SubnetId") == subnet_id:
                return route_table

    return resolve_main_route_table(
        route_tables,
        vpc_id,
    )


def endpoint_subnet_route_tables(
    route_tables: List[Dict[str, Any]],
    vpc_id: str,
    subnet_ids: List[str],
) -> List[Dict[str, Any]]:
    output: Dict[str, Dict[str, Any]] = {}

    for subnet_id in subnet_ids:
        route_table = resolve_subnet_route_table(
            route_tables,
            vpc_id,
            subnet_id,
        )

        if route_table and route_table.get("RouteTableId"):
            output[route_table["RouteTableId"]] = route_table

    return list(output.values())


def subnet_ids_using_route_table(
    route_tables: List[Dict[str, Any]],
    subnets: Dict[str, Dict[str, Any]],
    vpc_id: str,
    route_table_id: str,
) -> List[str]:
    target_route_table = next(
        (
            route_table
            for route_table in route_tables
            if route_table.get("RouteTableId")
            == route_table_id
        ),
        None,
    )

    if not target_route_table:
        return []

    explicit_subnets = {
        association.get("SubnetId")
        for association in target_route_table.get(
            "Associations",
            [],
        ) or []
        if association.get("SubnetId")
    }

    is_main = any(
        association.get("Main")
        for association in target_route_table.get(
            "Associations",
            [],
        ) or []
    )

    if not is_main:
        return sorted(explicit_subnets)

    all_vpc_subnets = {
        subnet_id
        for subnet_id, subnet in subnets.items()
        if subnet.get("VpcId") == vpc_id
    }

    subnets_with_explicit_association: Set[str] = set()

    for route_table in route_tables:
        if route_table.get("VpcId") != vpc_id:
            continue

        for association in route_table.get(
            "Associations",
            [],
        ) or []:
            subnet_id = association.get("SubnetId")

            if subnet_id:
                subnets_with_explicit_association.add(
                    subnet_id
                )

    main_table_subnets = (
        all_vpc_subnets
        - subnets_with_explicit_association
    )

    return sorted(
        explicit_subnets | main_table_subnets
    )


# ============================================================
# GATEWAY ENDPOINT EVALUATION
# ============================================================

def identify_gateway_service(
    service_name: str,
) -> str:
    lower = service_name.lower()

    if lower.endswith(".s3"):
        return "S3"

    if lower.endswith(".dynamodb"):
        return "DynamoDB"

    return "Other Gateway Service"


def evaluate_gateway_endpoint(
    endpoint: Dict[str, Any],
    inventory: Dict[str, Any],
    shared_subnets: Dict[str, Set[str]],
    trusted_accounts: Set[str],
) -> Dict[str, Any]:
    vpc_id = endpoint.get("VpcId", "")
    route_table_ids = endpoint.get(
        "RouteTableIds",
        [],
    ) or []

    effective_subnet_ids: Set[str] = set()
    untrusted_shares: List[Dict[str, str]] = []
    evidence: List[Dict[str, Any]] = []

    for route_table_id in route_table_ids:
        subnet_ids = subnet_ids_using_route_table(
            inventory["route_tables"],
            inventory["subnets"],
            vpc_id,
            route_table_id,
        )

        effective_subnet_ids.update(subnet_ids)

        evidence.append({
            "EvidenceType": "GATEWAY_ROUTE_TABLE",
            "ResourceId": route_table_id,
            "SourceAccount": "",
            "SourceNetwork": "",
            "RouteTableId": route_table_id,
            "RouteDestination": "",
            "RouteTarget": endpoint.get(
                "VpcEndpointId",
                "",
            ),
            "SecurityGroupId": "",
            "SecurityGroupRule": "",
            "Result": "CHECKED",
            "Detail": (
                f"Gateway endpoint route table is used by "
                f"{len(subnet_ids)} subnet(s)"
            ),
        })

    for subnet_id in sorted(effective_subnet_ids):
        for principal in shared_subnets.get(
            subnet_id,
            set(),
        ):
            if principal_is_trusted(
                principal,
                trusted_accounts,
            ):
                continue

            item = {
                "SubnetId": subnet_id,
                "Principal": principal,
            }

            untrusted_shares.append(item)

            evidence.append({
                "EvidenceType": "UNTRUSTED_SHARED_SUBNET",
                "ResourceId": subnet_id,
                "SourceAccount": principal,
                "SourceNetwork": "",
                "RouteTableId": "",
                "RouteDestination": "",
                "RouteTarget": "",
                "SecurityGroupId": "",
                "SecurityGroupRule": "",
                "Result": "ACCESSIBLE",
                "Detail": (
                    "Subnet using the gateway endpoint route "
                    "table is shared with an untrusted principal"
                ),
            })

    gateway_service = identify_gateway_service(
        endpoint.get("ServiceName", "")
    )

    if not route_table_ids:
        return {
            "Status": "REVIEW",
            "Accessible": "UNDETERMINED",
            "Reason": (
                "Gateway endpoint has no readable associated "
                "route-table IDs"
            ),
            "RecommendedAction": (
                "Verify the gateway endpoint route-table associations"
            ),
            "PathType": "GATEWAY_ROUTE_TABLE",
            "SourceAccount": "",
            "SourceNetwork": "",
            "MatchingRoute": "",
            "PermittingSgRule": "Not applicable",
            "RouteValidation": "UNDETERMINED",
            "SgValidation": "NOT_APPLICABLE",
            "Confidence": "LOW",
            "Finding": (
                f"{gateway_service} gateway endpoint could not "
                f"be fully evaluated"
            ),
            "EffectiveSubnetIds": sorted(
                effective_subnet_ids
            ),
            "SharedAccounts": untrusted_shares,
            "Evidence": evidence,
        }

    if untrusted_shares:
        accounts = unique_strings(
            item["Principal"]
            for item in untrusted_shares
        )

        return {
            "Status": "NON_COMPLIANT",
            "Accessible": "YES",
            "Reason": (
                f"{gateway_service} gateway endpoint route tables "
                f"serve subnets shared with untrusted account(s): "
                f"{join_values(accounts)}"
            ),
            "RecommendedAction": (
                "Remove untrusted subnet sharing, restrict the "
                "endpoint policy to approved accounts, or document "
                "the participant accounts as trusted"
            ),
            "PathType": "SHARED_VPC_SUBNET",
            "SourceAccount": join_values(accounts),
            "SourceNetwork": "",
            "MatchingRoute": (
                "Gateway endpoint associated route table"
            ),
            "PermittingSgRule": (
                "Not applicable to gateway endpoints"
            ),
            "RouteValidation": "CONFIRMED",
            "SgValidation": "NOT_APPLICABLE",
            "Confidence": "HIGH",
            "Finding": (
                "An untrusted participant account can deploy "
                "resources into a subnet that uses the gateway "
                "endpoint route table"
            ),
            "EffectiveSubnetIds": sorted(
                effective_subnet_ids
            ),
            "SharedAccounts": untrusted_shares,
            "Evidence": evidence,
        }

    return {
        "Status": "COMPLIANT",
        "Accessible": "NO",
        "Reason": (
            f"No untrusted account was found in subnets using "
            f"the {gateway_service} gateway endpoint route tables"
        ),
        "RecommendedAction": (
            "No network remediation required. The wildcard "
            "endpoint policy should still be handled separately."
        ),
        "PathType": "GATEWAY_ROUTE_TABLE",
        "SourceAccount": "",
        "SourceNetwork": "",
        "MatchingRoute": (
            "Endpoint route-table associations checked"
        ),
        "PermittingSgRule": (
            "Not applicable to gateway endpoints"
        ),
        "RouteValidation": "CONFIRMED",
        "SgValidation": "NOT_APPLICABLE",
        "Confidence": "HIGH",
        "Finding": (
            f"{gateway_service} gateway endpoint is limited to "
            f"resources in the endpoint VPC and no untrusted "
            f"shared-subnet participant was identified"
        ),
        "EffectiveSubnetIds": sorted(
            effective_subnet_ids
        ),
        "SharedAccounts": [],
        "Evidence": evidence,
    }


# ============================================================
# INTERFACE PATH DISCOVERY
# ============================================================

def remote_vpc_cidrs(
    vpc_info: Dict[str, Any],
) -> List[str]:
    cidrs: List[str] = []

    if vpc_info.get("CidrBlock"):
        cidrs.append(vpc_info["CidrBlock"])

    for association in (
        vpc_info.get("Ipv6CidrBlockSet", [])
        or vpc_info.get(
            "Ipv6CidrBlockAssociationSet",
            [],
        )
        or []
    ):
        cidr = association.get("Ipv6CidrBlock")

        if cidr:
            cidrs.append(cidr)

    return unique_strings(cidrs)


def discover_peering_paths(
    endpoint_vpc_id: str,
    peerings: List[Dict[str, Any]],
    trusted_accounts: Set[str],
) -> List[Dict[str, Any]]:
    paths: List[Dict[str, Any]] = []

    for peering in peerings:
        if peering.get(
            "Status",
            {},
        ).get("Code") != "active":
            continue

        requester = peering.get(
            "RequesterVpcInfo",
            {},
        )
        accepter = peering.get(
            "AccepterVpcInfo",
            {},
        )

        if requester.get("VpcId") == endpoint_vpc_id:
            remote = accepter

        elif accepter.get("VpcId") == endpoint_vpc_id:
            remote = requester

        else:
            continue

        remote_account = remote.get("OwnerId", "")

        if (
            remote_account
            and remote_account in trusted_accounts
        ):
            continue

        paths.append({
            "PathType": "VPC_PEERING",
            "ConnectionId": peering.get(
                "VpcPeeringConnectionId",
                "",
            ),
            "SourceAccount": (
                remote_account or "UNKNOWN"
            ),
            "SourceNetworks": remote_vpc_cidrs(
                remote
            ),
            "RemoteVpcId": remote.get("VpcId", ""),
        })

    return paths


def discover_shared_subnet_paths(
    endpoint: Dict[str, Any],
    inventory: Dict[str, Any],
    shared_subnets: Dict[str, Set[str]],
    trusted_accounts: Set[str],
) -> List[Dict[str, Any]]:
    paths: List[Dict[str, Any]] = []

    for subnet_id in endpoint.get(
        "SubnetIds",
        [],
    ) or []:
        subnet = inventory["subnets"].get(
            subnet_id,
            {},
        )

        subnet_cidr = subnet.get("CidrBlock", "")

        for principal in shared_subnets.get(
            subnet_id,
            set(),
        ):
            if principal_is_trusted(
                principal,
                trusted_accounts,
            ):
                continue

            paths.append({
                "PathType": "SHARED_VPC_SUBNET",
                "ConnectionId": subnet_id,
                "SourceAccount": principal,
                "SourceNetworks": (
                    [subnet_cidr]
                    if subnet_cidr
                    else []
                ),
                "RemoteVpcId": endpoint.get(
                    "VpcId",
                    "",
                ),
            })

    return paths


def endpoint_tgw_ids(
    endpoint_vpc_id: str,
    inventory: Dict[str, Any],
) -> Set[str]:
    output: Set[str] = set()

    for attachment in inventory.get(
        "tgw_vpc_attachments",
        [],
    ):
        if attachment.get("VpcId") != endpoint_vpc_id:
            continue

        if attachment.get("State") not in {
            "available",
            "pending",
            "modifying",
        }:
            continue

        tgw_id = attachment.get(
            "TransitGatewayId"
        )

        if tgw_id:
            output.add(tgw_id)

    return output


def discover_tgw_paths(
    endpoint_vpc_id: str,
    endpoint_route_table_list: List[Dict[str, Any]],
    inventory: Dict[str, Any],
    trusted_accounts: Set[str],
) -> List[Dict[str, Any]]:
    paths: List[Dict[str, Any]] = []

    attached_tgws = endpoint_tgw_ids(
        endpoint_vpc_id,
        inventory,
    )

    if not attached_tgws:
        return paths

    untrusted_tgws: Set[str] = set()

    for attachment in inventory.get(
        "tgw_attachments",
        [],
    ):
        tgw_id = attachment.get(
            "TransitGatewayId",
            "",
        )

        if tgw_id not in attached_tgws:
            continue

        if attachment.get("State") not in {
            "available",
            "pending",
            "modifying",
            "initiatingRequest",
        }:
            continue

        resource_owner = attachment.get(
            "ResourceOwnerId",
            "",
        )
        tgw_owner = attachment.get(
            "TransitGatewayOwnerId",
            "",
        )

        if (
            resource_owner
            and resource_owner not in trusted_accounts
        ) or (
            tgw_owner
            and tgw_owner not in trusted_accounts
        ):
            untrusted_tgws.add(tgw_id)

    for route_table in endpoint_route_table_list:
        for route in route_table.get(
            "Routes",
            [],
        ) or []:
            if route.get("State") == "blackhole":
                continue

            tgw_id = route.get("TransitGatewayId")

            if tgw_id not in untrusted_tgws:
                continue

            destination = route_destination(route)

            if not parse_network(destination):
                continue

            paths.append({
                "PathType": "TRANSIT_GATEWAY",
                "ConnectionId": tgw_id,
                "SourceAccount": "UNTRUSTED_OR_EXTERNAL",
                "SourceNetworks": [destination],
                "RemoteVpcId": "",
            })

    return paths


def discover_external_gateway_paths(
    endpoint_route_table_list: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    paths: List[Dict[str, Any]] = []

    for route_table in endpoint_route_table_list:
        for route in route_table.get(
            "Routes",
            [],
        ) or []:
            if route.get("State") == "blackhole":
                continue

            target_type, target_id = route_target(
                route
            )

            if target_type not in {
                "VIRTUAL_PRIVATE_GATEWAY",
                "CLOUD_WAN",
                "LOCAL_GATEWAY",
            }:
                continue

            destination = route_destination(route)

            if not parse_network(destination):
                continue

            paths.append({
                "PathType": target_type,
                "ConnectionId": target_id,
                "SourceAccount": "EXTERNAL_NETWORK",
                "SourceNetworks": [destination],
                "RemoteVpcId": "",
            })

    return paths


# ============================================================
# ROUTE CORRELATION
# ============================================================

def find_matching_route(
    path: Dict[str, Any],
    endpoint_route_table_list: List[Dict[str, Any]],
) -> List[Dict[str, str]]:
    path_type = path.get("PathType")
    connection_id = path.get("ConnectionId")
    source_networks = path.get(
        "SourceNetworks",
        [],
    )

    # A shared-subnet participant is already local to the VPC.
    if path_type == "SHARED_VPC_SUBNET":
        return [{
            "RouteTableId": "LOCAL",
            "Destination": join_values(source_networks),
            "Target": "local",
        }]

    expected_target_type = path_type

    matches: List[Dict[str, str]] = []

    for route_table in endpoint_route_table_list:
        route_table_id = route_table.get(
            "RouteTableId",
            "",
        )

        for route in route_table.get(
            "Routes",
            [],
        ) or []:
            if route.get("State") == "blackhole":
                continue

            target_type, target_id = route_target(
                route
            )

            if target_type != expected_target_type:
                continue

            if (
                connection_id
                and target_id != connection_id
            ):
                continue

            destination = route_destination(route)

            for source_network in source_networks:
                if network_contains(
                    destination,
                    source_network,
                ):
                    matches.append({
                        "RouteTableId": route_table_id,
                        "Destination": destination,
                        "Target": target_id,
                    })

    return matches


# ============================================================
# SECURITY GROUP CORRELATION
# ============================================================

def permission_allows_endpoint_port(
    permission: Dict[str, Any],
    endpoint_port: int,
) -> bool:
    protocol = str(
        permission.get("IpProtocol", "")
    ).lower()

    if protocol == "-1":
        return True

    if protocol not in {"6", "tcp"}:
        return False

    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")

    if from_port is None or to_port is None:
        return True

    return (
        int(from_port)
        <= endpoint_port
        <= int(to_port)
    )


def security_group_rule_text(
    group_id: str,
    permission: Dict[str, Any],
    source: str,
) -> str:
    protocol = permission.get(
        "IpProtocol",
        "",
    )
    from_port = permission.get(
        "FromPort",
        "ALL",
    )
    to_port = permission.get(
        "ToPort",
        "ALL",
    )

    return (
        f"{group_id}: protocol={protocol}, "
        f"ports={from_port}-{to_port}, "
        f"source={source}"
    )


def find_permitting_sg_rules(
    group_ids: List[str],
    security_groups: Dict[str, Dict[str, Any]],
    path: Dict[str, Any],
    trusted_accounts: Set[str],
    endpoint_port: int,
) -> Tuple[List[str], List[str], bool]:
    """
    Returns:
        matching rules,
        broad rules,
        whether any security group could not be read.
    """
    matching_rules: List[str] = []
    broad_rules: List[str] = []
    missing_group = False

    source_networks = path.get(
        "SourceNetworks",
        [],
    )
    source_account = path.get(
        "SourceAccount",
        "",
    )

    for group_id in group_ids:
        group = security_groups.get(group_id)

        if not group:
            missing_group = True
            continue

        for permission in group.get(
            "IpPermissions",
            [],
        ) or []:
            if not permission_allows_endpoint_port(
                permission,
                endpoint_port,
            ):
                continue

            for item in permission.get(
                "IpRanges",
                [],
            ) or []:
                rule_cidr = item.get("CidrIp", "")

                rule_text = security_group_rule_text(
                    group_id,
                    permission,
                    rule_cidr,
                )

                if is_broad_cidr(rule_cidr):
                    broad_rules.append(rule_text)

                for source_network in source_networks:
                    if network_contains(
                        rule_cidr,
                        source_network,
                    ):
                        matching_rules.append(
                            rule_text
                        )

            for item in permission.get(
                "Ipv6Ranges",
                [],
            ) or []:
                rule_cidr = item.get(
                    "CidrIpv6",
                    "",
                )

                rule_text = security_group_rule_text(
                    group_id,
                    permission,
                    rule_cidr,
                )

                if is_broad_cidr(rule_cidr):
                    broad_rules.append(rule_text)

                for source_network in source_networks:
                    if network_contains(
                        rule_cidr,
                        source_network,
                    ):
                        matching_rules.append(
                            rule_text
                        )

            for pair in permission.get(
                "UserIdGroupPairs",
                [],
            ) or []:
                pair_account = pair.get(
                    "UserId",
                    "",
                )
                pair_group = pair.get(
                    "GroupId",
                    "",
                )

                rule_text = security_group_rule_text(
                    group_id,
                    permission,
                    (
                        f"{pair_group}@"
                        f"{pair_account or 'unknown'}"
                    ),
                )

                if (
                    pair_account
                    and pair_account
                    == source_account
                    and pair_account
                    not in trusted_accounts
                ):
                    matching_rules.append(
                        rule_text
                    )

    return (
        unique_strings(matching_rules),
        unique_strings(broad_rules),
        missing_group,
    )


# ============================================================
# INTERFACE ENDPOINT EVALUATION
# ============================================================

def evaluate_interface_endpoint(
    endpoint: Dict[str, Any],
    inventory: Dict[str, Any],
    shared_subnets: Dict[str, Set[str]],
    trusted_accounts: Set[str],
    endpoint_port: int,
) -> Dict[str, Any]:
    vpc_id = endpoint.get("VpcId", "")
    subnet_ids = endpoint.get(
        "SubnetIds",
        [],
    ) or []

    group_ids = [
        group.get("GroupId")
        for group in endpoint.get(
            "Groups",
            [],
        ) or []
        if group.get("GroupId")
    ]

    endpoint_route_tables_list = (
        endpoint_subnet_route_tables(
            inventory["route_tables"],
            vpc_id,
            subnet_ids,
        )
    )

    candidate_paths: List[Dict[str, Any]] = []

    candidate_paths.extend(
        discover_shared_subnet_paths(
            endpoint,
            inventory,
            shared_subnets,
            trusted_accounts,
        )
    )

    candidate_paths.extend(
        discover_peering_paths(
            vpc_id,
            inventory["peerings"],
            trusted_accounts,
        )
    )

    candidate_paths.extend(
        discover_tgw_paths(
            vpc_id,
            endpoint_route_tables_list,
            inventory,
            trusted_accounts,
        )
    )

    candidate_paths.extend(
        discover_external_gateway_paths(
            endpoint_route_tables_list
        )
    )

    evidence: List[Dict[str, Any]] = []
    confirmed_access_paths: List[Dict[str, Any]] = []
    unresolved_paths: List[Dict[str, Any]] = []
    broad_sg_rules_seen: List[str] = []

    for path in candidate_paths:
        matching_routes = find_matching_route(
            path,
            endpoint_route_tables_list,
        )

        matching_sg_rules, broad_sg_rules, missing_sg = (
            find_permitting_sg_rules(
                group_ids,
                inventory["security_groups"],
                path,
                trusted_accounts,
                endpoint_port,
            )
        )

        broad_sg_rules_seen.extend(
            broad_sg_rules
        )

        if matching_routes and matching_sg_rules:
            confirmed = {
                **path,
                "Routes": matching_routes,
                "SecurityGroupRules": (
                    matching_sg_rules
                ),
            }

            confirmed_access_paths.append(
                confirmed
            )

            for matching_route in matching_routes:
                evidence.append({
                    "EvidenceType": (
                        "CONFIRMED_UNTRUSTED_ACCESS_PATH"
                    ),
                    "ResourceId": path.get(
                        "ConnectionId",
                        "",
                    ),
                    "SourceAccount": path.get(
                        "SourceAccount",
                        "",
                    ),
                    "SourceNetwork": join_values(
                        path.get(
                            "SourceNetworks",
                            [],
                        )
                    ),
                    "RouteTableId": (
                        matching_route["RouteTableId"]
                    ),
                    "RouteDestination": (
                        matching_route["Destination"]
                    ),
                    "RouteTarget": (
                        matching_route["Target"]
                    ),
                    "SecurityGroupId": "",
                    "SecurityGroupRule": join_values(
                        matching_sg_rules
                    ),
                    "Result": "ACCESSIBLE",
                    "Detail": (
                        "Both route and endpoint security-group "
                        "conditions permit the identified source"
                    ),
                })

        elif missing_sg:
            unresolved_paths.append({
                **path,
                "Reason": (
                    "One or more endpoint security groups "
                    "could not be read"
                ),
            })

        else:
            evidence.append({
                "EvidenceType": "BLOCKED_OR_INCOMPLETE_PATH",
                "ResourceId": path.get(
                    "ConnectionId",
                    "",
                ),
                "SourceAccount": path.get(
                    "SourceAccount",
                    "",
                ),
                "SourceNetwork": join_values(
                    path.get(
                        "SourceNetworks",
                        [],
                    )
                ),
                "RouteTableId": join_values(
                    route["RouteTableId"]
                    for route in matching_routes
                ),
                "RouteDestination": join_values(
                    route["Destination"]
                    for route in matching_routes
                ),
                "RouteTarget": join_values(
                    route["Target"]
                    for route in matching_routes
                ),
                "SecurityGroupId": "",
                "SecurityGroupRule": join_values(
                    matching_sg_rules
                ),
                "Result": "NOT_CONFIRMED",
                "Detail": (
                    "Path was not considered accessible because "
                    "both a matching route and permitting endpoint "
                    "security-group rule were not present"
                ),
            })

    if confirmed_access_paths:
        first = confirmed_access_paths[0]

        route_descriptions: List[str] = []

        for route in first["Routes"]:
            route_descriptions.append(
                f"{route['RouteTableId']}:"
                f"{route['Destination']} -> "
                f"{route['Target']}"
            )

        return {
            "Status": "NON_COMPLIANT",
            "Accessible": "YES",
            "Reason": (
                f"Interface endpoint is reachable from an "
                f"untrusted source through "
                f"{first['PathType']}; a matching route and "
                f"endpoint security-group rule were confirmed"
            ),
            "RecommendedAction": (
                "Restrict the endpoint security-group source, "
                "remove the untrusted network route/attachment, "
                "or add the approved account to the trusted list"
            ),
            "PathType": first["PathType"],
            "SourceAccount": first.get(
                "SourceAccount",
                "",
            ),
            "SourceNetwork": join_values(
                first.get("SourceNetworks", [])
            ),
            "MatchingRoute": join_values(
                route_descriptions
            ),
            "PermittingSgRule": join_values(
                first["SecurityGroupRules"]
            ),
            "RouteValidation": "CONFIRMED",
            "SgValidation": "CONFIRMED",
            "Confidence": "HIGH",
            "Finding": (
                "A complete untrusted network path exists: "
                "source connectivity, return routing and endpoint "
                "security-group permission were all identified"
            ),
            "BroadSgRules": unique_strings(
                broad_sg_rules_seen
            ),
            "Evidence": evidence,
        }

    if unresolved_paths:
        return {
            "Status": "REVIEW",
            "Accessible": "UNDETERMINED",
            "Reason": (
                "Network accessibility could not be fully "
                "determined because one or more endpoint "
                "security groups or path details could not be read"
            ),
            "RecommendedAction": (
                "Review the endpoint security groups and the "
                "evidence CSV for missing permissions"
            ),
            "PathType": join_values(
                path.get("PathType", "")
                for path in unresolved_paths
            ),
            "SourceAccount": join_values(
                path.get("SourceAccount", "")
                for path in unresolved_paths
            ),
            "SourceNetwork": join_values(
                network
                for path in unresolved_paths
                for network in path.get(
                    "SourceNetworks",
                    [],
                )
            ),
            "MatchingRoute": "",
            "PermittingSgRule": "",
            "RouteValidation": "UNDETERMINED",
            "SgValidation": "UNDETERMINED",
            "Confidence": "LOW",
            "Finding": (
                "No confirmed accessible path was found, but "
                "some required network information was unavailable"
            ),
            "BroadSgRules": unique_strings(
                broad_sg_rules_seen
            ),
            "Evidence": evidence,
        }

    return {
        "Status": "COMPLIANT",
        "Accessible": "NO",
        "Reason": (
            "No untrusted source had both a matching endpoint-"
            "subnet route and a permitting endpoint security-"
            "group rule"
        ),
        "RecommendedAction": (
            "No network remediation required. Review any broad "
            "security-group rules separately and restrict the "
            "wildcard endpoint policy where possible."
        ),
        "PathType": (
            join_values(
                path.get("PathType", "")
                for path in candidate_paths
            )
            or "NONE"
        ),
        "SourceAccount": "",
        "SourceNetwork": "",
        "MatchingRoute": "",
        "PermittingSgRule": "",
        "RouteValidation": (
            "CHECKED"
            if endpoint_route_tables_list
            else "NO_ENDPOINT_SUBNET_ROUTE_TABLE"
        ),
        "SgValidation": "CHECKED",
        "Confidence": "HIGH",
        "Finding": (
            "External connectivity may exist in the VPC, but "
            "no complete path to the interface endpoint was "
            "confirmed"
        ),
        "BroadSgRules": unique_strings(
            broad_sg_rules_seen
        ),
        "Evidence": evidence,
    }


# ============================================================
# SUMMARY ROW
# ============================================================

def build_base_row(
    account_id: str,
    partition: str,
    region: str,
    endpoint: Dict[str, Any],
) -> Dict[str, Any]:
    endpoint_id = endpoint.get(
        "VpcEndpointId",
        "",
    )

    endpoint_type = endpoint.get(
        "VpcEndpointType",
        "",
    )

    service_name = endpoint.get(
        "ServiceName",
        "",
    )

    return {
        "Account": account_id,
        "Region": region,
        "Control": CONTROL_NAME,
        "NetworkComplianceStatus": "",
        "AccessibleByUntrustedSource": "",
        "NonComplianceReason": "",
        "RecommendedAction": "",
        "VpcEndpointId": endpoint_id,
        "VpcEndpointArn": endpoint_arn(
            partition,
            region,
            account_id,
            endpoint_id,
        ),
        "EndpointName": get_name_tag(endpoint),
        "EndpointType": endpoint_type,
        "GatewayService": (
            identify_gateway_service(service_name)
            if endpoint_type == "Gateway"
            else "Not applicable"
        ),
        "State": endpoint.get("State", ""),
        "VpcId": endpoint.get("VpcId", ""),
        "ServiceName": service_name,
        "NetworkPathType": "",
        "UntrustedSourceAccount": "",
        "UntrustedSourceNetwork": "",
        "MatchingRoute": "",
        "PermittingSecurityGroupRule": "",
        "RouteValidationStatus": "",
        "SecurityGroupValidationStatus": "",
        "NetworkConfidence": "",
        "GatewayEndpointRouteTableIds": join_values(
            endpoint.get("RouteTableIds", [])
        ),
        "GatewayEndpointEffectiveSubnetIds": "",
        "GatewayEndpointSharedSubnetAccounts": "",
        "InterfaceEndpointSubnetIds": join_values(
            endpoint.get("SubnetIds", [])
        ),
        "InterfaceEndpointSecurityGroupIds": join_values(
            group.get("GroupId")
            for group in endpoint.get(
                "Groups",
                [],
            ) or []
        ),
        "InterfaceEndpointEniIds": join_values(
            endpoint.get(
                "NetworkInterfaceIds",
                [],
            )
        ),
        "PolicyTechnicalStatus": "",
        "PolicyContainsWildcard": "",
        "PolicyUntrustedPrincipals": "",
        "PolicyFinding": "",
        "NetworkFinding": "",
        "EvaluationStatus": "EVALUATED",
        "Error": "",
    }


# ============================================================
# CONTROL EXECUTION
# ============================================================

def check_vpc_endpoints(
    session: boto3.Session,
    regions: List[str],
    trusted_accounts: Set[str],
    include_inactive: bool,
    endpoint_port: int,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    account_id = get_account_id(session)
    partition = get_partition(session)

    summary_rows: List[Dict[str, Any]] = []
    evidence_rows: List[Dict[str, Any]] = []

    region_bar = tqdm(
        regions,
        desc="Scanning Regions",
        unit="region",
        position=0,
    )

    for region in region_bar:
        region_bar.set_postfix_str(region)

        try:
            ec2 = session.client(
                "ec2",
                region_name=region,
            )

            endpoints = paginate_items(
                ec2,
                "describe_vpc_endpoints",
                "VpcEndpoints",
            )

        except (ClientError, BotoCoreError) as error:
            summary_rows.append({
                "Account": account_id,
                "Region": region,
                "Control": CONTROL_NAME,
                "NetworkComplianceStatus": "SKIPPED",
                "AccessibleByUntrustedSource": "UNDETERMINED",
                "NonComplianceReason": "",
                "RecommendedAction": (
                    "Resolve regional API access error"
                ),
                "VpcEndpointId": "N/A",
                "VpcEndpointArn": "",
                "EndpointName": "",
                "EndpointType": "",
                "GatewayService": "",
                "State": "",
                "VpcId": "",
                "ServiceName": "",
                "NetworkPathType": "",
                "UntrustedSourceAccount": "",
                "UntrustedSourceNetwork": "",
                "MatchingRoute": "",
                "PermittingSecurityGroupRule": "",
                "RouteValidationStatus": "",
                "SecurityGroupValidationStatus": "",
                "NetworkConfidence": "LOW",
                "GatewayEndpointRouteTableIds": "",
                "GatewayEndpointEffectiveSubnetIds": "",
                "GatewayEndpointSharedSubnetAccounts": "",
                "InterfaceEndpointSubnetIds": "",
                "InterfaceEndpointSecurityGroupIds": "",
                "InterfaceEndpointEniIds": "",
                "PolicyTechnicalStatus": "",
                "PolicyContainsWildcard": "",
                "PolicyUntrustedPrincipals": "",
                "PolicyFinding": "",
                "NetworkFinding": "",
                "EvaluationStatus": "SKIPPED",
                "Error": error_text(error),
            })
            continue

        if not include_inactive:
            endpoints = [
                endpoint
                for endpoint in endpoints
                if endpoint.get("State")
                in ACTIVE_ENDPOINT_STATES
            ]

        if not endpoints:
            continue

        inventory, inventory_errors = load_inventory(
            ec2
        )

        shared_subnets, ram_errors = (
            get_shared_subnet_principals(
                session,
                region,
            )
        )

        regional_errors = (
            inventory_errors + ram_errors
        )

        endpoint_bar = tqdm(
            endpoints,
            desc=f"{region} endpoints",
            unit="endpoint",
            leave=False,
            position=1,
        )

        for endpoint in endpoint_bar:
            endpoint_id = endpoint.get(
                "VpcEndpointId",
                "UNKNOWN",
            )

            endpoint_bar.set_postfix_str(
                endpoint_id
            )

            row = build_base_row(
                account_id,
                partition,
                region,
                endpoint,
            )

            try:
                try:
                    policy_document = decode_policy(
                        endpoint.get(
                            "PolicyDocument"
                        )
                    )

                    policy_result = (
                        evaluate_policy_information(
                            policy_document,
                            trusted_accounts,
                        )
                    )

                except Exception as policy_error:
                    policy_result = {
                        "Status": "REVIEW",
                        "Wildcard": "",
                        "UntrustedPrincipals": [],
                        "Finding": (
                            "Policy could not be parsed: "
                            f"{error_text(policy_error)}"
                        ),
                    }

                endpoint_type = endpoint.get(
                    "VpcEndpointType",
                    "",
                )

                if endpoint_type == "Gateway":
                    network_result = (
                        evaluate_gateway_endpoint(
                            endpoint,
                            inventory,
                            shared_subnets,
                            trusted_accounts,
                        )
                    )

                elif endpoint_type == "Interface":
                    network_result = (
                        evaluate_interface_endpoint(
                            endpoint,
                            inventory,
                            shared_subnets,
                            trusted_accounts,
                            endpoint_port,
                        )
                    )

                else:
                    network_result = {
                        "Status": "REVIEW",
                        "Accessible": "UNDETERMINED",
                        "Reason": (
                            f"Endpoint type {endpoint_type} "
                            f"requires type-specific review"
                        ),
                        "RecommendedAction": (
                            "Review the endpoint architecture manually"
                        ),
                        "PathType": "",
                        "SourceAccount": "",
                        "SourceNetwork": "",
                        "MatchingRoute": "",
                        "PermittingSgRule": "",
                        "RouteValidation": "UNDETERMINED",
                        "SgValidation": "UNDETERMINED",
                        "Confidence": "LOW",
                        "Finding": (
                            "Automated evaluation is not implemented "
                            "for this endpoint type"
                        ),
                        "BroadSgRules": [],
                        "Evidence": [],
                    }

                row.update({
                    "NetworkComplianceStatus": (
                        network_result["Status"]
                    ),
                    "AccessibleByUntrustedSource": (
                        network_result["Accessible"]
                    ),
                    "NonComplianceReason": (
                        network_result["Reason"]
                        if network_result["Status"]
                        in {"NON_COMPLIANT", "REVIEW"}
                        else ""
                    ),
                    "RecommendedAction": (
                        network_result[
                            "RecommendedAction"
                        ]
                    ),
                    "NetworkPathType": (
                        network_result["PathType"]
                    ),
                    "UntrustedSourceAccount": (
                        network_result[
                            "SourceAccount"
                        ]
                    ),
                    "UntrustedSourceNetwork": (
                        network_result[
                            "SourceNetwork"
                        ]
                    ),
                    "MatchingRoute": (
                        network_result[
                            "MatchingRoute"
                        ]
                    ),
                    "PermittingSecurityGroupRule": (
                        network_result[
                            "PermittingSgRule"
                        ]
                    ),
                    "RouteValidationStatus": (
                        network_result[
                            "RouteValidation"
                        ]
                    ),
                    "SecurityGroupValidationStatus": (
                        network_result[
                            "SgValidation"
                        ]
                    ),
                    "NetworkConfidence": (
                        network_result[
                            "Confidence"
                        ]
                    ),
                    "PolicyTechnicalStatus": (
                        policy_result["Status"]
                    ),
                    "PolicyContainsWildcard": (
                        policy_result["Wildcard"]
                    ),
                    "PolicyUntrustedPrincipals": (
                        join_values(
                            policy_result[
                                "UntrustedPrincipals"
                            ]
                        )
                    ),
                    "PolicyFinding": (
                        policy_result["Finding"]
                    ),
                    "NetworkFinding": (
                        network_result["Finding"]
                    ),
                })

                if endpoint_type == "Gateway":
                    row[
                        "GatewayEndpointEffectiveSubnetIds"
                    ] = join_values(
                        network_result[
                            "EffectiveSubnetIds"
                        ]
                    )

                    row[
                        "GatewayEndpointSharedSubnetAccounts"
                    ] = join_values(
                        item["Principal"]
                        for item in network_result[
                            "SharedAccounts"
                        ]
                    )

                if regional_errors:
                    row["Error"] = join_values(
                        regional_errors
                    )

                    # Do not override a confirmed result merely because
                    # unrelated inventory calls failed. The errors remain
                    # visible for review.
                    if (
                        row["NetworkComplianceStatus"]
                        == "COMPLIANT"
                        and any(
                            operation in row["Error"]
                            for operation in [
                                "describe_route_tables",
                                "describe_security_groups",
                                "describe_subnets",
                            ]
                        )
                    ):
                        row[
                            "NetworkComplianceStatus"
                        ] = "REVIEW"

                        row[
                            "AccessibleByUntrustedSource"
                        ] = "UNDETERMINED"

                        row[
                            "NonComplianceReason"
                        ] = (
                            "Required route, subnet or "
                            "security-group inventory was incomplete"
                        )

                        row[
                            "NetworkConfidence"
                        ] = "LOW"

                for item in network_result[
                    "Evidence"
                ]:
                    evidence_rows.append({
                        "Account": account_id,
                        "Region": region,
                        "VpcEndpointId": endpoint_id,
                        "EndpointType": endpoint_type,
                        "ServiceName": endpoint.get(
                            "ServiceName",
                            "",
                        ),
                        "NetworkComplianceStatus": row[
                            "NetworkComplianceStatus"
                        ],
                        **item,
                    })

            except Exception as error:
                row.update({
                    "NetworkComplianceStatus": "REVIEW",
                    "AccessibleByUntrustedSource": (
                        "UNDETERMINED"
                    ),
                    "NonComplianceReason": (
                        "Endpoint evaluation failed before "
                        "a reliable network conclusion was reached"
                    ),
                    "RecommendedAction": (
                        "Review the endpoint and the error field"
                    ),
                    "NetworkConfidence": "LOW",
                    "NetworkFinding": (
                        "Manual validation required"
                    ),
                    "EvaluationStatus": "PARTIAL",
                    "Error": error_text(error),
                })

            summary_rows.append(row)

    return summary_rows, evidence_rows


# ============================================================
# OUTPUT
# ============================================================

def write_csv(
    filename: str,
    fieldnames: List[str],
    rows: List[Dict[str, Any]],
) -> None:
    with open(
        filename,
        "w",
        newline="",
        encoding="utf-8-sig",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
            extrasaction="ignore",
        )

        writer.writeheader()
        writer.writerows(rows)


def print_summary(
    account_id: str,
    rows: List[Dict[str, Any]],
) -> None:
    endpoint_rows = [
        row
        for row in rows
        if row.get("VpcEndpointId") != "N/A"
    ]

    status_counts: Dict[str, int] = defaultdict(int)
    type_counts: Dict[str, int] = defaultdict(int)
    gateway_service_counts: Dict[str, int] = defaultdict(int)

    for row in endpoint_rows:
        status_counts[
            row.get(
                "NetworkComplianceStatus",
                "UNKNOWN",
            )
        ] += 1

        type_counts[
            row.get("EndpointType", "Unknown")
        ] += 1

        if row.get("EndpointType") == "Gateway":
            gateway_service_counts[
                row.get(
                    "GatewayService",
                    "Unknown",
                )
            ] += 1

    skipped_regions = sum(
        1
        for row in rows
        if row.get("EvaluationStatus") == "SKIPPED"
    )

    print("\n============================================================")
    print(f"CONTROL : {CONTROL_NAME}")
    print(f"ACCOUNT : {account_id}")
    print("RESULT  : NETWORK ACCESSIBILITY EXCLUDING POLICY")
    print("============================================================")

    print(
        f"\nTotal VPC endpoints evaluated : "
        f"{len(endpoint_rows)}"
    )
    print(
        f"Skipped region records        : "
        f"{skipped_regions}"
    )

    print("\nEndpoint types")
    print("------------------------------------------------------------")

    for endpoint_type, count in sorted(
        type_counts.items()
    ):
        print(f"{endpoint_type:<32}: {count}")

    if gateway_service_counts:
        print("\nGateway endpoint services checked")
        print("------------------------------------------------------------")

        for service, count in sorted(
            gateway_service_counts.items()
        ):
            print(f"{service:<32}: {count}")

    print("\nNetwork compliance status")
    print("------------------------------------------------------------")

    for status in [
        "COMPLIANT",
        "NON_COMPLIANT",
        "REVIEW",
        "SKIPPED",
    ]:
        print(
            f"{status:<32}: "
            f"{status_counts.get(status, 0)}"
        )

    if status_counts.get("NON_COMPLIANT", 0):
        overall = "NON_COMPLIANT"

    elif status_counts.get("REVIEW", 0):
        overall = "REVIEW"

    elif endpoint_rows:
        overall = "COMPLIANT"

    else:
        overall = "NO_RESOURCES"

    print(
        f"\nOVERALL NETWORK STATUS: {overall}"
    )
    print("============================================================\n")

    failing = [
        row
        for row in endpoint_rows
        if row.get("NetworkComplianceStatus")
        in {"NON_COMPLIANT", "REVIEW"}
    ]

    if failing:
        print("Endpoints requiring attention")
        print("------------------------------------------------------------")

        for row in failing:
            print(
                f"{row['Region']:<15} "
                f"{row['VpcEndpointId']:<24} "
                f"{row['EndpointType']:<12} "
                f"{row['NetworkComplianceStatus']:<14} "
                f"{row['NonComplianceReason']}"
            )

        print()


# ============================================================
# ARGUMENTS
# ============================================================

def parse_trusted_accounts(
    own_account_id: str,
    arguments: List[str],
) -> Set[str]:
    trusted = {own_account_id}

    for argument in arguments:
        for account in argument.split(","):
            account = account.strip()

            if not account:
                continue

            if not ACCOUNT_ID_RE.fullmatch(account):
                raise ValueError(
                    f"Invalid trusted account ID: {account}. "
                    f"Expected exactly 12 digits."
                )

            trusted.add(account)

    return trusted


def main() -> None:
    parser = argparse.ArgumentParser(
        description=CONTROL_NAME,
        formatter_class=(
            argparse.ArgumentDefaultsHelpFormatter
        ),
    )

    parser.add_argument(
        "-R",
        "--role-arn",
        help="IAM role ARN to assume",
    )

    parser.add_argument(
        "--trusted-account",
        action="append",
        default=[],
        help=(
            "Approved 12-digit AWS account ID. "
            "May be repeated or comma-separated. "
            "The scanned account is automatically trusted."
        ),
    )

    parser.add_argument(
        "--regions",
        nargs="+",
        help=(
            "Specific regions to scan. "
            "All enabled regions are scanned when omitted."
        ),
    )

    parser.add_argument(
        "--include-inactive",
        action="store_true",
        help="Include inactive VPC endpoints",
    )

    parser.add_argument(
        "--endpoint-port",
        type=int,
        default=443,
        help=(
            "Interface endpoint destination port used for "
            "security-group correlation"
        ),
    )

    parser.add_argument(
        "--output-dir",
        default=".",
        help="Output directory for CSV reports",
    )

    args = parser.parse_args()

    try:
        session = get_session(args.role_arn)
        account_id = get_account_id(session)

        trusted_accounts = parse_trusted_accounts(
            account_id,
            args.trusted_account,
        )

        regions = (
            sorted(set(args.regions))
            if args.regions
            else get_enabled_regions(session)
        )

        os.makedirs(
            args.output_dir,
            exist_ok=True,
        )

        print(f"\nAccount          : {account_id}")
        print(
            f"Trusted accounts : "
            f"{join_values(sorted(trusted_accounts))}"
        )
        print(
            f"Regions          : {len(regions)}"
        )
        print(
            f"Endpoint port    : {args.endpoint_port}\n"
        )

        summary_rows, evidence_rows = (
            check_vpc_endpoints(
                session=session,
                regions=regions,
                trusted_accounts=trusted_accounts,
                include_inactive=args.include_inactive,
                endpoint_port=args.endpoint_port,
            )
        )

        summary_filename = os.path.join(
            args.output_dir,
            (
                f"vpc_endpoint_network_access_"
                f"{account_id}.csv"
            ),
        )

        evidence_filename = os.path.join(
            args.output_dir,
            (
                f"vpc_endpoint_network_evidence_"
                f"{account_id}.csv"
            ),
        )

        write_csv(
            summary_filename,
            SUMMARY_FIELDS,
            summary_rows,
        )

        write_csv(
            evidence_filename,
            EVIDENCE_FIELDS,
            evidence_rows,
        )

        print_summary(
            account_id,
            summary_rows,
        )

        print(
            f"Clear summary CSV : {summary_filename}"
        )
        print(
            f"Evidence CSV      : {evidence_filename}\n"
        )

    except KeyboardInterrupt:
        print(
            "\nAudit interrupted by user.",
            file=sys.stderr,
        )
        sys.exit(130)

    except Exception as error:
        print(
            f"\nFatal error: {error_text(error)}",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
