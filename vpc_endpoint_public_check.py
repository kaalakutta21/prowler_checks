#!/usr/bin/env python3

"""
Control:
    VPC endpoint policy allows access only from trusted AWS accounts

Purpose:
    1. Evaluate the endpoint policy technically.
    2. Assess whether an endpoint with an open/untrusted policy has practical
       cross-account or external network exposure.
    3. Produce one clear summary row per VPC endpoint and detailed evidence rows.

Important:
    Network restrictions do not make an open endpoint policy technically compliant.
    They may reduce practical risk, resulting in EffectiveRiskStatus=MITIGATED.

Supported endpoint types:
    - Gateway
    - Interface
    - GatewayLoadBalancer
    - Resource
    - ServiceNetwork
    - Other endpoint types returned by EC2

Outputs:
    1. vpc_endpoint_trusted_accounts_summary_<account>.csv
    2. vpc_endpoint_trusted_accounts_evidence_<account>.csv

Required permissions may include:
    ec2:DescribeRegions
    ec2:DescribeVpcEndpoints
    ec2:DescribeVpcs
    ec2:DescribeSubnets
    ec2:DescribeRouteTables
    ec2:DescribeSecurityGroups
    ec2:DescribeVpcPeeringConnections
    ec2:DescribeTransitGatewayAttachments
    ec2:DescribeTransitGatewayVpcAttachments
    ec2:DescribeVpnGateways
    ec2:DescribeVpnConnections
    ec2:DescribeNetworkInterfaces
    ram:GetResourceShares
    ram:ListResources
    ram:ListPrincipals
    sts:GetCallerIdentity
    sts:AssumeRole
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
    "pendingAcceptance",
    "pending",
}

TRUST_CONDITION_KEYS = {
    "aws:principalaccount",
    "aws:principalarn",
    "aws:sourceaccount",
}

ACCOUNT_ID_PATTERN = re.compile(r"^\d{12}$")
ARN_ACCOUNT_PATTERN = re.compile(
    r"^arn:(?:aws|aws-us-gov|aws-cn):[^:]*:[^:]*:(\d{12}):"
)

BROAD_IPV4 = ipaddress.ip_network("0.0.0.0/0")
BROAD_IPV6 = ipaddress.ip_network("::/0")


# ============================================================
# AUTHENTICATION
# ============================================================

def get_session(role_arn: Optional[str] = None) -> boto3.Session:
    if not role_arn:
        return boto3.Session()

    base_session = boto3.Session()
    sts = base_session.client("sts")

    response = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName="vpc-endpoint-trusted-accounts-audit",
    )

    credentials = response["Credentials"]

    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )


def get_account_id(session: boto3.Session) -> str:
    return session.client("sts").get_caller_identity()["Account"]


# ============================================================
# COMMON HELPERS
# ============================================================

def error_code(error: Exception) -> str:
    if isinstance(error, ClientError):
        return error.response.get("Error", {}).get("Code", type(error).__name__)
    return type(error).__name__


def error_message(error: Exception) -> str:
    if isinstance(error, ClientError):
        return error.response.get("Error", {}).get("Message", str(error))
    return str(error)


def compact_error(error: Exception) -> str:
    return f"{error_code(error)}: {error_message(error)}"


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


def get_name_tag(resource: Dict[str, Any]) -> str:
    for tag in resource.get("Tags", []) or []:
        if tag.get("Key") == "Name":
            return tag.get("Value", "")
    return ""


def json_string(value: Any) -> str:
    return json.dumps(
        value,
        separators=(",", ":"),
        sort_keys=True,
        default=str,
    )


def join_values(values: Iterable[Any]) -> str:
    return ";".join(unique_strings(values))


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


def get_partition(session: boto3.Session) -> str:
    region = session.region_name or "us-east-1"

    if region.startswith("us-gov-"):
        return "aws-us-gov"

    if region.startswith("cn-"):
        return "aws-cn"

    return "aws"


def get_enabled_regions(session: boto3.Session) -> List[str]:
    ec2 = session.client("ec2", region_name="us-east-1")

    response = ec2.describe_regions(AllRegions=True)

    regions = [
        item["RegionName"]
        for item in response.get("Regions", [])
        if item.get("OptInStatus") in {
            "opt-in-not-required",
            "opted-in",
        }
    ]

    return sorted(regions)


def paginate_items(
    client: Any,
    operation_name: str,
    result_key: str,
    **kwargs: Any,
) -> List[Dict[str, Any]]:
    paginator = client.get_paginator(operation_name)
    items: List[Dict[str, Any]] = []

    for page in paginator.paginate(**kwargs):
        items.extend(page.get(result_key, []))

    return items


def timestamp_to_text(value: Any) -> str:
    if value is None:
        return ""

    try:
        return value.isoformat()
    except AttributeError:
        return str(value)


# ============================================================
# POLICY PARSING
# ============================================================

def decode_policy_document(policy_document: Any) -> Dict[str, Any]:
    if not policy_document:
        return {}

    if isinstance(policy_document, dict):
        return policy_document

    if not isinstance(policy_document, str):
        raise ValueError(
            f"Unsupported policy document type: {type(policy_document).__name__}"
        )

    candidates = [policy_document]

    try:
        decoded = unquote(policy_document)
        if decoded != policy_document:
            candidates.append(decoded)
    except Exception:
        pass

    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            continue

    raise ValueError("PolicyDocument could not be decoded as JSON")


def extract_account_from_principal(principal: str) -> Optional[str]:
    principal = principal.strip()

    if ACCOUNT_ID_PATTERN.fullmatch(principal):
        return principal

    match = ARN_ACCOUNT_PATTERN.match(principal)
    if match:
        return match.group(1)

    return None


def flatten_principal(principal: Any) -> List[str]:
    """
    Returns all principal representations in a simple list.

    Examples:
        "*"
        {"AWS": "*"}
        {"AWS": ["arn:aws:iam::111122223333:root"]}
        {"Service": "ec2.amazonaws.com"}
    """
    values: List[str] = []

    if principal is None:
        return values

    if isinstance(principal, str):
        return [principal]

    if isinstance(principal, list):
        for item in principal:
            values.extend(flatten_principal(item))
        return values

    if isinstance(principal, dict):
        for principal_type, principal_value in principal.items():
            for item in normalize_list(principal_value):
                values.append(f"{principal_type}:{item}")
        return values

    values.append(str(principal))
    return values


def condition_values(
    condition: Any,
    wanted_keys: Set[str],
) -> Dict[str, List[str]]:
    output: Dict[str, List[str]] = defaultdict(list)

    if not isinstance(condition, dict):
        return output

    for operator, condition_block in condition.items():
        if not isinstance(condition_block, dict):
            continue

        operator_lower = str(operator).lower()

        for key, value in condition_block.items():
            key_lower = str(key).lower()

            if key_lower not in wanted_keys:
                continue

            for item in normalize_list(value):
                output[f"{operator_lower}:{key_lower}"].append(str(item))

    return dict(output)


def trusted_accounts_from_conditions(
    condition: Any,
) -> Tuple[Set[str], bool, List[str]]:
    """
    Returns:
        account IDs found in recognized restricting conditions,
        whether all recognized values were parseable,
        textual condition evidence.

    This does not attempt to be a complete IAM policy simulator.
    """
    discovered_accounts: Set[str] = set()
    all_parseable = True
    evidence: List[str] = []

    values = condition_values(condition, TRUST_CONDITION_KEYS)

    for operator_key, entries in values.items():
        operator, key = operator_key.split(":", 1)

        evidence.append(f"{operator}:{key}={entries}")

        # Negative operators do not create a trusted allow-list.
        if "not" in operator:
            all_parseable = False
            continue

        for entry in entries:
            if key in {"aws:principalaccount", "aws:sourceaccount"}:
                if ACCOUNT_ID_PATTERN.fullmatch(entry):
                    discovered_accounts.add(entry)
                else:
                    all_parseable = False

            elif key == "aws:principalarn":
                account = extract_account_from_principal(entry)

                if account:
                    discovered_accounts.add(account)
                else:
                    all_parseable = False

    return discovered_accounts, all_parseable, evidence


def evaluate_policy(
    policy_document: Dict[str, Any],
    trusted_accounts: Set[str],
) -> Dict[str, Any]:
    """
    Technical evaluation of Allow statements.

    COMPLIANT:
        All account-based AWS principals are trusted, or wildcard principal
        is restricted by a recognized trusted-account condition.

    NON_COMPLIANT:
        Wildcard principal without trusted-account restriction, or explicit
        AWS principal from an untrusted account.

    REVIEW:
        Complex IAM constructs cannot safely be resolved by this script.
    """
    statements = normalize_list(policy_document.get("Statement"))

    if not statements:
        return {
            "TechnicalStatus": "REVIEW",
            "PolicyFinding": "Policy contains no readable Statement entries",
            "WildcardPrincipal": False,
            "TrustedPrincipals": [],
            "UntrustedPrincipals": [],
            "ServicePrincipals": [],
            "ComplexStatements": [],
        }

    wildcard_principal = False
    trusted_principals: List[str] = []
    untrusted_principals: List[str] = []
    service_principals: List[str] = []
    complex_statements: List[str] = []
    granting_statements = 0

    for index, statement in enumerate(statements, start=1):
        if not isinstance(statement, dict):
            complex_statements.append(
                f"Statement {index}: statement is not an object"
            )
            continue

        effect = str(statement.get("Effect", "")).lower()

        # Deny statements do not independently grant access.
        if effect != "allow":
            continue

        granting_statements += 1

        if "NotPrincipal" in statement:
            complex_statements.append(
                f"Statement {index}: uses NotPrincipal"
            )
            continue

        if "NotAction" in statement:
            complex_statements.append(
                f"Statement {index}: uses NotAction"
            )

        if "NotResource" in statement:
            complex_statements.append(
                f"Statement {index}: uses NotResource"
            )

        principals = flatten_principal(statement.get("Principal"))
        condition = statement.get("Condition", {})

        condition_accounts, condition_parseable, condition_evidence = (
            trusted_accounts_from_conditions(condition)
        )

        for principal in principals:
            raw_principal = principal

            if ":" in principal:
                principal_type, principal_value = principal.split(":", 1)
            else:
                principal_type = "AWS"
                principal_value = principal

            principal_type_lower = principal_type.lower()
            principal_value = principal_value.strip()

            if principal_type_lower == "service":
                service_principals.append(principal_value)
                continue

            if principal_type_lower not in {"aws", "federated", "canonicaluser"}:
                complex_statements.append(
                    f"Statement {index}: unsupported principal type "
                    f"{principal_type}"
                )
                continue

            if principal_value == "*":
                wildcard_principal = True

                if (
                    condition_accounts
                    and condition_parseable
                    and condition_accounts.issubset(trusted_accounts)
                ):
                    trusted_principals.append(
                        f"{raw_principal} restricted by "
                        f"{sorted(condition_accounts)}"
                    )
                else:
                    reason = (
                        f"{raw_principal} without a recognized trusted-account "
                        f"restriction"
                    )

                    if condition_evidence:
                        reason += f"; conditions={condition_evidence}"

                    untrusted_principals.append(reason)

                continue

            account = extract_account_from_principal(principal_value)

            if account:
                if account in trusted_accounts:
                    trusted_principals.append(principal_value)
                else:
                    untrusted_principals.append(principal_value)
            else:
                complex_statements.append(
                    f"Statement {index}: principal cannot be mapped to an "
                    f"AWS account: {principal_value}"
                )

    if granting_statements == 0:
        return {
            "TechnicalStatus": "REVIEW",
            "PolicyFinding": "No Allow statements were found",
            "WildcardPrincipal": wildcard_principal,
            "TrustedPrincipals": trusted_principals,
            "UntrustedPrincipals": untrusted_principals,
            "ServicePrincipals": service_principals,
            "ComplexStatements": complex_statements,
        }

    if untrusted_principals:
        status = "NON_COMPLIANT"
        finding = (
            "Endpoint policy permits wildcard or untrusted AWS principals"
        )
    elif complex_statements:
        status = "REVIEW"
        finding = (
            "No confirmed untrusted principal was identified, but complex "
            "policy elements require manual review"
        )
    else:
        status = "COMPLIANT"
        finding = "Endpoint policy grants access only to trusted AWS accounts"

    return {
        "TechnicalStatus": status,
        "PolicyFinding": finding,
        "WildcardPrincipal": wildcard_principal,
        "TrustedPrincipals": trusted_principals,
        "UntrustedPrincipals": untrusted_principals,
        "ServicePrincipals": service_principals,
        "ComplexStatements": complex_statements,
    }


# ============================================================
# REGIONAL INVENTORY
# ============================================================

def load_regional_inventory(
    ec2: Any,
    include_network_inventory: bool = True,
) -> Tuple[Dict[str, Any], List[str]]:
    inventory: Dict[str, Any] = {
        "vpcs": {},
        "subnets": {},
        "route_tables": [],
        "security_groups": {},
        "peerings": [],
        "tgw_attachments": [],
        "tgw_vpc_attachments": [],
        "vpn_gateways": [],
        "vpn_connections": [],
        "network_interfaces": {},
    }

    errors: List[str] = []

    operations = [
        ("describe_vpcs", "Vpcs", "vpcs"),
        ("describe_subnets", "Subnets", "subnets"),
        ("describe_route_tables", "RouteTables", "route_tables"),
        ("describe_security_groups", "SecurityGroups", "security_groups"),
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
        ("describe_vpn_gateways", "VpnGateways", "vpn_gateways"),
        ("describe_vpn_connections", "VpnConnections", "vpn_connections"),
        (
            "describe_network_interfaces",
            "NetworkInterfaces",
            "network_interfaces",
        ),
    ]

    if not include_network_inventory:
        operations = operations[:4]

    for operation, result_key, inventory_key in operations:
        try:
            items = paginate_items(
                ec2,
                operation,
                result_key,
            )

            if inventory_key == "vpcs":
                inventory[inventory_key] = {
                    item["VpcId"]: item for item in items
                }

            elif inventory_key == "subnets":
                inventory[inventory_key] = {
                    item["SubnetId"]: item for item in items
                }

            elif inventory_key == "security_groups":
                inventory[inventory_key] = {
                    item["GroupId"]: item for item in items
                }

            elif inventory_key == "network_interfaces":
                inventory[inventory_key] = {
                    item["NetworkInterfaceId"]: item for item in items
                }

            else:
                inventory[inventory_key] = items

        except (ClientError, BotoCoreError) as error:
            errors.append(f"{operation}: {compact_error(error)}")

    return inventory, errors


# ============================================================
# AWS RAM / SHARED SUBNET INVENTORY
# ============================================================

def get_shared_subnet_principals(
    session: boto3.Session,
    region: str,
) -> Tuple[Dict[str, Set[str]], List[str]]:
    """
    Returns:
        subnet ID -> principals with which the subnet is shared.

    VPC sharing is implemented by sharing subnets, not the entire VPC object.
    """
    subnet_principals: Dict[str, Set[str]] = defaultdict(set)
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

                principal_values = {
                    str(item.get("id", "")).strip()
                    for item in principals
                    if item.get("id")
                }

                for resource in resources:
                    resource_arn = resource.get("arn", "")

                    if ":subnet/" not in resource_arn:
                        continue

                    subnet_id = resource_arn.rsplit("/", 1)[-1]
                    subnet_principals[subnet_id].update(principal_values)

            except (ClientError, BotoCoreError) as error:
                errors.append(
                    f"RAM share {share_arn}: {compact_error(error)}"
                )

    except (ClientError, BotoCoreError) as error:
        errors.append(f"AWS RAM inventory: {compact_error(error)}")

    return dict(subnet_principals), errors


def principal_is_trusted(
    principal: str,
    trusted_accounts: Set[str],
) -> bool:
    principal = principal.strip()

    if ACCOUNT_ID_PATTERN.fullmatch(principal):
        return principal in trusted_accounts

    account = extract_account_from_principal(principal)
    if account:
        return account in trusted_accounts

    # Organization and OU principals cannot be safely resolved to accounts
    # by this script alone.
    return False


# ============================================================
# NETWORK ANALYSIS HELPERS
# ============================================================

def vpc_cidrs(vpc: Dict[str, Any]) -> List[str]:
    cidrs: List[str] = []

    if vpc.get("CidrBlock"):
        cidrs.append(vpc["CidrBlock"])

    for association in vpc.get("CidrBlockAssociationSet", []) or []:
        if association.get("CidrBlock"):
            cidrs.append(association["CidrBlock"])

    for association in vpc.get("Ipv6CidrBlockAssociationSet", []) or []:
        if association.get("Ipv6CidrBlock"):
            cidrs.append(association["Ipv6CidrBlock"])

    return unique_strings(cidrs)


def subnet_cidrs(subnet: Dict[str, Any]) -> List[str]:
    cidrs: List[str] = []

    if subnet.get("CidrBlock"):
        cidrs.append(subnet["CidrBlock"])

    if subnet.get("Ipv6CidrBlock"):
        cidrs.append(subnet["Ipv6CidrBlock"])

    for association in subnet.get("Ipv6CidrBlockAssociationSet", []) or []:
        if association.get("Ipv6CidrBlock"):
            cidrs.append(association["Ipv6CidrBlock"])

    return unique_strings(cidrs)


def route_destination(route: Dict[str, Any]) -> str:
    return (
        route.get("DestinationCidrBlock")
        or route.get("DestinationIpv6CidrBlock")
        or route.get("DestinationPrefixListId")
        or ""
    )


def route_target(route: Dict[str, Any]) -> Tuple[str, str]:
    target_fields = [
        ("VpcPeeringConnectionId", "PEERING"),
        ("TransitGatewayId", "TRANSIT_GATEWAY"),
        ("GatewayId", "GATEWAY"),
        ("NatGatewayId", "NAT_GATEWAY"),
        ("NetworkInterfaceId", "NETWORK_INTERFACE"),
        ("VpcEndpointId", "VPC_ENDPOINT"),
        ("EgressOnlyInternetGatewayId", "EGRESS_ONLY_IGW"),
        ("InstanceId", "INSTANCE"),
        ("LocalGatewayId", "LOCAL_GATEWAY"),
        ("CarrierGatewayId", "CARRIER_GATEWAY"),
        ("CoreNetworkArn", "CLOUD_WAN"),
    ]

    for field, target_type in target_fields:
        value = route.get(field)
        if value:
            return target_type, value

    return "", ""


def route_tables_for_vpc(
    route_tables: List[Dict[str, Any]],
    vpc_id: str,
) -> List[Dict[str, Any]]:
    return [
        route_table
        for route_table in route_tables
        if route_table.get("VpcId") == vpc_id
    ]


def route_tables_for_subnets(
    route_tables: List[Dict[str, Any]],
    subnet_ids: List[str],
    vpc_id: str,
) -> List[Dict[str, Any]]:
    selected: Dict[str, Dict[str, Any]] = {}
    main_route_table: Optional[Dict[str, Any]] = None

    subnet_set = set(subnet_ids)

    for route_table in route_tables_for_vpc(route_tables, vpc_id):
        route_table_id = route_table.get("RouteTableId", "")

        for association in route_table.get("Associations", []) or []:
            if association.get("Main"):
                main_route_table = route_table

            if association.get("SubnetId") in subnet_set:
                selected[route_table_id] = route_table

    for subnet_id in subnet_set:
        explicit = False

        for route_table in selected.values():
            if any(
                association.get("SubnetId") == subnet_id
                for association in route_table.get("Associations", []) or []
            ):
                explicit = True
                break

        if not explicit and main_route_table:
            selected[main_route_table.get("RouteTableId", "")] = (
                main_route_table
            )

    return list(selected.values())


def parse_ip_network(cidr: str) -> Optional[ipaddress._BaseNetwork]:
    try:
        return ipaddress.ip_network(cidr, strict=False)
    except (ValueError, TypeError):
        return None


def cidr_overlaps_any(cidr: str, candidates: Iterable[str]) -> bool:
    network = parse_ip_network(cidr)

    if not network:
        return False

    for candidate in candidates:
        candidate_network = parse_ip_network(candidate)

        if (
            candidate_network
            and network.version == candidate_network.version
            and network.overlaps(candidate_network)
        ):
            return True

    return False


def cidr_is_broad(cidr: str) -> bool:
    network = parse_ip_network(cidr)

    if not network:
        return False

    return network == BROAD_IPV4 or network == BROAD_IPV6


# ============================================================
# SECURITY-GROUP ANALYSIS
# ============================================================

def evaluate_endpoint_security_groups(
    group_ids: List[str],
    security_groups: Dict[str, Dict[str, Any]],
    peer_cidrs: List[str],
    trusted_accounts: Set[str],
) -> Dict[str, Any]:
    """
    Interface endpoint ingress is normally TCP/443, but endpoint services may
    use other ports. Therefore all inbound permissions are displayed.

    Exposure categories:
        RESTRICTED
        BROAD
        CROSS_ACCOUNT_PATH_ALLOWED
        REVIEW
        UNKNOWN
    """
    evidence: List[Dict[str, Any]] = []
    broad_rules: List[str] = []
    peer_allowed_rules: List[str] = []
    referenced_groups: List[str] = []
    missing_groups: List[str] = []

    for group_id in group_ids:
        group = security_groups.get(group_id)

        if not group:
            missing_groups.append(group_id)
            continue

        for permission in group.get("IpPermissions", []) or []:
            protocol = permission.get("IpProtocol", "")
            from_port = permission.get("FromPort", "")
            to_port = permission.get("ToPort", "")

            for item in permission.get("IpRanges", []) or []:
                cidr = item.get("CidrIp", "")
                description = item.get("Description", "")

                row = {
                    "EvidenceType": "SECURITY_GROUP_IPV4",
                    "ResourceId": group_id,
                    "Direction": "INGRESS",
                    "Protocol": protocol,
                    "Ports": f"{from_port}-{to_port}",
                    "Source": cidr,
                    "Detail": description,
                }
                evidence.append(row)

                if cidr_is_broad(cidr):
                    broad_rules.append(
                        f"{group_id}:{protocol}:{from_port}-{to_port}:{cidr}"
                    )

                if peer_cidrs and cidr_overlaps_any(cidr, peer_cidrs):
                    peer_allowed_rules.append(
                        f"{group_id}:{protocol}:{from_port}-{to_port}:{cidr}"
                    )

            for item in permission.get("Ipv6Ranges", []) or []:
                cidr = item.get("CidrIpv6", "")
                description = item.get("Description", "")

                row = {
                    "EvidenceType": "SECURITY_GROUP_IPV6",
                    "ResourceId": group_id,
                    "Direction": "INGRESS",
                    "Protocol": protocol,
                    "Ports": f"{from_port}-{to_port}",
                    "Source": cidr,
                    "Detail": description,
                }
                evidence.append(row)

                if cidr_is_broad(cidr):
                    broad_rules.append(
                        f"{group_id}:{protocol}:{from_port}-{to_port}:{cidr}"
                    )

                if peer_cidrs and cidr_overlaps_any(cidr, peer_cidrs):
                    peer_allowed_rules.append(
                        f"{group_id}:{protocol}:{from_port}-{to_port}:{cidr}"
                    )

            for item in permission.get("UserIdGroupPairs", []) or []:
                source_group_id = item.get("GroupId", "")
                source_account = item.get("UserId", "")
                source_vpc = item.get("VpcId", "")

                referenced_groups.append(
                    f"{source_group_id}@{source_account or 'unknown-account'}"
                )

                evidence.append({
                    "EvidenceType": "SECURITY_GROUP_REFERENCE",
                    "ResourceId": group_id,
                    "Direction": "INGRESS",
                    "Protocol": protocol,
                    "Ports": f"{from_port}-{to_port}",
                    "Source": source_group_id,
                    "Detail": (
                        f"SourceAccount={source_account};"
                        f"SourceVpc={source_vpc}"
                    ),
                })

                if (
                    source_account
                    and source_account not in trusted_accounts
                ):
                    peer_allowed_rules.append(
                        f"{group_id}:untrusted-SG-reference:"
                        f"{source_group_id}@{source_account}"
                    )

            for item in permission.get("PrefixListIds", []) or []:
                prefix_list_id = item.get("PrefixListId", "")

                evidence.append({
                    "EvidenceType": "SECURITY_GROUP_PREFIX_LIST",
                    "ResourceId": group_id,
                    "Direction": "INGRESS",
                    "Protocol": protocol,
                    "Ports": f"{from_port}-{to_port}",
                    "Source": prefix_list_id,
                    "Detail": item.get("Description", ""),
                })

    if broad_rules:
        posture = "BROAD"
        finding = "Endpoint security group permits broad inbound access"

    elif peer_allowed_rules:
        posture = "CROSS_ACCOUNT_PATH_ALLOWED"
        finding = (
            "Endpoint security group permits a detected cross-account network "
            "source or untrusted security-group reference"
        )

    elif missing_groups:
        posture = "UNKNOWN"
        finding = "One or more endpoint security groups could not be read"

    elif referenced_groups:
        posture = "REVIEW"
        finding = (
            "Ingress is restricted by security-group references; confirm the "
            "source workloads and account ownership"
        )

    else:
        posture = "RESTRICTED"
        finding = "No broad or confirmed untrusted ingress rule was identified"

    return {
        "SecurityGroupPosture": posture,
        "SecurityGroupFinding": finding,
        "BroadRules": broad_rules,
        "PeerAllowedRules": peer_allowed_rules,
        "ReferencedGroups": referenced_groups,
        "MissingGroups": missing_groups,
        "Evidence": evidence,
    }


# ============================================================
# CROSS-ACCOUNT CONNECTIVITY ANALYSIS
# ============================================================

def cross_account_peerings(
    peerings: List[Dict[str, Any]],
    endpoint_vpc_id: str,
    trusted_accounts: Set[str],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    matches: List[Dict[str, Any]] = []
    peer_cidrs: List[str] = []

    for peering in peerings:
        if peering.get("Status", {}).get("Code") != "active":
            continue

        requester = peering.get("RequesterVpcInfo", {})
        accepter = peering.get("AccepterVpcInfo", {})

        local_side: Optional[Dict[str, Any]] = None
        remote_side: Optional[Dict[str, Any]] = None

        if requester.get("VpcId") == endpoint_vpc_id:
            local_side = requester
            remote_side = accepter

        elif accepter.get("VpcId") == endpoint_vpc_id:
            local_side = accepter
            remote_side = requester

        if not local_side or not remote_side:
            continue

        remote_owner = remote_side.get("OwnerId", "")

        if remote_owner in trusted_accounts:
            continue

        cidrs = []

        if remote_side.get("CidrBlock"):
            cidrs.append(remote_side["CidrBlock"])

        for association in (
            remote_side.get("Ipv6CidrBlockSet", [])
            or remote_side.get("Ipv6CidrBlockAssociationSet", [])
            or []
        ):
            value = association.get("Ipv6CidrBlock")
            if value:
                cidrs.append(value)

        peer_cidrs.extend(cidrs)

        matches.append({
            "PeeringId": peering.get("VpcPeeringConnectionId", ""),
            "RemoteVpcId": remote_side.get("VpcId", ""),
            "RemoteOwnerId": remote_owner or "UNKNOWN",
            "RemoteRegion": remote_side.get("Region", ""),
            "RemoteCidrs": cidrs,
        })

    return matches, unique_strings(peer_cidrs)


def cross_account_tgw_paths(
    inventory: Dict[str, Any],
    endpoint_vpc_id: str,
    trusted_accounts: Set[str],
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []

    endpoint_tgw_ids: Set[str] = set()

    for attachment in inventory.get("tgw_vpc_attachments", []):
        if (
            attachment.get("VpcId") == endpoint_vpc_id
            and attachment.get("State") in {
                "available",
                "pending",
                "modifying",
            }
        ):
            tgw_id = attachment.get("TransitGatewayId")

            if tgw_id:
                endpoint_tgw_ids.add(tgw_id)

    if not endpoint_tgw_ids:
        return results

    for attachment in inventory.get("tgw_attachments", []):
        tgw_id = attachment.get("TransitGatewayId")

        if tgw_id not in endpoint_tgw_ids:
            continue

        state = attachment.get("State", "")

        if state not in {
            "available",
            "pending",
            "modifying",
            "initiatingRequest",
        }:
            continue

        resource_owner = attachment.get("ResourceOwnerId", "")
        resource_id = attachment.get("ResourceId", "")
        resource_type = attachment.get("ResourceType", "")
        tgw_owner = attachment.get("TransitGatewayOwnerId", "")

        if resource_id == endpoint_vpc_id:
            continue

        untrusted_resource_owner = (
            resource_owner
            and resource_owner not in trusted_accounts
        )
        untrusted_tgw_owner = (
            tgw_owner
            and tgw_owner not in trusted_accounts
        )

        if untrusted_resource_owner or untrusted_tgw_owner:
            results.append({
                "TransitGatewayId": tgw_id,
                "AttachmentId": attachment.get(
                    "TransitGatewayAttachmentId",
                    "",
                ),
                "ResourceType": resource_type,
                "ResourceId": resource_id,
                "ResourceOwnerId": resource_owner or "UNKNOWN",
                "TransitGatewayOwnerId": tgw_owner or "UNKNOWN",
                "State": state,
            })

    return results


def external_route_indicators(
    route_tables: List[Dict[str, Any]],
    endpoint_vpc_id: str,
    endpoint_subnets: List[str],
) -> List[Dict[str, Any]]:
    """
    Returns potential external/inter-VPC route indicators.

    This is evidence of possible connectivity, not proof that traffic can
    successfully reach the endpoint.
    """
    selected_route_tables = route_tables_for_subnets(
        route_tables,
        endpoint_subnets,
        endpoint_vpc_id,
    )

    if not selected_route_tables:
        selected_route_tables = route_tables_for_vpc(
            route_tables,
            endpoint_vpc_id,
        )

    indicators: List[Dict[str, Any]] = []

    for route_table in selected_route_tables:
        route_table_id = route_table.get("RouteTableId", "")

        for route in route_table.get("Routes", []) or []:
            if route.get("State") == "blackhole":
                continue

            target_type, target_id = route_target(route)

            relevant = False
            category = ""

            if target_type == "PEERING":
                relevant = True
                category = "VPC_PEERING_ROUTE"

            elif target_type == "TRANSIT_GATEWAY":
                relevant = True
                category = "TRANSIT_GATEWAY_ROUTE"

            elif (
                target_type == "GATEWAY"
                and (
                    target_id.startswith("vgw-")
                    or target_id.startswith("lgw-")
                )
            ):
                relevant = True
                category = "VPN_OR_DIRECT_CONNECT_ROUTE"

            elif target_type in {"LOCAL_GATEWAY", "CLOUD_WAN"}:
                relevant = True
                category = f"{target_type}_ROUTE"

            if relevant:
                indicators.append({
                    "RouteTableId": route_table_id,
                    "Category": category,
                    "Destination": route_destination(route),
                    "TargetType": target_type,
                    "TargetId": target_id,
                })

    return indicators


# ============================================================
# ENDPOINT NETWORK ANALYSIS
# ============================================================

def evaluate_network_exposure(
    endpoint: Dict[str, Any],
    inventory: Dict[str, Any],
    shared_subnet_principals: Dict[str, Set[str]],
    trusted_accounts: Set[str],
) -> Dict[str, Any]:
    endpoint_type = endpoint.get("VpcEndpointType", "Unknown")
    endpoint_vpc_id = endpoint.get("VpcId", "")
    subnet_ids = endpoint.get("SubnetIds", []) or []
    group_ids = [
        group.get("GroupId")
        for group in endpoint.get("Groups", []) or []
        if group.get("GroupId")
    ]

    evidence: List[Dict[str, Any]] = []

    endpoint_subnet_ids = set(subnet_ids)

    # Gateway endpoints do not expose SubnetIds. Evaluate all shared subnets
    # belonging to the endpoint VPC because workloads in those subnets use
    # VPC-owner-controlled routing.
    if endpoint_type == "Gateway":
        endpoint_subnet_ids = {
            subnet_id
            for subnet_id, subnet in inventory.get("subnets", {}).items()
            if subnet.get("VpcId") == endpoint_vpc_id
        }

    shared_untrusted_principals: Dict[str, List[str]] = {}

    for subnet_id in endpoint_subnet_ids:
        principals = shared_subnet_principals.get(subnet_id, set())

        untrusted = sorted(
            principal
            for principal in principals
            if not principal_is_trusted(
                principal,
                trusted_accounts,
            )
        )

        if untrusted:
            shared_untrusted_principals[subnet_id] = untrusted

            evidence.append({
                "EvidenceType": "SHARED_SUBNET",
                "ResourceId": subnet_id,
                "Direction": "",
                "Protocol": "",
                "Ports": "",
                "Source": join_values(untrusted),
                "Detail": (
                    "Subnet is shared through AWS RAM with a principal that "
                    "is not in the trusted-account list"
                ),
            })

    peerings, peer_cidrs = cross_account_peerings(
        inventory.get("peerings", []),
        endpoint_vpc_id,
        trusted_accounts,
    )

    for item in peerings:
        evidence.append({
            "EvidenceType": "CROSS_ACCOUNT_PEERING",
            "ResourceId": item["PeeringId"],
            "Direction": "",
            "Protocol": "",
            "Ports": "",
            "Source": item["RemoteOwnerId"],
            "Detail": json_string(item),
        })

    tgw_paths = cross_account_tgw_paths(
        inventory,
        endpoint_vpc_id,
        trusted_accounts,
    )

    for item in tgw_paths:
        evidence.append({
            "EvidenceType": "CROSS_ACCOUNT_TGW",
            "ResourceId": item["AttachmentId"],
            "Direction": "",
            "Protocol": "",
            "Ports": "",
            "Source": item["ResourceOwnerId"],
            "Detail": json_string(item),
        })

    route_indicators = external_route_indicators(
        inventory.get("route_tables", []),
        endpoint_vpc_id,
        subnet_ids,
    )

    for item in route_indicators:
        evidence.append({
            "EvidenceType": item["Category"],
            "ResourceId": item["RouteTableId"],
            "Direction": "",
            "Protocol": "",
            "Ports": "",
            "Source": item["Destination"],
            "Detail": (
                f"TargetType={item['TargetType']};"
                f"TargetId={item['TargetId']}"
            ),
        })

    security_group_result = {
        "SecurityGroupPosture": "NOT_APPLICABLE",
        "SecurityGroupFinding": (
            "Endpoint type does not use endpoint security groups"
        ),
        "BroadRules": [],
        "PeerAllowedRules": [],
        "ReferencedGroups": [],
        "MissingGroups": [],
        "Evidence": [],
    }

    if endpoint_type in {"Interface", "GatewayLoadBalancer"}:
        security_group_result = evaluate_endpoint_security_groups(
            group_ids,
            inventory.get("security_groups", {}),
            peer_cidrs,
            trusted_accounts,
        )

        evidence.extend(security_group_result["Evidence"])

    network_exposure = "RESTRICTED"
    network_finding = (
        "No confirmed untrusted endpoint network path was identified"
    )
    confidence = "MEDIUM"

    if endpoint_type == "Gateway":
        # Gateway endpoints do not support access through peering, TGW,
        # VPN or Direct Connect. Shared-subnet participants remain relevant.
        if shared_untrusted_principals:
            network_exposure = "POTENTIAL_CROSS_ACCOUNT"
            network_finding = (
                "Resources owned by an untrusted account may be placed in "
                "shared subnets of the endpoint VPC"
            )
            confidence = "HIGH"
        else:
            network_exposure = "RESTRICTED"
            network_finding = (
                "No untrusted VPC-subnet sharing was identified. Gateway "
                "endpoints are not reachable through VPC peering, Transit "
                "Gateway, VPN or Direct Connect."
            )
            confidence = "MEDIUM"

    elif endpoint_type == "Interface":
        sg_posture = security_group_result["SecurityGroupPosture"]

        if shared_untrusted_principals and sg_posture in {
            "BROAD",
            "CROSS_ACCOUNT_PATH_ALLOWED",
            "REVIEW",
        }:
            network_exposure = "POTENTIAL_CROSS_ACCOUNT"
            network_finding = (
                "Endpoint subnets are shared with untrusted principals and "
                "endpoint security groups do not conclusively prevent access"
            )
            confidence = "HIGH"

        elif sg_posture == "BROAD":
            if peerings or tgw_paths or route_indicators:
                network_exposure = "BROAD"
                network_finding = (
                    "Endpoint security groups allow broad inbound access and "
                    "the VPC has external or cross-account connectivity "
                    "indicators"
                )
                confidence = "HIGH"
            else:
                network_exposure = "BROAD"
                network_finding = (
                    "Endpoint security groups allow broad inbound access; no "
                    "cross-account path was confirmed, but the network control "
                    "is not restrictive"
                )
                confidence = "MEDIUM"

        elif (
            security_group_result["PeerAllowedRules"]
            and (peerings or tgw_paths)
        ):
            network_exposure = "POTENTIAL_CROSS_ACCOUNT"
            network_finding = (
                "A cross-account network path exists and endpoint security "
                "groups permit a matching source"
            )
            confidence = "HIGH"

        elif peerings or tgw_paths or route_indicators:
            network_exposure = "REVIEW"
            network_finding = (
                "Cross-account or external connectivity exists, but endpoint "
                "security groups did not conclusively allow that source"
            )
            confidence = "MEDIUM"

        elif sg_posture == "RESTRICTED":
            network_exposure = "RESTRICTED"
            network_finding = (
                "No broad endpoint security-group rule or confirmed "
                "cross-account network path was identified"
            )
            confidence = "MEDIUM"

        else:
            network_exposure = "UNKNOWN"
            network_finding = (
                "Endpoint security-group posture could not be fully resolved"
            )
            confidence = "LOW"

    elif endpoint_type == "GatewayLoadBalancer":
        if shared_untrusted_principals or peerings or tgw_paths:
            network_exposure = "REVIEW"
            network_finding = (
                "Gateway Load Balancer endpoint participates in an "
                "architecture with potential cross-account connectivity; "
                "manual route and service-owner validation is required"
            )
            confidence = "LOW"
        else:
            network_exposure = "RESTRICTED"
            network_finding = (
                "No cross-account sharing or connectivity indicator was "
                "identified for the Gateway Load Balancer endpoint"
            )
            confidence = "LOW"

    else:
        if shared_untrusted_principals or peerings or tgw_paths:
            network_exposure = "REVIEW"
            network_finding = (
                f"Endpoint type {endpoint_type} has cross-account network "
                f"indicators requiring manual validation"
            )
            confidence = "LOW"
        else:
            network_exposure = "UNKNOWN"
            network_finding = (
                f"Automated reachability classification for endpoint type "
                f"{endpoint_type} is limited"
            )
            confidence = "LOW"

    return {
        "NetworkExposure": network_exposure,
        "NetworkFinding": network_finding,
        "NetworkConfidence": confidence,
        "SecurityGroupPosture": security_group_result[
            "SecurityGroupPosture"
        ],
        "SecurityGroupFinding": security_group_result[
            "SecurityGroupFinding"
        ],
        "SharedUntrustedPrincipals": shared_untrusted_principals,
        "CrossAccountPeerings": peerings,
        "CrossAccountTgwPaths": tgw_paths,
        "ExternalRouteIndicators": route_indicators,
        "SecurityGroupBroadRules": security_group_result["BroadRules"],
        "SecurityGroupPeerAllowedRules": security_group_result[
            "PeerAllowedRules"
        ],
        "Evidence": evidence,
    }


# ============================================================
# FINAL STATUS
# ============================================================

def calculate_effective_risk(
    technical_status: str,
    network_exposure: str,
) -> Tuple[str, str]:
    if technical_status == "COMPLIANT":
        if network_exposure in {"UNKNOWN", "REVIEW"}:
            return (
                "REVIEW",
                "Policy is trusted-account restricted, but network posture "
                "requires review",
            )

        return (
            "LOW",
            "Endpoint policy limits access to trusted accounts",
        )

    if technical_status == "NON_COMPLIANT":
        if network_exposure in {
            "BROAD",
            "POTENTIAL_CROSS_ACCOUNT",
        }:
            return (
                "HIGH",
                "Open or untrusted endpoint policy is combined with a "
                "potentially usable untrusted network path",
            )

        if network_exposure == "RESTRICTED":
            return (
                "MITIGATED",
                "Endpoint policy remains technically non-compliant, but no "
                "confirmed untrusted network path was identified",
            )

        return (
            "REVIEW",
            "Endpoint policy is technically non-compliant and network "
            "reachability could not be conclusively determined",
        )

    if technical_status == "REVIEW":
        return (
            "REVIEW",
            "Policy or network conditions require manual validation",
        )

    return (
        "UNKNOWN",
        "Endpoint could not be fully evaluated",
    )


# ============================================================
# ROW CREATION
# ============================================================

def base_summary_row(
    account_id: str,
    region: str,
    endpoint: Dict[str, Any],
    partition: str,
) -> Dict[str, Any]:
    endpoint_id = endpoint.get("VpcEndpointId", "")

    return {
        "Account": account_id,
        "Region": region,
        "Control": CONTROL_NAME,
        "VpcEndpointId": endpoint_id,
        "VpcEndpointArn": endpoint_arn(
            partition,
            region,
            account_id,
            endpoint_id,
        ),
        "Name": get_name_tag(endpoint),
        "VpcEndpointType": endpoint.get("VpcEndpointType", ""),
        "State": endpoint.get("State", ""),
        "VpcId": endpoint.get("VpcId", ""),
        "ServiceName": endpoint.get("ServiceName", ""),
        "ServiceRegion": endpoint.get("ServiceRegion", ""),
        "ServiceNetworkArn": endpoint.get("ServiceNetworkArn", ""),
        "ResourceConfigurationArn": endpoint.get(
            "ResourceConfigurationArn",
            "",
        ),
        "OwnerId": endpoint.get("OwnerId", account_id),
        "RequesterManaged": endpoint.get("RequesterManaged", False),
        "PrivateDnsEnabled": endpoint.get("PrivateDnsEnabled", ""),
        "IpAddressType": endpoint.get("IpAddressType", ""),
        "DnsOptions": json_string(endpoint.get("DnsOptions", {})),
        "SubnetIds": join_values(endpoint.get("SubnetIds", [])),
        "RouteTableIds": join_values(endpoint.get("RouteTableIds", [])),
        "SecurityGroupIds": join_values(
            group.get("GroupId")
            for group in endpoint.get("Groups", []) or []
        ),
        "NetworkInterfaceIds": join_values(
            endpoint.get("NetworkInterfaceIds", [])
        ),
        "CreationTimestamp": timestamp_to_text(
            endpoint.get("CreationTimestamp")
        ),
        "PolicyDocument": endpoint.get("PolicyDocument", ""),
        "TechnicalStatus": "",
        "PolicyFinding": "",
        "WildcardPrincipal": "",
        "TrustedPrincipals": "",
        "UntrustedPrincipals": "",
        "ServicePrincipals": "",
        "ComplexPolicyElements": "",
        "NetworkExposure": "",
        "NetworkConfidence": "",
        "NetworkFinding": "",
        "SecurityGroupPosture": "",
        "SecurityGroupFinding": "",
        "SharedUntrustedPrincipals": "",
        "CrossAccountPeerings": "",
        "CrossAccountTgwPaths": "",
        "ExternalRouteIndicators": "",
        "SecurityGroupBroadRules": "",
        "SecurityGroupPeerAllowedRules": "",
        "EffectiveRiskStatus": "",
        "EffectiveRiskFinding": "",
        "EvaluationStatus": "EVALUATED",
        "Error": "",
    }


def skipped_summary_row(
    account_id: str,
    region: str,
    partition: str,
    error: Exception,
) -> Dict[str, Any]:
    row = base_summary_row(
        account_id,
        region,
        {"VpcEndpointId": "N/A"},
        partition,
    )

    row.update({
        "TechnicalStatus": "SKIPPED",
        "NetworkExposure": "UNKNOWN",
        "NetworkConfidence": "LOW",
        "EffectiveRiskStatus": "UNKNOWN",
        "EvaluationStatus": "SKIPPED",
        "Error": compact_error(error),
    })

    return row


# ============================================================
# MAIN CONTROL
# ============================================================

def check_vpc_endpoints(
    session: boto3.Session,
    trusted_accounts: Set[str],
    regions: List[str],
    include_inactive: bool,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    account_id = get_account_id(session)
    partition = get_partition(session)

    summary_rows: List[Dict[str, Any]] = []
    evidence_rows: List[Dict[str, Any]] = []

    print(f"\nAccount              : {account_id}")
    print(f"Trusted accounts     : {', '.join(sorted(trusted_accounts))}")
    print(f"Regions to scan      : {len(regions)}")
    print(f"Include inactive     : {include_inactive}\n")

    region_bar = tqdm(
        regions,
        desc="Scanning Regions",
        unit="region",
        position=0,
    )

    for region in region_bar:
        region_bar.set_postfix_str(region)

        try:
            ec2 = session.client("ec2", region_name=region)

            endpoints = paginate_items(
                ec2,
                "describe_vpc_endpoints",
                "VpcEndpoints",
            )

        except (ClientError, BotoCoreError) as error:
            summary_rows.append(
                skipped_summary_row(
                    account_id,
                    region,
                    partition,
                    error,
                )
            )
            continue

        if not include_inactive:
            endpoints = [
                endpoint
                for endpoint in endpoints
                if endpoint.get("State") in ACTIVE_ENDPOINT_STATES
            ]

        if not endpoints:
            continue

        inventory, inventory_errors = load_regional_inventory(ec2)

        shared_subnet_principals, ram_errors = (
            get_shared_subnet_principals(
                session,
                region,
            )
        )

        regional_errors = inventory_errors + ram_errors

        endpoint_bar = tqdm(
            endpoints,
            desc=f"{region} endpoints",
            unit="endpoint",
            leave=False,
            position=1,
        )

        for endpoint in endpoint_bar:
            endpoint_id = endpoint.get("VpcEndpointId", "UNKNOWN")
            endpoint_bar.set_postfix_str(endpoint_id)

            row = base_summary_row(
                account_id,
                region,
                endpoint,
                partition,
            )

            try:
                policy_document = decode_policy_document(
                    endpoint.get("PolicyDocument")
                )

                policy_result = evaluate_policy(
                    policy_document,
                    trusted_accounts,
                )

                network_result = evaluate_network_exposure(
                    endpoint,
                    inventory,
                    shared_subnet_principals,
                    trusted_accounts,
                )

                effective_risk, effective_finding = (
                    calculate_effective_risk(
                        policy_result["TechnicalStatus"],
                        network_result["NetworkExposure"],
                    )
                )

                row.update({
                    "TechnicalStatus": policy_result[
                        "TechnicalStatus"
                    ],
                    "PolicyFinding": policy_result["PolicyFinding"],
                    "WildcardPrincipal": policy_result[
                        "WildcardPrincipal"
                    ],
                    "TrustedPrincipals": join_values(
                        policy_result["TrustedPrincipals"]
                    ),
                    "UntrustedPrincipals": join_values(
                        policy_result["UntrustedPrincipals"]
                    ),
                    "ServicePrincipals": join_values(
                        policy_result["ServicePrincipals"]
                    ),
                    "ComplexPolicyElements": join_values(
                        policy_result["ComplexStatements"]
                    ),
                    "NetworkExposure": network_result[
                        "NetworkExposure"
                    ],
                    "NetworkConfidence": network_result[
                        "NetworkConfidence"
                    ],
                    "NetworkFinding": network_result["NetworkFinding"],
                    "SecurityGroupPosture": network_result[
                        "SecurityGroupPosture"
                    ],
                    "SecurityGroupFinding": network_result[
                        "SecurityGroupFinding"
                    ],
                    "SharedUntrustedPrincipals": json_string(
                        network_result["SharedUntrustedPrincipals"]
                    ),
                    "CrossAccountPeerings": json_string(
                        network_result["CrossAccountPeerings"]
                    ),
                    "CrossAccountTgwPaths": json_string(
                        network_result["CrossAccountTgwPaths"]
                    ),
                    "ExternalRouteIndicators": json_string(
                        network_result["ExternalRouteIndicators"]
                    ),
                    "SecurityGroupBroadRules": join_values(
                        network_result["SecurityGroupBroadRules"]
                    ),
                    "SecurityGroupPeerAllowedRules": join_values(
                        network_result[
                            "SecurityGroupPeerAllowedRules"
                        ]
                    ),
                    "EffectiveRiskStatus": effective_risk,
                    "EffectiveRiskFinding": effective_finding,
                })

                for item in network_result["Evidence"]:
                    evidence_rows.append({
                        "Account": account_id,
                        "Region": region,
                        "Control": CONTROL_NAME,
                        "VpcEndpointId": endpoint_id,
                        "VpcEndpointArn": row["VpcEndpointArn"],
                        "VpcEndpointType": row["VpcEndpointType"],
                        "VpcId": row["VpcId"],
                        "ServiceName": row["ServiceName"],
                        "TechnicalStatus": row["TechnicalStatus"],
                        "NetworkExposure": row["NetworkExposure"],
                        "EffectiveRiskStatus": row[
                            "EffectiveRiskStatus"
                        ],
                        "EvidenceType": item.get(
                            "EvidenceType",
                            "",
                        ),
                        "ResourceId": item.get("ResourceId", ""),
                        "Direction": item.get("Direction", ""),
                        "Protocol": item.get("Protocol", ""),
                        "Ports": item.get("Ports", ""),
                        "Source": item.get("Source", ""),
                        "Detail": item.get("Detail", ""),
                    })

                for regional_error in regional_errors:
                    evidence_rows.append({
                        "Account": account_id,
                        "Region": region,
                        "Control": CONTROL_NAME,
                        "VpcEndpointId": endpoint_id,
                        "VpcEndpointArn": row["VpcEndpointArn"],
                        "VpcEndpointType": row["VpcEndpointType"],
                        "VpcId": row["VpcId"],
                        "ServiceName": row["ServiceName"],
                        "TechnicalStatus": row["TechnicalStatus"],
                        "NetworkExposure": row["NetworkExposure"],
                        "EffectiveRiskStatus": row[
                            "EffectiveRiskStatus"
                        ],
                        "EvidenceType": "INVENTORY_WARNING",
                        "ResourceId": "",
                        "Direction": "",
                        "Protocol": "",
                        "Ports": "",
                        "Source": "",
                        "Detail": regional_error,
                    })

                if regional_errors:
                    row["Error"] = join_values(regional_errors)

            except Exception as error:
                row.update({
                    "TechnicalStatus": "REVIEW",
                    "PolicyFinding": (
                        "Endpoint evaluation failed before a reliable "
                        "technical conclusion could be reached"
                    ),
                    "NetworkExposure": "UNKNOWN",
                    "NetworkConfidence": "LOW",
                    "NetworkFinding": (
                        "Network exposure could not be evaluated"
                    ),
                    "EffectiveRiskStatus": "REVIEW",
                    "EffectiveRiskFinding": (
                        "Manual validation required due to evaluation error"
                    ),
                    "EvaluationStatus": "PARTIAL",
                    "Error": compact_error(error),
                })

            summary_rows.append(row)

    return summary_rows, evidence_rows


# ============================================================
# CSV OUTPUT
# ============================================================

SUMMARY_FIELDS = [
    "Account",
    "Region",
    "Control",
    "VpcEndpointId",
    "VpcEndpointArn",
    "Name",
    "VpcEndpointType",
    "State",
    "VpcId",
    "ServiceName",
    "ServiceRegion",
    "ServiceNetworkArn",
    "ResourceConfigurationArn",
    "OwnerId",
    "RequesterManaged",
    "PrivateDnsEnabled",
    "IpAddressType",
    "DnsOptions",
    "SubnetIds",
    "RouteTableIds",
    "SecurityGroupIds",
    "NetworkInterfaceIds",
    "CreationTimestamp",
    "TechnicalStatus",
    "PolicyFinding",
    "WildcardPrincipal",
    "TrustedPrincipals",
    "UntrustedPrincipals",
    "ServicePrincipals",
    "ComplexPolicyElements",
    "NetworkExposure",
    "NetworkConfidence",
    "NetworkFinding",
    "SecurityGroupPosture",
    "SecurityGroupFinding",
    "SharedUntrustedPrincipals",
    "CrossAccountPeerings",
    "CrossAccountTgwPaths",
    "ExternalRouteIndicators",
    "SecurityGroupBroadRules",
    "SecurityGroupPeerAllowedRules",
    "EffectiveRiskStatus",
    "EffectiveRiskFinding",
    "EvaluationStatus",
    "Error",
    "PolicyDocument",
]

EVIDENCE_FIELDS = [
    "Account",
    "Region",
    "Control",
    "VpcEndpointId",
    "VpcEndpointArn",
    "VpcEndpointType",
    "VpcId",
    "ServiceName",
    "TechnicalStatus",
    "NetworkExposure",
    "EffectiveRiskStatus",
    "EvidenceType",
    "ResourceId",
    "Direction",
    "Protocol",
    "Ports",
    "Source",
    "Detail",
]


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

        for row in rows:
            writer.writerow(row)


# ============================================================
# TERMINAL SUMMARY
# ============================================================

def print_summary(
    account_id: str,
    summary_rows: List[Dict[str, Any]],
) -> None:
    actual_rows = [
        row
        for row in summary_rows
        if row.get("VpcEndpointId") != "N/A"
    ]

    total = len(actual_rows)

    technical_counts: Dict[str, int] = defaultdict(int)
    network_counts: Dict[str, int] = defaultdict(int)
    risk_counts: Dict[str, int] = defaultdict(int)
    type_counts: Dict[str, int] = defaultdict(int)

    for row in actual_rows:
        technical_counts[row.get("TechnicalStatus", "UNKNOWN")] += 1
        network_counts[row.get("NetworkExposure", "UNKNOWN")] += 1
        risk_counts[row.get("EffectiveRiskStatus", "UNKNOWN")] += 1
        type_counts[row.get("VpcEndpointType", "Unknown")] += 1

    skipped_regions = sum(
        1
        for row in summary_rows
        if row.get("EvaluationStatus") == "SKIPPED"
    )

    print("\n============================================================")
    print(f"CONTROL : {CONTROL_NAME}")
    print(f"ACCOUNT : {account_id}")
    print("============================================================")

    print(f"\nTotal VPC endpoints evaluated : {total}")
    print(f"Skipped region records        : {skipped_regions}")

    print("\nEndpoint types")
    print("------------------------------------------------------------")
    for endpoint_type, count in sorted(type_counts.items()):
        print(f"{endpoint_type:<32}: {count}")

    print("\nTechnical policy status")
    print("------------------------------------------------------------")
    for status in [
        "COMPLIANT",
        "NON_COMPLIANT",
        "REVIEW",
        "SKIPPED",
        "UNKNOWN",
    ]:
        print(f"{status:<32}: {technical_counts.get(status, 0)}")

    print("\nNetwork exposure")
    print("------------------------------------------------------------")
    for status in [
        "RESTRICTED",
        "POTENTIAL_CROSS_ACCOUNT",
        "BROAD",
        "REVIEW",
        "UNKNOWN",
    ]:
        print(f"{status:<32}: {network_counts.get(status, 0)}")

    print("\nEffective risk")
    print("------------------------------------------------------------")
    for status in [
        "LOW",
        "MITIGATED",
        "HIGH",
        "REVIEW",
        "UNKNOWN",
    ]:
        print(f"{status:<32}: {risk_counts.get(status, 0)}")

    if technical_counts.get("NON_COMPLIANT", 0) > 0:
        overall = "NON_COMPLIANT"
    elif technical_counts.get("REVIEW", 0) > 0:
        overall = "REVIEW"
    elif total == 0:
        overall = "NO_RESOURCES"
    else:
        overall = "COMPLIANT"

    print(f"\nOVERALL TECHNICAL STATUS: {overall}")
    print("============================================================\n")


def print_high_risk_endpoints(
    summary_rows: List[Dict[str, Any]],
    limit: int = 25,
) -> None:
    high_risk = [
        row
        for row in summary_rows
        if row.get("EffectiveRiskStatus") in {"HIGH", "REVIEW"}
        and row.get("VpcEndpointId") != "N/A"
    ]

    if not high_risk:
        return

    print("Endpoints requiring immediate review")
    print("------------------------------------------------------------")

    for row in high_risk[:limit]:
        print(
            f"{row['Region']:<15} "
            f"{row['VpcEndpointId']:<24} "
            f"{row['VpcEndpointType']:<20} "
            f"Policy={row['TechnicalStatus']:<14} "
            f"Network={row['NetworkExposure']:<24} "
            f"Risk={row['EffectiveRiskStatus']}"
        )

    if len(high_risk) > limit:
        print(
            f"...and {len(high_risk) - limit} additional endpoints. "
            f"Review the summary CSV."
        )

    print()


# ============================================================
# ARGUMENTS
# ============================================================

def parse_trusted_accounts(
    own_account_id: str,
    account_arguments: List[str],
) -> Set[str]:
    trusted = {own_account_id}

    for argument in account_arguments:
        for account in argument.split(","):
            account = account.strip()

            if not account:
                continue

            if not ACCOUNT_ID_PATTERN.fullmatch(account):
                raise ValueError(
                    f"Invalid trusted account ID: {account}. "
                    f"Expected exactly 12 digits."
                )

            trusted.add(account)

    return trusted


def main() -> None:
    parser = argparse.ArgumentParser(
        description=CONTROL_NAME,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "-R",
        "--role-arn",
        help="IAM role ARN to assume before performing the audit",
    )

    parser.add_argument(
        "--trusted-account",
        action="append",
        default=[],
        help=(
            "Trusted 12-digit AWS account ID. May be repeated or supplied "
            "as a comma-separated list. The scanned account is trusted "
            "automatically."
        ),
    )

    parser.add_argument(
        "--regions",
        nargs="+",
        help=(
            "Regions to scan. When omitted, all enabled regions are scanned."
        ),
    )

    parser.add_argument(
        "--include-inactive",
        action="store_true",
        help=(
            "Include endpoints whose state is not available or pending."
        ),
    )

    parser.add_argument(
        "--output-dir",
        default=".",
        help="Directory in which CSV reports will be written",
    )

    parser.add_argument(
        "--high-risk-print-limit",
        type=int,
        default=25,
        help=(
            "Maximum number of HIGH/REVIEW endpoints printed to the terminal"
        ),
    )

    args = parser.parse_args()

    try:
        session = get_session(args.role_arn)
        account_id = get_account_id(session)

        trusted_accounts = parse_trusted_accounts(
            account_id,
            args.trusted_account,
        )

        if args.regions:
            regions = sorted(set(args.regions))
        else:
            regions = get_enabled_regions(session)

        os.makedirs(args.output_dir, exist_ok=True)

        summary_rows, evidence_rows = check_vpc_endpoints(
            session=session,
            trusted_accounts=trusted_accounts,
            regions=regions,
            include_inactive=args.include_inactive,
        )

        summary_filename = os.path.join(
            args.output_dir,
            f"vpc_endpoint_trusted_accounts_summary_{account_id}.csv",
        )

        evidence_filename = os.path.join(
            args.output_dir,
            f"vpc_endpoint_trusted_accounts_evidence_{account_id}.csv",
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

        print_summary(account_id, summary_rows)

        print_high_risk_endpoints(
            summary_rows,
            limit=max(args.high_risk_print_limit, 0),
        )

        print(f"Summary CSV  : {summary_filename}")
        print(f"Evidence CSV : {evidence_filename}\n")

    except KeyboardInterrupt:
        print("\nAudit interrupted by user.", file=sys.stderr)
        sys.exit(130)

    except Exception as error:
        print(
            f"\nFatal error: {compact_error(error)}",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
