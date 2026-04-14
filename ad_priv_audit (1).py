#!/usr/bin/env python3
"""
AD Privileged Group Discovery & Analysis Tool v2
-------------------------------------------------
Enumerates privileged AD groups, maps nested membership,
identifies privilege creep and conflicts, and generates
an interactive HTML report.

Changes in v2:
  - Group member caching: each group is only queried once via PowerShell
  - Findings display: "Display Name (samAccountName)" format
  - Nesting tiers: Inherited (1 level) / Deep (2) / Deeply Nested (3+)
  - Tree visualization: multi-appearance groups highlighted, depth gradient,
    tooltips, nesting summary panel

Requires: Python 3.8+, PowerShell with ActiveDirectory module
Run from a domain-joined workstation with appropriate read permissions.

Usage:
    python ad_priv_audit.py                     # Full audit, default groups
    python ad_priv_audit.py --discover          # Auto-discover privileged groups first
    python ad_priv_audit.py --groups "Domain Admins" "Enterprise Admins"
    python ad_priv_audit.py --search-user jsmith
    python ad_priv_audit.py --search-group "Server Admins"
    python ad_priv_audit.py --demo              # Generate report with mock data
"""

import subprocess
import json
import sys
import argparse
import re
import os
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

# ============================================================================
# Configuration
# ============================================================================

DEFAULT_TIER0_GROUPS = [
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Backup Operators",
    "Server Operators",
    "Print Operators",
]

DISCOVERY_NAME_PATTERNS = [
    r"admin", r"operator", r"privilege", r"elevated",
    r"tier\s*0", r"t0[\s\-_]", r"domain\s*controller",
    r"dc\s*access", r"root", r"super\s*user",
]

GUID_REPL_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
GUID_REPL_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"

STALE_LOGON_DAYS = 90
STALE_PASSWORD_DAYS = 180
MULTI_GROUP_CREEP_THRESHOLD = 2

# ============================================================================
# PowerShell Interface
# ============================================================================

def run_ps(command: str, timeout: int = 120) -> Optional[str]:
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True, text=True, timeout=timeout
        )
        if result.returncode != 0:
            print(f"[!] PowerShell error: {result.stderr.strip()}", file=sys.stderr)
            return None
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        print("[!] PowerShell command timed out", file=sys.stderr)
        return None
    except FileNotFoundError:
        print("[!] PowerShell not found. Run this on a Windows workstation.", file=sys.stderr)
        return None


def ps_json(command: str, timeout: int = 120) -> Optional[list | dict]:
    raw = run_ps(command, timeout)
    if not raw:
        return None
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            data = [data]
        return data
    except json.JSONDecodeError as e:
        print(f"[!] JSON parse error: {e}", file=sys.stderr)
        return None


# ============================================================================
# Data Model
# ============================================================================

@dataclass
class ADObject:
    name: str
    sam_account_name: str
    distinguished_name: str
    object_class: str
    enabled: Optional[bool] = None
    last_logon: Optional[str] = None
    password_last_set: Optional[str] = None
    password_never_expires: bool = False
    admin_count: Optional[int] = None
    description: str = ""
    when_created: Optional[str] = None
    member_of_direct: list = field(default_factory=list)

    @property
    def display_label(self) -> str:
        """Display Name (samAccountName) format for findings."""
        if self.name and self.name != self.sam_account_name:
            return f"{self.name} ({self.sam_account_name})"
        return self.sam_account_name


@dataclass
class GroupNode:
    name: str
    distinguished_name: str
    depth: int
    parent_path: list
    direct_members: list = field(default_factory=list)
    child_groups: list = field(default_factory=list)


@dataclass
class Finding:
    severity: str
    category: str
    account: str       # Display Name (samAccountName) format
    sam: str           # Raw SAM for dedup
    detail: str
    inheritance_path: str = ""


@dataclass
class DiscoveryResult:
    group_name: str
    distinguished_name: str
    discovery_method: str
    detail: str
    already_known: bool = False


# ============================================================================
# Group Member Cache
# ============================================================================

_member_cache: dict[str, Optional[list[dict]]] = {}
_cache_hits = 0
_cache_misses = 0


def get_group_direct_members(group_name: str) -> Optional[list[dict]]:
    """Get direct members with caching — each group queried only once."""
    global _cache_hits, _cache_misses
    cache_key = group_name.lower()

    if cache_key in _member_cache:
        _cache_hits += 1
        return _member_cache[cache_key]

    _cache_misses += 1
    cmd = f"""
    Get-ADGroupMember -Identity '{group_name}' |
    ForEach-Object {{
        $obj = $_
        $extra = @{{
            Name = $obj.Name
            SamAccountName = $obj.SamAccountName
            distinguishedName = $obj.distinguishedName
            objectClass = $obj.objectClass
        }}
        if ($obj.objectClass -ne 'group') {{
            $user = Get-ADUser -Identity $obj.SamAccountName -Properties `
                Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires, `
                AdminCount, Description, whenCreated, MemberOf -ErrorAction SilentlyContinue
            if ($user) {{
                $extra['Enabled'] = $user.Enabled
                $extra['LastLogonDate'] = if ($user.LastLogonDate) {{ $user.LastLogonDate.ToString('o') }} else {{ $null }}
                $extra['PasswordLastSet'] = if ($user.PasswordLastSet) {{ $user.PasswordLastSet.ToString('o') }} else {{ $null }}
                $extra['PasswordNeverExpires'] = $user.PasswordNeverExpires
                $extra['AdminCount'] = $user.AdminCount
                $extra['Description'] = $user.Description
                $extra['whenCreated'] = if ($user.whenCreated) {{ $user.whenCreated.ToString('o') }} else {{ $null }}
                $extra['MemberOf'] = @($user.MemberOf | ForEach-Object {{ ($_ -split ',')[0] -replace 'CN=' }})
            }}
        }}
        [PSCustomObject]$extra
    }} | ConvertTo-Json -Depth 3
    """
    result = ps_json(cmd)
    _member_cache[cache_key] = result
    return result


def get_cache_stats() -> tuple[int, int]:
    return _cache_hits, _cache_misses


# ============================================================================
# Auto-Discovery Engine
# ============================================================================

def discover_admincount_groups() -> list[DiscoveryResult]:
    print("  [1/3] Querying AdminCount=1 groups...")
    cmd = """
    Get-ADGroup -Filter {AdminCount -eq 1} -Properties AdminCount, Description |
    Select Name, DistinguishedName, Description |
    ConvertTo-Json -Depth 2
    """
    results = ps_json(cmd)
    if not results:
        return []
    discovered = []
    defaults_lower = {g.lower() for g in DEFAULT_TIER0_GROUPS}
    for g in results:
        name = g.get("Name", "")
        discovered.append(DiscoveryResult(
            group_name=name, distinguished_name=g.get("DistinguishedName", ""),
            discovery_method="admincount",
            detail=f"AdminCount=1 (AdminSDHolder protected). {g.get('Description', '')}".strip(),
            already_known=name.lower() in defaults_lower
        ))
    return discovered


def discover_name_pattern_groups() -> list[DiscoveryResult]:
    print("  [2/3] Searching groups by naming patterns...")
    cmd = """
    Get-ADGroup -Filter * -Properties Description |
    Select Name, DistinguishedName, Description |
    ConvertTo-Json -Depth 2 -Compress
    """
    results = ps_json(cmd, timeout=180)
    if not results:
        return []
    compiled = [re.compile(p, re.IGNORECASE) for p in DISCOVERY_NAME_PATTERNS]
    defaults_lower = {g.lower() for g in DEFAULT_TIER0_GROUPS}
    discovered = []
    for g in results:
        name = g.get("Name", "")
        for pattern in compiled:
            if pattern.search(name):
                discovered.append(DiscoveryResult(
                    group_name=name, distinguished_name=g.get("DistinguishedName", ""),
                    discovery_method="name_pattern",
                    detail=f"Name matches pattern /{pattern.pattern}/. {g.get('Description', '')}".strip(),
                    already_known=name.lower() in defaults_lower
                ))
                break
    return discovered


def discover_dangerous_acls() -> list[DiscoveryResult]:
    print("  [3/3] Checking ACLs on high-value objects...")
    discovered = []
    defaults_lower = {g.lower() for g in DEFAULT_TIER0_GROUPS}

    print("    Checking DCSync rights...")
    dcsync_cmd = f"""
    $domain = (Get-ADDomain).DistinguishedName
    $acls = (Get-Acl "AD:\\$domain").Access |
        Where-Object {{
            ($_.ObjectType -eq '{GUID_REPL_CHANGES}' -or
             $_.ObjectType -eq '{GUID_REPL_CHANGES_ALL}') -and
            $_.AccessControlType -eq 'Allow'
        }}
    $acls | ForEach-Object {{
        $identity = $_.IdentityReference.Value
        try {{
            $obj = Get-ADObject -Filter "SAMAccountName -eq '$($identity.Split('\\')[-1])'" -Properties objectClass
            [PSCustomObject]@{{
                Identity = $identity
                Right = if ($_.ObjectType -eq '{GUID_REPL_CHANGES}') {{ 'Repl-Changes' }} else {{ 'Repl-Changes-All' }}
                ObjectClass = $obj.objectClass
                DN = $obj.DistinguishedName
            }}
        }} catch {{}}
    }} | Where-Object {{ $_.ObjectClass -eq 'group' }} | ConvertTo-Json -Depth 2
    """
    dcsync_results = ps_json(dcsync_cmd, timeout=180)
    if dcsync_results:
        for r in dcsync_results:
            name = r.get("Identity", "").split("\\")[-1]
            discovered.append(DiscoveryResult(
                group_name=name, distinguished_name=r.get("DN", ""),
                discovery_method="acl_dcsync",
                detail=f"Has {r.get('Right', 'DCSync')} rights on domain root - can extract password hashes",
                already_known=name.lower() in defaults_lower
            ))

    print("    Checking write access to Tier 0 groups...")
    for target_group in ["Domain Admins", "Enterprise Admins", "Administrators"]:
        acl_cmd = f"""
        try {{
            $dn = (Get-ADGroup '{target_group}').DistinguishedName
            $acls = (Get-Acl "AD:\\$dn").Access |
                Where-Object {{
                    ($_.ActiveDirectoryRights -match 'WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner') -and
                    $_.AccessControlType -eq 'Allow' -and
                    $_.IsInherited -eq $false
                }}
            $acls | ForEach-Object {{
                $identity = $_.IdentityReference.Value
                try {{
                    $samName = $identity.Split('\\')[-1]
                    $obj = Get-ADObject -Filter "SAMAccountName -eq '$samName'" -Properties objectClass
                    if ($obj.objectClass -eq 'group') {{
                        [PSCustomObject]@{{
                            Identity = $identity
                            Rights = $_.ActiveDirectoryRights.ToString()
                            Target = '{target_group}'
                            DN = $obj.DistinguishedName
                        }}
                    }}
                }} catch {{}}
            }} | ConvertTo-Json -Depth 2
        }} catch {{}}
        """
        results = ps_json(acl_cmd, timeout=120)
        if results:
            for r in results:
                name = r.get("Identity", "").split("\\")[-1]
                discovered.append(DiscoveryResult(
                    group_name=name, distinguished_name=r.get("DN", ""),
                    discovery_method="acl_group_write",
                    detail=f"Has {r.get('Rights', 'write')} on {r.get('Target', target_group)} - can modify membership",
                    already_known=name.lower() in defaults_lower
                ))

    print("    Checking GPO modification rights on DC OU...")
    gpo_cmd = """
    try {
        $dcOU = (Get-ADDomain).DomainControllersContainer
        $links = (Get-ADObject $dcOU -Properties gPLink).gPLink
        if ($links) {
            $guids = [regex]::Matches($links, '\\{([^}]+)\\}') | ForEach-Object { $_.Groups[1].Value }
            foreach ($guid in $guids) {
                try {
                    $gpo = Get-GPO -Guid $guid -ErrorAction SilentlyContinue
                    if ($gpo) {
                        $acls = Get-GPPermission -Guid $guid -All |
                            Where-Object { $_.Permission -match 'GpoEdit|GpoEditDeleteModifySecurity' -and $_.Trustee.SidType -eq 'Group' }
                        foreach ($acl in $acls) {
                            [PSCustomObject]@{
                                GPOName = $gpo.DisplayName
                                GroupName = $acl.Trustee.Name
                                Permission = $acl.Permission.ToString()
                            }
                        }
                    }
                } catch {}
            }
        }
    } catch {} | ConvertTo-Json -Depth 2
    """
    gpo_results = ps_json(gpo_cmd, timeout=120)
    if gpo_results:
        for r in gpo_results:
            name = r.get("GroupName", "")
            discovered.append(DiscoveryResult(
                group_name=name, distinguished_name="",
                discovery_method="acl_gpo_write",
                detail=f"Can edit GPO '{r.get('GPOName', '?')}' linked to Domain Controllers OU ({r.get('Permission', '')})",
                already_known=name.lower() in defaults_lower
            ))

    print("    Checking dangerous rights on domain root...")
    domain_cmd = f"""
    try {{
        $domain = (Get-ADDomain).DistinguishedName
        $acls = (Get-Acl "AD:\\$domain").Access |
            Where-Object {{
                ($_.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner') -and
                $_.AccessControlType -eq 'Allow' -and
                $_.IsInherited -eq $false
            }}
        $acls | ForEach-Object {{
            $identity = $_.IdentityReference.Value
            try {{
                $samName = $identity.Split('\\')[-1]
                $obj = Get-ADObject -Filter "SAMAccountName -eq '$samName'" -Properties objectClass
                if ($obj.objectClass -eq 'group') {{
                    [PSCustomObject]@{{
                        Identity = $identity
                        Rights = $_.ActiveDirectoryRights.ToString()
                        DN = $obj.DistinguishedName
                    }}
                }}
            }} catch {{}}
        }} | ConvertTo-Json -Depth 2
    }} catch {{}}
    """
    domain_results = ps_json(domain_cmd, timeout=120)
    if domain_results:
        for r in domain_results:
            name = r.get("Identity", "").split("\\")[-1]
            discovered.append(DiscoveryResult(
                group_name=name, distinguished_name=r.get("DN", ""),
                discovery_method="acl_domain_write",
                detail=f"Has {r.get('Rights', 'dangerous rights')} on domain root object",
                already_known=name.lower() in defaults_lower
            ))

    return discovered


def run_full_discovery() -> tuple[list[str], list[DiscoveryResult]]:
    print("\n[*] Running auto-discovery...\n")
    all_discovered = []
    all_discovered.extend(discover_admincount_groups())
    all_discovered.extend(discover_name_pattern_groups())
    all_discovered.extend(discover_dangerous_acls())

    method_priority = {
        "acl_dcsync": 0, "acl_domain_write": 1, "acl_group_write": 2,
        "acl_gpo_write": 3, "admincount": 4, "name_pattern": 5, "builtin": 6
    }
    best_per_group = {}
    for d in all_discovered:
        key = d.group_name.lower()
        if key not in best_per_group or method_priority.get(d.discovery_method, 99) < method_priority.get(best_per_group[key].discovery_method, 99):
            best_per_group[key] = d
    deduped = list(best_per_group.values())

    merged_names = list(DEFAULT_TIER0_GROUPS)
    for d in deduped:
        if not d.already_known and d.group_name not in merged_names:
            merged_names.append(d.group_name)

    for g in DEFAULT_TIER0_GROUPS:
        if g.lower() not in best_per_group:
            deduped.append(DiscoveryResult(
                group_name=g, distinguished_name="", discovery_method="builtin",
                detail="Built-in privileged group", already_known=True
            ))

    new_groups = [d for d in deduped if not d.already_known]
    print(f"\n  Discovery Summary:")
    print(f"    Built-in Tier 0 groups:    {len(DEFAULT_TIER0_GROUPS)}")
    print(f"    AdminCount groups found:   {sum(1 for d in all_discovered if d.discovery_method == 'admincount')}")
    print(f"    Name pattern matches:      {sum(1 for d in all_discovered if d.discovery_method == 'name_pattern')}")
    print(f"    Dangerous ACL grants:      {sum(1 for d in all_discovered if d.discovery_method.startswith('acl_'))}")
    print(f"    New groups to enumerate:   {len(new_groups)}")
    if new_groups:
        for d in new_groups:
            print(f"      + {d.group_name} [{d.discovery_method}]")
    print(f"    Total groups for audit:    {len(merged_names)}")

    return merged_names, deduped


# ============================================================================
# Demo Data
# ============================================================================

def generate_demo_discovery() -> list[DiscoveryResult]:
    return [
        DiscoveryResult("Domain Admins", "", "admincount", "AdminCount=1 (AdminSDHolder protected)", True),
        DiscoveryResult("Enterprise Admins", "", "admincount", "AdminCount=1 (AdminSDHolder protected)", True),
        DiscoveryResult("Schema Admins", "", "admincount", "AdminCount=1 (AdminSDHolder protected)", True),
        DiscoveryResult("Administrators", "", "admincount", "AdminCount=1 (AdminSDHolder protected)", True),
        DiscoveryResult("Backup Operators", "", "admincount", "AdminCount=1 (AdminSDHolder protected)", True),
        DiscoveryResult("SQL Server Admins", "", "name_pattern", "Name matches pattern /admin/. SQL DBA team", False),
        DiscoveryResult("Citrix Admins", "", "name_pattern", "Name matches pattern /admin/. Citrix farm", False),
        DiscoveryResult("Workstation Administrators", "", "name_pattern", "Name matches pattern /admin/", False),
        DiscoveryResult("Exchange Operators", "", "name_pattern", "Name matches pattern /operator/", False),
        DiscoveryResult("IT Automation Svc", "", "acl_dcsync", "Has Repl-Changes-All rights on domain root", False),
        DiscoveryResult("GPO Management Team", "", "acl_gpo_write", "Can edit GPO 'DC Security Policy' linked to DC OU", False),
        DiscoveryResult("AD Delegation Group", "", "acl_group_write", "Has GenericWrite on Domain Admins", False),
    ]


def generate_demo_data():
    def mu(name, sam, enabled=True, ll_days=5, pw_days=30,
           pw_never_expires=False, admin_count=1, desc=""):
        now = datetime.now(timezone.utc)
        return ADObject(
            name=name, sam_account_name=sam,
            distinguished_name=f"CN={name},OU=Users,DC=example,DC=local",
            object_class="user", enabled=enabled,
            last_logon=(now - timedelta(days=ll_days)).isoformat() if ll_days else None,
            password_last_set=(now - timedelta(days=pw_days)).isoformat(),
            password_never_expires=pw_never_expires, admin_count=admin_count,
            description=desc, when_created=(now - timedelta(days=800)).isoformat(),
        )

    # Shared nested group — appears under both DA and Administrators
    infra_ops = GroupNode("Infrastructure Ops", "CN=Infrastructure Ops,OU=Groups,DC=example,DC=local", 1, [])
    infra_ops.direct_members = [
        mu("Karl InfraOps", "k.infraops", desc="Infrastructure team"),
        mu("Svc Patching", "svc.patching", pw_never_expires=True, pw_days=500, desc="Patching service acct"),
    ]
    # Sub-group under infra_ops for deep nesting demo
    net_team = GroupNode("Network Team", "CN=Network Team,OU=Groups,DC=example,DC=local", 2, [])
    net_team.direct_members = [
        mu("Larry NetEng", "l.neteng", desc="Network engineer"),
    ]
    firewall_ops = GroupNode("Firewall Operators", "CN=Firewall Operators,OU=Groups,DC=example,DC=local", 3, [])
    firewall_ops.direct_members = [
        mu("Mike FWAdmin", "m.fwadmin", desc="Firewall admin"),
        mu("Nancy NOC", "n.noc", desc="NOC analyst"),
    ]
    net_team.child_groups.append(firewall_ops)
    infra_ops.child_groups.append(net_team)

    # Domain Admins
    da = GroupNode("Domain Admins", "CN=Domain Admins,CN=Users,DC=example,DC=local", 0, [])
    da.direct_members = [
        mu("Admin Primary", "admin.primary", desc="Primary DA - IT Lead"),
        mu("Svc Migration 2019", "svc.migration", ll_days=780, pw_days=780,
           pw_never_expires=True, desc="Server migration project 2019"),
        mu("Jane Former-Admin", "j.formeradmin", enabled=False, ll_days=400),
    ]
    server_admins = GroupNode("Server Admins", "CN=Server Admins,OU=Groups,DC=example,DC=local", 1, ["Domain Admins"])
    server_admins.direct_members = [
        mu("Bob ServerGuy", "b.serverguy", desc="Server team lead"),
        mu("Carol Ops", "c.ops", desc="Operations"),
    ]
    helpdesk_t2 = GroupNode("Helpdesk Tier2", "CN=Helpdesk Tier2,OU=Groups,DC=example,DC=local", 2, [])
    helpdesk_t2.direct_members = [
        mu("Dave Helpdesk", "d.helpdesk", desc="Helpdesk tier 2"),
        mu("Eve Support", "e.support", desc="Helpdesk tier 2"),
    ]
    server_admins.child_groups.append(helpdesk_t2)
    da.child_groups.append(server_admins)

    # Clone infra_ops for DA tree (simulates shared group)
    import copy
    infra_da = copy.deepcopy(infra_ops)
    infra_da.parent_path = ["Domain Admins"]
    da.child_groups.append(infra_da)

    # Administrators (also contains Infrastructure Ops)
    admins = GroupNode("Administrators", "CN=Administrators,CN=Builtin,DC=example,DC=local", 0, [])
    admins.direct_members = [
        mu("Admin Primary", "admin.primary", desc="Primary DA - IT Lead"),
    ]
    infra_admins = copy.deepcopy(infra_ops)
    infra_admins.parent_path = ["Administrators"]
    admins.child_groups.append(infra_admins)

    # Enterprise Admins
    ea = GroupNode("Enterprise Admins", "CN=Enterprise Admins,CN=Users,DC=example,DC=local", 0, [])
    ea.direct_members = [
        mu("Admin Primary", "admin.primary", desc="Primary DA - IT Lead"),
        mu("Frank Enterprise", "f.enterprise", pw_days=400, desc="Enterprise admin"),
    ]

    bo = GroupNode("Backup Operators", "CN=Backup Operators,CN=Builtin,DC=example,DC=local", 0, [])
    bo.direct_members = [
        mu("Svc Backup Agent", "svc.backup", pw_never_expires=True, desc="Backup service account"),
        mu("Greg Backups", "g.backups", ll_days=200, desc="Former backup admin"),
    ]

    sql_admins = GroupNode("SQL Server Admins", "CN=SQL Server Admins,OU=Groups,DC=example,DC=local", 0, [])
    sql_admins.direct_members = [
        mu("Henry DBA", "h.dba", desc="Senior DBA"),
        mu("Svc SQL Agent", "svc.sql", pw_never_expires=True, pw_days=600, desc="SQL maintenance agent"),
    ]

    it_auto = GroupNode("IT Automation Svc", "CN=IT Automation Svc,OU=ServiceGroups,DC=example,DC=local", 0, [])
    it_auto.direct_members = [
        mu("Svc Ansible Tower", "svc.ansible", pw_never_expires=True, desc="Ansible automation"),
        mu("Svc SCCM", "svc.sccm", pw_never_expires=True, pw_days=900, desc="SCCM deployment"),
    ]

    ad_deleg = GroupNode("AD Delegation Group", "CN=AD Delegation Group,OU=Groups,DC=example,DC=local", 0, [])
    ad_deleg.direct_members = [
        mu("Admin Primary", "admin.primary", desc="Primary DA - IT Lead"),
        mu("Ivan IAM", "i.iam", desc="IAM team lead"),
    ]

    return {
        "Domain Admins": da, "Administrators": admins,
        "Enterprise Admins": ea, "Backup Operators": bo,
        "SQL Server Admins": sql_admins, "IT Automation Svc": it_auto,
        "AD Delegation Group": ad_deleg,
    }


# ============================================================================
# AD Enumeration
# ============================================================================

def build_group_tree(group_name: str, depth: int = 0, parent_path: list = None,
                     visited: set = None) -> Optional[GroupNode]:
    if parent_path is None:
        parent_path = []
    if visited is None:
        visited = set()

    if group_name.lower() in visited:
        print(f"  [!] Circular nesting detected: {group_name} (skipping)", file=sys.stderr)
        return None
    visited.add(group_name.lower())

    cached = group_name.lower() in _member_cache
    tag = "(cached)" if cached else ""
    print(f"  {'  ' * depth}Enumerating: {group_name} {tag}")

    members = get_group_direct_members(group_name)
    node = GroupNode(name=group_name, distinguished_name="", depth=depth, parent_path=list(parent_path))

    if not members:
        return node

    current_path = parent_path + [group_name]
    for m in members:
        if m.get("objectClass") == "group":
            child = build_group_tree(m["Name"], depth + 1, current_path, visited.copy())
            if child:
                child.distinguished_name = m.get("distinguishedName", "")
                node.child_groups.append(child)
        else:
            obj = ADObject(
                name=m.get("Name", ""), sam_account_name=m.get("SamAccountName", ""),
                distinguished_name=m.get("distinguishedName", ""),
                object_class=m.get("objectClass", "user"), enabled=m.get("Enabled"),
                last_logon=m.get("LastLogonDate"), password_last_set=m.get("PasswordLastSet"),
                password_never_expires=m.get("PasswordNeverExpires", False),
                admin_count=m.get("AdminCount"), description=m.get("Description", ""),
                when_created=m.get("whenCreated"), member_of_direct=m.get("MemberOf", [])
            )
            node.direct_members.append(obj)
    return node


# ============================================================================
# Analysis Engine
# ============================================================================

def collect_all_accounts(tree: GroupNode, path: list = None) -> list[tuple]:
    if path is None:
        path = [tree.name]
    results = []
    for member in tree.direct_members:
        results.append((member, " \u2192 ".join(path)))
    for child in tree.child_groups:
        results.extend(collect_all_accounts(child, path + [child.name]))
    return results


def collect_group_appearances(trees: dict) -> dict[str, list[str]]:
    """Map group names to the root trees they appear in."""
    appearances = defaultdict(set)

    def _walk(node, root_name):
        appearances[node.name.lower()].add(root_name)
        for child in node.child_groups:
            _walk(child, root_name)

    for root_name, tree in trees.items():
        _walk(tree, root_name)

    return {k: sorted(v) for k, v in appearances.items() if len(v) > 1}


def analyze(trees: dict[str, GroupNode]) -> list[Finding]:
    findings = []
    now = datetime.now(timezone.utc)
    account_groups = defaultdict(list)
    all_entries = []

    for root_name, tree in trees.items():
        entries = collect_all_accounts(tree)
        all_entries.extend(entries)
        for acct, path in entries:
            account_groups[acct.sam_account_name].append((root_name, path, acct))

    # --- Privilege creep ---
    for sam, memberships in account_groups.items():
        unique_roots = set(r for r, _, _ in memberships)
        if len(unique_roots) >= MULTI_GROUP_CREEP_THRESHOLD:
            acct = memberships[0][2]
            groups_list = ", ".join(sorted(unique_roots))
            findings.append(Finding(
                severity="HIGH", category="Privilege Creep",
                account=acct.display_label, sam=sam,
                detail=f"Member of {len(unique_roots)} privileged groups: {groups_list}",
                inheritance_path=memberships[0][1]
            ))

    # --- Disabled accounts ---
    for acct, path in all_entries:
        if acct.enabled is False:
            findings.append(Finding(
                severity="CRITICAL", category="Disabled Account",
                account=acct.display_label, sam=acct.sam_account_name,
                detail="Disabled account still in privileged group", inheritance_path=path
            ))

    # --- Stale logon ---
    for acct, path in all_entries:
        if acct.last_logon:
            try:
                last = datetime.fromisoformat(acct.last_logon.replace('Z', '+00:00'))
                days = (now - last).days
                if days > STALE_LOGON_DAYS:
                    findings.append(Finding(
                        severity="CRITICAL" if days > 365 else "HIGH",
                        category="Stale Logon", account=acct.display_label,
                        sam=acct.sam_account_name,
                        detail=f"Last logon {days} days ago ({acct.last_logon[:10]})",
                        inheritance_path=path
                    ))
            except (ValueError, TypeError):
                pass
        elif acct.object_class == "user":
            findings.append(Finding(
                severity="HIGH", category="No Logon Recorded",
                account=acct.display_label, sam=acct.sam_account_name,
                detail="No LastLogonDate - may never have logged in or data not replicated",
                inheritance_path=path
            ))

    # --- Password never expires ---
    for acct, path in all_entries:
        if acct.password_never_expires and acct.object_class == "user":
            findings.append(Finding(
                severity="MEDIUM", category="Password Never Expires",
                account=acct.display_label, sam=acct.sam_account_name,
                detail="PasswordNeverExpires set on privileged account", inheritance_path=path
            ))

    # --- Stale password ---
    for acct, path in all_entries:
        if acct.password_last_set:
            try:
                pw_set = datetime.fromisoformat(acct.password_last_set.replace('Z', '+00:00'))
                days = (now - pw_set).days
                if days > STALE_PASSWORD_DAYS:
                    findings.append(Finding(
                        severity="MEDIUM", category="Stale Password",
                        account=acct.display_label, sam=acct.sam_account_name,
                        detail=f"Password last set {days} days ago ({acct.password_last_set[:10]})",
                        inheritance_path=path
                    ))
            except (ValueError, TypeError):
                pass

    # --- Orphaned AdminCount ---
    seen_in_privileged = set(sam for sam in account_groups)
    for acct, path in all_entries:
        if acct.admin_count == 1 and acct.sam_account_name not in seen_in_privileged:
            findings.append(Finding(
                severity="MEDIUM", category="Orphaned AdminCount",
                account=acct.display_label, sam=acct.sam_account_name,
                detail="AdminCount=1 but no longer in any enumerated privileged group",
                inheritance_path=path
            ))

    # --- Tiered nesting analysis ---
    for root_name, tree in trees.items():
        _flag_nesting(tree, [], findings, root_name)

    # Deduplicate by (sam, category)
    seen = set()
    deduped = []
    for f in findings:
        key = (f.sam, f.category)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    deduped.sort(key=lambda f: sev_order.get(f.severity, 5))
    return deduped


def _flag_nesting(node, path, findings, root_name):
    """Flag ALL inherited access with severity tiered by depth."""
    current_path = path + [node.name]
    nesting_depth = len(current_path) - 1  # 0 = direct member of root

    if nesting_depth >= 1:
        for member in node.direct_members:
            chain = " \u2192 ".join(current_path)
            if nesting_depth == 1:
                sev, cat = "LOW", "Inherited Access"
            elif nesting_depth == 2:
                sev, cat = "MEDIUM", "Deep Nesting"
            else:
                sev, cat = "HIGH", "Deeply Nested"
            findings.append(Finding(
                severity=sev, category=cat,
                account=member.display_label, sam=member.sam_account_name,
                detail=f"Gains {root_name} membership through {nesting_depth}-level nesting",
                inheritance_path=chain
            ))
    for child in node.child_groups:
        _flag_nesting(child, current_path, findings, root_name)


# ============================================================================
# Search
# ============================================================================

def search_user(trees, query):
    q = query.lower()
    results = []
    for root_name, tree in trees.items():
        for acct, path in collect_all_accounts(tree):
            if q in acct.sam_account_name.lower() or q in acct.name.lower() or q in acct.distinguished_name.lower():
                results.append((root_name, acct, path))
    return results

def search_group(trees, query):
    q = query.lower()
    results = []
    def _walk(node, root_name, path):
        cp = path + [node.name]
        if q in node.name.lower():
            results.append((root_name, node, " \u2192 ".join(cp)))
        for child in node.child_groups:
            _walk(child, root_name, cp)
    for root_name, tree in trees.items():
        _walk(tree, root_name, [])
    return results

def print_user_search(trees, query):
    results = search_user(trees, query)
    if not results:
        print(f"\n  No results for user '{query}'")
        return
    print(f"\n  Found {len(results)} membership(s) for '{query}':\n")
    for root, acct, path in results:
        print(f"  Privileged Group : {root}")
        print(f"  Account          : {acct.display_label}")
        print(f"  Enabled          : {acct.enabled}")
        print(f"  Last Logon       : {acct.last_logon or 'N/A'}")
        print(f"  PW Last Set      : {acct.password_last_set or 'N/A'}")
        print(f"  PW Never Expires : {acct.password_never_expires}")
        print(f"  AdminCount       : {acct.admin_count}")
        print(f"  Inheritance Path : {path}")
        print(f"  Description      : {acct.description or '(none)'}")
        print()

def print_group_search(trees, query):
    results = search_group(trees, query)
    if not results:
        print(f"\n  No results for group '{query}'")
        return
    print(f"\n  Found {len(results)} match(es) for group '{query}':\n")
    for root, node, path in results:
        print(f"  Root Group     : {root}")
        print(f"  Group          : {node.name}")
        print(f"  Nesting Path   : {path}")
        print(f"  Direct Members : {len(node.direct_members)} accounts, {len(node.child_groups)} nested groups")
        for m in node.direct_members:
            status = "ENABLED" if m.enabled else "DISABLED" if m.enabled is False else "?"
            print(f"    - {m.display_label} ({m.object_class}) [{status}]")
        for g in node.child_groups:
            print(f"    - [GROUP] {g.name}")
        print()


# ============================================================================
# HTML Report
# ============================================================================

def tree_to_d3(node, multi_groups):
    """Convert tree to D3 JSON with multi-appearance and depth metadata."""
    children = []
    for cg in node.child_groups:
        children.append(tree_to_d3(cg, multi_groups))
    for m in node.direct_members:
        status = "enabled" if m.enabled else "disabled" if m.enabled is False else "unknown"
        children.append({
            "name": m.sam_account_name, "display_name": m.name,
            "type": m.object_class, "status": status,
            "last_logon": m.last_logon or "N/A",
            "pw_never_expires": m.password_never_expires,
            "admin_count": m.admin_count, "description": m.description or ""
        })
    multi = multi_groups.get(node.name.lower())
    return {
        "name": node.name, "type": "group", "depth": node.depth,
        "children": children,
        "multi_appearance": multi if multi else None,
        "appearance_count": len(multi) if multi else 1,
    }


def generate_html_report(trees, findings, discovery_results, output_path):
    multi_groups = collect_group_appearances(trees)
    d3_roots = [tree_to_d3(tree, multi_groups) for tree in trees.values()]
    d3_data = {"name": "Privileged Groups", "type": "root", "children": d3_roots}

    all_accounts = []
    for root_name, tree in trees.items():
        for acct, path in collect_all_accounts(tree):
            all_accounts.append({
                "sam": acct.sam_account_name, "name": acct.name, "root_group": root_name,
                "path": path, "enabled": acct.enabled, "last_logon": acct.last_logon or "",
                "pw_last_set": acct.password_last_set or "",
                "pw_never_expires": acct.password_never_expires,
                "admin_count": acct.admin_count, "description": acct.description or "",
                "object_class": acct.object_class,
            })

    unique_accounts = set(a["sam"] for a in all_accounts)
    direct_count = sum(1 for a in all_accounts if a["path"].count("\u2192") == 0)
    inherited_count = len(all_accounts) - direct_count
    sev_counts = defaultdict(int)
    for f in findings:
        sev_counts[f.severity] += 1

    disc_new = [d for d in discovery_results if not d.already_known]
    disc_acl_new = [d for d in discovery_results if d.discovery_method.startswith("acl_") and not d.already_known]

    # Build nesting chain data for the Nesting tab
    nesting_chains = []  # All inherited membership paths
    nesting_groups = []  # All nested group-to-group relationships

    def _collect_nesting(node, root_name, path):
        current_path = path + [node.name]
        depth = len(current_path) - 1  # 0 = root group itself
        if depth >= 1:
            # Record group nesting
            is_multi = node.name.lower() in multi_groups
            nesting_groups.append({
                "group": node.name, "root": root_name, "depth": depth,
                "chain": " \u2192 ".join(current_path),
                "member_count": len(node.direct_members),
                "child_count": len(node.child_groups),
                "multi": is_multi,
                "trees": multi_groups.get(node.name.lower(), [root_name]),
            })
            # Record each member's inherited path
            for m in node.direct_members:
                status = "enabled" if m.enabled else "disabled" if m.enabled is False else "unknown"
                nesting_chains.append({
                    "account": m.display_label, "sam": m.sam_account_name,
                    "root": root_name, "depth": depth,
                    "chain": " \u2192 ".join(current_path),
                    "via_group": node.name,  # The immediate group granting access
                    "status": status,
                    "multi_group": node.name.lower() in multi_groups,
                })
        for child in node.child_groups:
            _collect_nesting(child, root_name, current_path)

    for root_name, tree in trees.items():
        _collect_nesting(tree, root_name, [])

    # Depth distribution for summary
    depth_dist = defaultdict(int)
    for c in nesting_chains:
        depth_dist[c["depth"]] += 1
    max_depth = max(depth_dist.keys()) if depth_dist else 0

    findings_json = json.dumps([{"severity": f.severity, "category": f.category,
                                  "account": f.account, "detail": f.detail, "path": f.inheritance_path} for f in findings])
    discovery_json = json.dumps([{"group": d.group_name, "method": d.discovery_method,
                                   "detail": d.detail, "new": not d.already_known} for d in discovery_results])
    multi_groups_json = json.dumps({k: v for k, v in multi_groups.items()})
    nesting_chains_json = json.dumps(nesting_chains)
    nesting_groups_json = json.dumps(nesting_groups)

    method_labels = {"builtin": "Built-in", "admincount": "AdminCount", "name_pattern": "Name Pattern",
                     "acl_dcsync": "DCSync Rights", "acl_group_write": "Group Write ACL",
                     "acl_gpo_write": "GPO Write ACL", "acl_domain_write": "Domain Root ACL"}

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    hits, misses = get_cache_stats()

    html_parts = []
    html_parts.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AD Privileged Group Audit - {timestamp}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=DM+Sans:wght@400;500;600;700&display=swap');
  :root {{
    --bg-primary:#0b0e14;--bg-secondary:#111821;--bg-tertiary:#1a2332;--bg-card:#151d2b;
    --border:#1e2d3d;--border-hover:#2a4a6b;--text-primary:#c5cdd8;--text-secondary:#6b7d8f;
    --text-bright:#e8edf2;--accent:#3d8ef0;--critical:#e05252;--critical-bg:rgba(224,82,82,.1);
    --high:#e0883c;--high-bg:rgba(224,136,60,.1);--medium:#d4c04e;--medium-bg:rgba(212,192,78,.1);
    --low:#4ea8d4;--low-bg:rgba(78,168,212,.1);--info:#6b7d8f;--node-group:#3d8ef0;
    --node-user:#4eca7a;--node-disabled:#e05252;--node-computer:#a87ae0;
    --node-multi:#e866e8;--new-badge:#4eca7a;--new-badge-bg:rgba(78,202,122,.12);
    --acl-badge:#e0883c;--acl-badge-bg:rgba(224,136,60,.12);
    --font-body:'DM Sans',-apple-system,sans-serif;--font-mono:'JetBrains Mono','Consolas',monospace;
  }}
  *{{margin:0;padding:0;box-sizing:border-box}}
  body{{background:var(--bg-primary);color:var(--text-primary);font-family:var(--font-body);font-size:14px;line-height:1.6;min-height:100vh}}
  .report-header{{background:var(--bg-secondary);border-bottom:1px solid var(--border);padding:28px 40px;display:flex;justify-content:space-between;align-items:center}}
  .report-header h1{{font-size:20px;font-weight:700;color:var(--text-bright);letter-spacing:-.3px}}
  .report-header .meta{{font-family:var(--font-mono);font-size:12px;color:var(--text-secondary)}}
  .container{{max-width:1400px;margin:0 auto;padding:24px 40px}}
  .dashboard{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:28px}}
  .stat-card{{background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:18px 20px;transition:border-color .2s}}
  .stat-card:hover{{border-color:var(--border-hover)}}
  .stat-card .label{{font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:var(--text-secondary);margin-bottom:6px}}
  .stat-card .value{{font-family:var(--font-mono);font-size:28px;font-weight:600;color:var(--text-bright)}}
  .stat-card .value.critical{{color:var(--critical)}}.stat-card .value.high{{color:var(--high)}}
  .stat-card .value.medium{{color:var(--medium)}}.stat-card .value.accent{{color:var(--accent)}}
  .stat-card .value.new-grp{{color:var(--new-badge)}}.stat-card .value.multi{{color:var(--node-multi)}}
  .tabs{{display:flex;gap:0;border-bottom:1px solid var(--border);margin-bottom:20px}}
  .tab{{padding:10px 24px;font-size:13px;font-weight:600;color:var(--text-secondary);cursor:pointer;border-bottom:2px solid transparent;transition:all .2s;user-select:none}}
  .tab:hover{{color:var(--text-primary)}}.tab.active{{color:var(--accent);border-bottom-color:var(--accent)}}
  .tab-content{{display:none}}.tab-content.active{{display:block}}
  .search-bar{{display:flex;gap:10px;margin-bottom:20px;flex-wrap:wrap}}
  .search-bar input{{flex:1;min-width:200px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:4px;padding:10px 16px;color:var(--text-bright);font-family:var(--font-mono);font-size:13px;outline:none;transition:border-color .2s}}
  .search-bar input:focus{{border-color:var(--accent)}}.search-bar input::placeholder{{color:var(--text-secondary)}}
  .search-bar select{{background:var(--bg-tertiary);border:1px solid var(--border);border-radius:4px;padding:10px 16px;color:var(--text-primary);font-size:13px;cursor:pointer;outline:none}}
  table{{width:100%;border-collapse:collapse;font-size:13px}}
  thead th{{text-align:left;padding:10px 14px;font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:var(--text-secondary);border-bottom:1px solid var(--border);background:var(--bg-secondary);position:sticky;top:0;z-index:1}}
  tbody td{{padding:10px 14px;border-bottom:1px solid var(--border);font-family:var(--font-mono);font-size:12px;vertical-align:top}}
  tbody tr:hover{{background:var(--bg-tertiary)}}
  .sev-badge{{display:inline-block;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px}}
  .sev-CRITICAL{{background:var(--critical-bg);color:var(--critical)}}.sev-HIGH{{background:var(--high-bg);color:var(--high)}}
  .sev-MEDIUM{{background:var(--medium-bg);color:var(--medium)}}.sev-LOW{{background:var(--low-bg);color:var(--low)}}
  .sev-INFO{{background:rgba(107,125,143,.15);color:var(--info)}}
  .method-badge{{display:inline-block;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:600;letter-spacing:.3px}}
  .method-builtin{{background:rgba(107,125,143,.15);color:var(--info)}}
  .method-admincount{{background:var(--medium-bg);color:var(--medium)}}
  .method-name_pattern{{background:var(--low-bg);color:var(--low)}}
  .method-acl{{background:var(--acl-badge-bg);color:var(--acl-badge)}}
  .new-tag{{display:inline-block;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:700;text-transform:uppercase;background:var(--new-badge-bg);color:var(--new-badge);margin-left:6px}}
  .multi-tag{{display:inline-block;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:700;text-transform:uppercase;background:rgba(232,102,232,.12);color:var(--node-multi);margin-left:6px}}
  .depth-badge{{display:inline-block;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:600;font-family:var(--font-mono)}}
  .depth-1{{background:var(--low-bg);color:var(--low)}}.depth-2{{background:var(--medium-bg);color:var(--medium)}}
  .depth-3{{background:var(--high-bg);color:var(--high)}}.depth-deep{{background:var(--critical-bg);color:var(--critical)}}
  .status-enabled{{color:var(--node-user)}}.status-disabled{{color:var(--critical)}}
  .path-text{{color:var(--text-secondary);font-size:11px;word-break:break-all}}
  #tree-container{{background:var(--bg-secondary);border:1px solid var(--border);border-radius:6px;overflow:auto;min-height:500px}}
  .node circle{{stroke-width:2px;cursor:pointer;transition:r .2s}}.node circle:hover{{r:7}}
  .node text{{font-family:var(--font-mono);font-size:11px;fill:var(--text-primary)}}
  .link{{fill:none;stroke:var(--border);stroke-width:1.2px}}
  .link-deep{{stroke:var(--high);stroke-dasharray:4,3;stroke-width:1.5px}}
  .multi-ring{{fill:none;stroke:var(--node-multi);stroke-width:2px;stroke-dasharray:3,2}}
  .tooltip{{position:absolute;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:4px;padding:8px 12px;font-family:var(--font-mono);font-size:11px;color:var(--text-primary);pointer-events:none;z-index:10;max-width:350px;line-height:1.5}}
  .tree-legend{{display:flex;gap:20px;padding:12px 20px;border-bottom:1px solid var(--border);font-size:12px;flex-wrap:wrap}}
  .tree-legend span{{display:flex;align-items:center;gap:6px}}
  .tree-legend .dot{{width:10px;height:10px;border-radius:50%;display:inline-block}}
  .tree-legend .dot-ring{{width:10px;height:10px;border-radius:50%;display:inline-block;border:2px dashed var(--node-multi);background:transparent}}
  .no-results{{text-align:center;padding:40px;color:var(--text-secondary);font-style:italic}}
  .export-btn{{background:var(--bg-tertiary);border:1px solid var(--border);border-radius:4px;padding:8px 16px;color:var(--text-primary);font-size:12px;cursor:pointer;font-family:var(--font-body);transition:border-color .2s}}
  .export-btn:hover{{border-color:var(--accent);color:var(--accent)}}
  .disc-summary,.nesting-summary{{background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:20px 24px;margin-bottom:20px;font-size:13px;line-height:1.8}}
  .disc-summary strong,.nesting-summary strong{{color:var(--text-bright)}}
</style>
</head>
<body>
<div class="report-header">
  <h1>AD Privileged Group Audit</h1>
  <div class="meta">Generated {timestamp} | CND Internal Use{' | Cache: ' + str(hits) + ' hits / ' + str(misses) + ' queries' if misses > 0 else ''}</div>
</div>
<div class="container">
  <div class="dashboard">
    <div class="stat-card"><div class="label">Unique Priv Accounts</div><div class="value">{len(unique_accounts)}</div></div>
    <div class="stat-card"><div class="label">Total Memberships</div><div class="value">{len(all_accounts)}</div></div>
    <div class="stat-card"><div class="label">Direct / Inherited</div><div class="value" style="font-size:20px">{direct_count} / {inherited_count}</div></div>
    <div class="stat-card"><div class="label">Groups Enumerated</div><div class="value accent">{len(trees)}</div></div>
    <div class="stat-card"><div class="label">Multi-Appear Groups</div><div class="value multi">{len(multi_groups)}</div></div>
    <div class="stat-card"><div class="label">Max Nesting Depth</div><div class="value high">{max_depth}</div></div>
    <div class="stat-card"><div class="label">Critical Findings</div><div class="value critical">{sev_counts.get('CRITICAL', 0)}</div></div>
    <div class="stat-card"><div class="label">High Findings</div><div class="value high">{sev_counts.get('HIGH', 0)}</div></div>
    <div class="stat-card"><div class="label">Total Findings</div><div class="value">{len(findings)}</div></div>
  </div>
  <div class="tabs">
    <div class="tab active" data-tab="findings">Findings</div>
    <div class="tab" data-tab="accounts">All Accounts</div>
    <div class="tab" data-tab="nesting">Nesting</div>
    <div class="tab" data-tab="discovery">Discovery</div>
    <div class="tab" data-tab="tree">Hierarchy</div>
  </div>
  <div id="tab-findings" class="tab-content active">
    <div class="search-bar">
      <input type="text" id="findings-search" placeholder="Filter findings..." oninput="filterFindings()">
      <select id="findings-sev" onchange="filterFindings()">
        <option value="">All Severities</option><option value="CRITICAL">Critical</option>
        <option value="HIGH">High</option><option value="MEDIUM">Medium</option><option value="LOW">Low</option>
      </select>
      <select id="findings-cat" onchange="filterFindings()">
        <option value="">All Categories</option>
      </select>
      <button class="export-btn" onclick="exportCSV('findings')">Export CSV</button>
    </div>
    <table id="findings-table"><thead><tr><th>Severity</th><th>Category</th><th>Account</th><th>Detail</th><th>Inheritance Path</th></tr></thead><tbody></tbody></table>
  </div>
  <div id="tab-accounts" class="tab-content">
    <div class="search-bar">
      <input type="text" id="accounts-search" placeholder="Search by name, SAM, or group..." oninput="filterAccounts()">
      <select id="accounts-status" onchange="filterAccounts()">
        <option value="">All Statuses</option><option value="enabled">Enabled</option><option value="disabled">Disabled</option>
      </select>
      <button class="export-btn" onclick="exportCSV('accounts')">Export CSV</button>
    </div>
    <table id="accounts-table"><thead><tr><th>SAM Account</th><th>Name</th><th>Status</th><th>Priv Group</th><th>Last Logon</th><th>PW Expires</th><th>Path</th></tr></thead><tbody></tbody></table>
  </div>
  <div id="tab-nesting" class="tab-content">
    <div class="disc-summary">
      <strong>Nesting Analysis:</strong>
      <strong>{inherited_count}</strong> inherited membership(s) across <strong>{len(nesting_groups)}</strong> nested group relationship(s).
      Max nesting depth: <strong>{max_depth}</strong> level(s).
      {f'<strong>{len(multi_groups)}</strong> group(s) appear under multiple privileged roots — their members accumulate privileges from each.' if multi_groups else ''}
      {'Depth distribution: ' + ', '.join(f'L{d}={c}' for d, c in sorted(depth_dist.items())) + '.' if depth_dist else ''}
    </div>
    <h3 style="color:var(--text-bright);margin-bottom:12px;font-size:14px">Nested Groups</h3>
    <div class="search-bar">
      <input type="text" id="ngrp-search" placeholder="Filter groups..." oninput="filterNestGroups()">
      <select id="ngrp-multi" onchange="filterNestGroups()">
        <option value="">All Groups</option><option value="multi">Multi-Appearance Only</option>
      </select>
      <select id="ngrp-depth" onchange="filterNestGroups()">
        <option value="">All Depths</option>
        {' '.join(f'<option value="{d}">Depth {d}</option>' for d in sorted(depth_dist.keys()))}
      </select>
      <button class="export-btn" onclick="exportCSV('nest_groups')">Export CSV</button>
    </div>
    <table id="ngrp-table"><thead><tr><th>Group</th><th>Depth</th><th>Root</th><th>Members</th><th>Sub-Groups</th><th>Inheritance Chain</th></tr></thead><tbody></tbody></table>
    <h3 style="color:var(--text-bright);margin:24px 0 12px;font-size:14px">Inherited Account Access</h3>
    <div class="search-bar">
      <input type="text" id="nchain-search" placeholder="Filter by account, group, or root..." oninput="filterNestChains()">
      <select id="nchain-depth" onchange="filterNestChains()">
        <option value="">All Depths</option>
        {' '.join(f'<option value="{d}">Depth {d}</option>' for d in sorted(depth_dist.keys()))}
      </select>
      <select id="nchain-status" onchange="filterNestChains()">
        <option value="">All Statuses</option><option value="enabled">Enabled</option><option value="disabled">Disabled</option>
      </select>
      <button class="export-btn" onclick="exportCSV('nest_chains')">Export CSV</button>
    </div>
    <table id="nchain-table"><thead><tr><th>Account</th><th>Status</th><th>Depth</th><th>Root Group</th><th>Via Group</th><th>Full Chain</th></tr></thead><tbody></tbody></table>
  </div>
  <div id="tab-discovery" class="tab-content">
    <div class="disc-summary">
      <strong>Discovery Overview:</strong> Scanned using AdminCount flags, naming patterns, and targeted ACL analysis.
      <strong>{len(disc_new)}</strong> new group(s) beyond {len(DEFAULT_TIER0_GROUPS)} built-in defaults.
      {"<strong>" + str(len(disc_acl_new)) + "</strong> discovered through dangerous ACL grants (implicit Tier 0)." if disc_acl_new else ""}
    </div>
    <div class="search-bar">
      <input type="text" id="disc-search" placeholder="Filter..." oninput="filterDiscovery()">
      <select id="disc-method" onchange="filterDiscovery()">
        <option value="">All Methods</option><option value="builtin">Built-in</option>
        <option value="admincount">AdminCount</option><option value="name_pattern">Name Pattern</option>
        <option value="acl">ACL (All)</option>
      </select>
      <select id="disc-new" onchange="filterDiscovery()">
        <option value="">All Groups</option><option value="new">New Only</option><option value="known">Known Only</option>
      </select>
      <button class="export-btn" onclick="exportCSV('discovery')">Export CSV</button>
    </div>
    <table id="disc-table"><thead><tr><th>Group</th><th>Method</th><th>Detail</th><th>Status</th></tr></thead><tbody></tbody></table>
  </div>
  <div id="tab-tree" class="tab-content">
    <div class="nesting-summary" id="nesting-summary"></div>
    <div class="tree-legend">
      <span><span class="dot" style="background:var(--node-group)"></span> Group</span>
      <span><span class="dot" style="background:var(--node-user)"></span> Enabled User</span>
      <span><span class="dot" style="background:var(--node-disabled)"></span> Disabled</span>
      <span><span class="dot" style="background:var(--node-computer)"></span> Computer</span>
      <span><span class="dot-ring"></span> Multi-Appearance</span>
      <span style="color:var(--high);font-size:11px">- - - Deep nesting</span>
      <span style="margin-left:auto;color:var(--text-secondary);font-size:11px">Click to expand/collapse. Hover for details.</span>
    </div>
    <div id="tree-container"></div>
  </div>
</div>
""")

    js_code = """
<script src="https://d3js.org/d3.v7.min.js"></script>
<script>
const treeData = TREE_DATA_PLACEHOLDER;
const findingsData = FINDINGS_DATA_PLACEHOLDER;
const accountsData = ACCOUNTS_DATA_PLACEHOLDER;
const discoveryData = DISCOVERY_DATA_PLACEHOLDER;
const multiGroups = MULTI_GROUPS_PLACEHOLDER;
const methodLabels = METHOD_LABELS_PLACEHOLDER;
const nestGroups = NESTING_GROUPS_PLACEHOLDER;
const nestChains = NESTING_CHAINS_PLACEHOLDER;

// Populate category filter
const cats = [...new Set(findingsData.map(f => f.category))].sort();
const catSel = document.getElementById('findings-cat');
cats.forEach(c => { const o = document.createElement('option'); o.value = c; o.textContent = c; catSel.appendChild(o); });

// Build nesting summary
const multiKeys = Object.keys(multiGroups);
if (multiKeys.length > 0) {
  const lines = multiKeys.map(k => {
    const trees = multiGroups[k];
    const name = k.charAt(0).toUpperCase() + k.slice(1);
    return `<strong>${name}</strong>: appears in ${trees.join(', ')}`;
  });
  document.getElementById('nesting-summary').innerHTML =
    '<strong>Multi-Appearance Groups:</strong> These groups are nested under multiple privileged root groups, meaning their members inherit privileges from each.<br>' + lines.join('<br>');
} else {
  document.getElementById('nesting-summary').style.display = 'none';
}

document.querySelectorAll('.tab').forEach(t => {
  t.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(x => x.classList.remove('active'));
    t.classList.add('active');
    document.getElementById('tab-' + t.dataset.tab).classList.add('active');
    if (t.dataset.tab === 'tree' && !window._treeRendered) renderTree();
  });
});

function renderFindings(data) {
  const tbody = document.querySelector('#findings-table tbody');
  if (!data.length) { tbody.innerHTML = '<tr><td colspan="5" class="no-results">No findings match</td></tr>'; return; }
  tbody.innerHTML = data.map(f => `<tr><td><span class="sev-badge sev-${f.severity}">${f.severity}</span></td><td>${f.category}</td><td>${f.account}</td><td>${f.detail}</td><td class="path-text">${f.path}</td></tr>`).join('');
}
function filterFindings() {
  const q = document.getElementById('findings-search').value.toLowerCase();
  const sev = document.getElementById('findings-sev').value;
  const cat = document.getElementById('findings-cat').value;
  renderFindings(findingsData.filter(f => {
    if (sev && f.severity !== sev) return false;
    if (cat && f.category !== cat) return false;
    if (q && !(f.account.toLowerCase().includes(q) || f.category.toLowerCase().includes(q) || f.detail.toLowerCase().includes(q))) return false;
    return true;
  }));
}
renderFindings(findingsData);

function renderAccounts(data) {
  const tbody = document.querySelector('#accounts-table tbody');
  if (!data.length) { tbody.innerHTML = '<tr><td colspan="7" class="no-results">No accounts match</td></tr>'; return; }
  tbody.innerHTML = data.map(a => {
    const sc = a.enabled === true ? 'status-enabled' : a.enabled === false ? 'status-disabled' : '';
    const st = a.enabled === true ? 'Enabled' : a.enabled === false ? 'Disabled' : '\u2014';
    const ll = a.last_logon ? a.last_logon.substring(0,10) : '\u2014';
    const pw = a.pw_never_expires ? '<span style="color:var(--medium)">Never</span>' : 'Yes';
    return `<tr><td>${a.sam}</td><td>${a.name}</td><td class="${sc}">${st}</td><td>${a.root_group}</td><td>${ll}</td><td>${pw}</td><td class="path-text">${a.path}</td></tr>`;
  }).join('');
}
function filterAccounts() {
  const q = document.getElementById('accounts-search').value.toLowerCase();
  const s = document.getElementById('accounts-status').value;
  renderAccounts(accountsData.filter(a => {
    if (s === 'enabled' && a.enabled !== true) return false;
    if (s === 'disabled' && a.enabled !== false) return false;
    if (q && !(a.sam.toLowerCase().includes(q) || a.name.toLowerCase().includes(q) || a.root_group.toLowerCase().includes(q) || a.path.toLowerCase().includes(q))) return false;
    return true;
  }));
}
renderAccounts(accountsData);

function depthBadge(d) {
  const cls = d >= 4 ? 'depth-deep' : 'depth-' + d;
  return `<span class="depth-badge ${cls}">L${d}</span>`;
}

function renderNestGroups(data) {
  const tbody = document.querySelector('#ngrp-table tbody');
  if (!data.length) { tbody.innerHTML = '<tr><td colspan="6" class="no-results">No nested groups match</td></tr>'; return; }
  tbody.innerHTML = data.map(g => {
    const multiTag = g.multi ? `<span class="multi-tag">multi: ${g.trees.join(', ')}</span>` : '';
    return `<tr><td>${g.group}${multiTag}</td><td>${depthBadge(g.depth)}</td><td>${g.root}</td><td>${g.member_count}</td><td>${g.child_count}</td><td class="path-text">${g.chain}</td></tr>`;
  }).join('');
}
function filterNestGroups() {
  const q = document.getElementById('ngrp-search').value.toLowerCase();
  const m = document.getElementById('ngrp-multi').value;
  const d = document.getElementById('ngrp-depth').value;
  renderNestGroups(nestGroups.filter(g => {
    if (m === 'multi' && !g.multi) return false;
    if (d && g.depth !== parseInt(d)) return false;
    if (q && !(g.group.toLowerCase().includes(q) || g.root.toLowerCase().includes(q) || g.chain.toLowerCase().includes(q))) return false;
    return true;
  }));
}
renderNestGroups(nestGroups);

function renderNestChains(data) {
  const tbody = document.querySelector('#nchain-table tbody');
  if (!data.length) { tbody.innerHTML = '<tr><td colspan="6" class="no-results">No inherited access paths match</td></tr>'; return; }
  tbody.innerHTML = data.map(c => {
    const sc = c.status === 'enabled' ? 'status-enabled' : c.status === 'disabled' ? 'status-disabled' : '';
    const st = c.status === 'enabled' ? 'Enabled' : c.status === 'disabled' ? 'Disabled' : '\u2014';
    const multiTag = c.multi_group ? '<span class="multi-tag">multi</span>' : '';
    return `<tr><td>${c.account}</td><td class="${sc}">${st}</td><td>${depthBadge(c.depth)}</td><td>${c.root}</td><td>${c.via_group}${multiTag}</td><td class="path-text">${c.chain}</td></tr>`;
  }).join('');
}
function filterNestChains() {
  const q = document.getElementById('nchain-search').value.toLowerCase();
  const d = document.getElementById('nchain-depth').value;
  const s = document.getElementById('nchain-status').value;
  renderNestChains(nestChains.filter(c => {
    if (d && c.depth !== parseInt(d)) return false;
    if (s && c.status !== s) return false;
    if (q && !(c.account.toLowerCase().includes(q) || c.via_group.toLowerCase().includes(q) || c.root.toLowerCase().includes(q) || c.chain.toLowerCase().includes(q))) return false;
    return true;
  }));
}
renderNestChains(nestChains);

function renderDiscovery(data) {
  const tbody = document.querySelector('#disc-table tbody');
  if (!data.length) { tbody.innerHTML = '<tr><td colspan="4" class="no-results">No results match</td></tr>'; return; }
  tbody.innerHTML = data.map(d => {
    const mClass = d.method.startsWith('acl') ? 'method-acl' : 'method-' + d.method;
    const mLabel = methodLabels[d.method] || d.method;
    const newTag = d.new ? '<span class="new-tag">new</span>' : '';
    return `<tr><td>${d.group}${newTag}</td><td><span class="method-badge ${mClass}">${mLabel}</span></td><td>${d.detail}</td><td>${d.new ? 'Discovered' : 'Known'}</td></tr>`;
  }).join('');
}
function filterDiscovery() {
  const q = document.getElementById('disc-search').value.toLowerCase();
  const m = document.getElementById('disc-method').value;
  const n = document.getElementById('disc-new').value;
  renderDiscovery(discoveryData.filter(d => {
    if (m === 'acl' && !d.method.startsWith('acl')) return false;
    if (m && m !== 'acl' && d.method !== m) return false;
    if (n === 'new' && !d.new) return false;
    if (n === 'known' && d.new) return false;
    if (q && !(d.group.toLowerCase().includes(q) || d.detail.toLowerCase().includes(q))) return false;
    return true;
  }));
}
renderDiscovery(discoveryData);

function renderTree() {
  window._treeRendered = true;
  const container = document.getElementById('tree-container');
  const width = container.clientWidth || 1200;
  const root = d3.hierarchy(treeData);
  root.x0 = 0; root.y0 = 0;
  function collapse(d) {
    if (d.children && d.depth > 0) { d._children = d.children; d._children.forEach(collapse); d.children = null; }
    else if (d.children) { d.children.forEach(collapse); }
  }
  root.children?.forEach(collapse);
  const margin = { top: 30, right: 260, bottom: 30, left: 80 };
  const nodeHeight = 28;
  const svg = d3.select('#tree-container').append('svg').attr('width', width).style('font-family', "'JetBrains Mono', monospace");
  const g = svg.append('g').attr('transform', `translate(${margin.left},${margin.top})`);
  const treemap = d3.tree().nodeSize([nodeHeight, 220]);

  // Tooltip
  const tip = d3.select('body').append('div').attr('class','tooltip').style('display','none');

  function nodeColor(d, fill) {
    const t = d.data.type;
    if (t === 'group' || t === 'root') {
      if (d.data.appearance_count > 1) return fill ? (d._children ? 'var(--node-multi)' : 'var(--bg-secondary)') : 'var(--node-multi)';
      return fill ? (d._children ? 'var(--node-group)' : 'var(--bg-secondary)') : 'var(--node-group)';
    }
    if (d.data.status === 'disabled') return 'var(--node-disabled)';
    if (t === 'computer') return 'var(--node-computer)';
    return 'var(--node-user)';
  }

  function update(source) {
    const treeLayout = treemap(root);
    const nodes = treeLayout.descendants();
    const links = treeLayout.links();
    let minX = Infinity, maxX = -Infinity;
    nodes.forEach(d => { if (d.x < minX) minX = d.x; if (d.x > maxX) maxX = d.x; });
    const height = maxX - minX + margin.top + margin.bottom + 40;
    svg.attr('height', height);
    g.attr('transform', `translate(${margin.left},${margin.top + Math.abs(minX) + 20})`);

    const node = g.selectAll('g.node').data(nodes, d => d.data.name + '-' + d.depth + '-' + (d.parent?.data?.name || ''));
    const nodeEnter = node.enter().append('g').attr('class', 'node')
      .attr('transform', `translate(${source.y0 || 0},${source.x0 || 0})`)
      .on('click', (event, d) => {
        if (d.children) { d._children = d.children; d.children = null; }
        else if (d._children) { d.children = d._children; d._children = null; }
        update(d);
      })
      .on('mouseover', (event, d) => {
        let html = '<strong>' + d.data.name + '</strong>';
        if (d.data.display_name) html += '<br>Display: ' + d.data.display_name;
        if (d.data.type === 'group') {
          const cc = (d.children || d._children || []).length;
          html += '<br>Members/subgroups: ' + cc;
          if (d.data.appearance_count > 1) html += '<br><span style="color:var(--node-multi)">Appears in ' + d.data.appearance_count + ' root groups</span>';
        } else {
          html += '<br>Status: ' + (d.data.status || '?');
          if (d.data.last_logon && d.data.last_logon !== 'N/A') html += '<br>Last logon: ' + d.data.last_logon.substring(0,10);
          if (d.data.pw_never_expires) html += '<br><span style="color:var(--medium)">PW Never Expires</span>';
          if (d.data.description) html += '<br>' + d.data.description;
        }
        html += '<br>Depth: ' + d.depth;
        tip.html(html).style('display','block')
          .style('left', (event.pageX + 15) + 'px').style('top', (event.pageY - 10) + 'px');
      })
      .on('mousemove', (event) => {
        tip.style('left', (event.pageX + 15) + 'px').style('top', (event.pageY - 10) + 'px');
      })
      .on('mouseout', () => tip.style('display','none'));

    nodeEnter.append('circle').attr('r', 5)
      .attr('fill', d => nodeColor(d, true))
      .attr('stroke', d => nodeColor(d, false));

    // Multi-appearance ring
    nodeEnter.filter(d => d.data.appearance_count > 1)
      .append('circle').attr('class','multi-ring').attr('r', 9);

    nodeEnter.append('text').attr('dy','0.35em')
      .attr('x', d => (d.children||d._children)?-12:12)
      .attr('text-anchor', d => (d.children||d._children)?'end':'start')
      .text(d => d.data.type === 'group' || d.data.type === 'root' ? d.data.name : (d.data.display_name ? d.data.display_name + ' (' + d.data.name + ')' : d.data.name));

    const nodeUpdate = nodeEnter.merge(node);
    nodeUpdate.transition().duration(300).attr('transform', d => `translate(${d.y},${d.x})`);
    nodeUpdate.select('circle:first-child')
      .attr('fill', d => nodeColor(d, true))
      .attr('stroke', d => nodeColor(d, false));
    node.exit().transition().duration(200).attr('transform', `translate(${source.y},${source.x})`).remove();

    const link = g.selectAll('path.link,path.link-deep').data(links, d => d.target.data.name + '-' + d.target.depth + '-' + (d.target.parent?.data?.name || ''));
    link.enter().insert('path','g')
      .attr('class', d => d.target.depth >= 3 ? 'link link-deep' : 'link')
      .attr('d', () => { const o={x:source.x0||0,y:source.y0||0}; return diagonal(o,o); })
      .merge(link).transition().duration(300)
      .attr('class', d => d.target.depth >= 3 ? 'link link-deep' : 'link')
      .attr('d', d => diagonal(d.source,d.target));
    link.exit().transition().duration(200).attr('d', () => { const o={x:source.x,y:source.y}; return diagonal(o,o); }).remove();
    nodes.forEach(d => { d.x0=d.x; d.y0=d.y; });
  }
  function diagonal(s,d) { return `M${s.y},${s.x} C${(s.y+d.y)/2},${s.x} ${(s.y+d.y)/2},${d.x} ${d.y},${d.x}`; }
  update(root);
}

function exportCSV(type) {
  let csv, filename;
  if (type === 'findings') {
    csv = 'Severity,Category,Account,Detail,Path\\n' + findingsData.map(f => `${f.severity},"${f.category}","${f.account.replace(/"/g,'""')}","${f.detail.replace(/"/g,'""')}","${f.path}"`).join('\\n');
    filename = 'ad_priv_findings.csv';
  } else if (type === 'accounts') {
    csv = 'SAM,Name,Status,PrivGroup,LastLogon,PwNeverExpires,Path\\n' + accountsData.map(a => `${a.sam},"${a.name}",${a.enabled},${a.root_group},${a.last_logon||''},${a.pw_never_expires},"${a.path}"`).join('\\n');
    filename = 'ad_priv_accounts.csv';
  } else if (type === 'nest_groups') {
    csv = 'Group,Depth,Root,Members,SubGroups,Chain,MultiAppearance\\n' + nestGroups.map(g => `"${g.group}",${g.depth},"${g.root}",${g.member_count},${g.child_count},"${g.chain}",${g.multi}`).join('\\n');
    filename = 'ad_priv_nested_groups.csv';
  } else if (type === 'nest_chains') {
    csv = 'Account,SAM,Status,Depth,Root,ViaGroup,Chain\\n' + nestChains.map(c => `"${c.account.replace(/"/g,'""')}","${c.sam}","${c.status}",${c.depth},"${c.root}","${c.via_group}","${c.chain}"`).join('\\n');
    filename = 'ad_priv_inherited_access.csv';
  } else {
    csv = 'Group,Method,Detail,Status\\n' + discoveryData.map(d => `"${d.group}","${d.method}","${d.detail.replace(/"/g,'""')}",${d.new?'New':'Known'}`).join('\\n');
    filename = 'ad_priv_discovery.csv';
  }
  const blob = new Blob([csv], {type:'text/csv'});
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = filename; a.click();
}
</script>
</body></html>
"""
    js_code = js_code.replace("TREE_DATA_PLACEHOLDER", json.dumps(d3_data))
    js_code = js_code.replace("FINDINGS_DATA_PLACEHOLDER", findings_json)
    js_code = js_code.replace("ACCOUNTS_DATA_PLACEHOLDER", json.dumps(all_accounts))
    js_code = js_code.replace("DISCOVERY_DATA_PLACEHOLDER", discovery_json)
    js_code = js_code.replace("MULTI_GROUPS_PLACEHOLDER", multi_groups_json)
    js_code = js_code.replace("METHOD_LABELS_PLACEHOLDER", json.dumps(method_labels))
    js_code = js_code.replace("NESTING_GROUPS_PLACEHOLDER", nesting_groups_json)
    js_code = js_code.replace("NESTING_CHAINS_PLACEHOLDER", nesting_chains_json)

    html_parts.append(js_code)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("".join(html_parts))
    print(f"\n[+] Report written to: {output_path}")


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="AD Privileged Group Discovery & Analysis Tool")
    parser.add_argument("--groups", nargs="+", default=DEFAULT_TIER0_GROUPS)
    parser.add_argument("--discover", action="store_true", help="Auto-discover privileged groups")
    parser.add_argument("--search-user", type=str)
    parser.add_argument("--search-group", type=str)
    parser.add_argument("--output", type=str, default="ad_priv_audit_report.html")
    parser.add_argument("--demo", action="store_true", help="Generate report with mock data")
    args = parser.parse_args()

    print("=" * 60)
    print("  AD Privileged Group Discovery & Analysis Tool v2")
    print("=" * 60)

    discovery_results = []

    if args.demo:
        print("\n[*] Running in DEMO mode with mock data...\n")
        trees = generate_demo_data()
        discovery_results = generate_demo_discovery()
    else:
        check = run_ps("Get-Module -ListAvailable ActiveDirectory | Select Name | ConvertTo-Json")
        if not check:
            print("[!] ActiveDirectory PowerShell module not found.")
            print("    Install with: Install-WindowsFeature RSAT-AD-PowerShell")
            print("    Or run with --demo to test the report format.")
            sys.exit(1)

        groups_to_enumerate = list(args.groups)
        if args.discover:
            groups_to_enumerate, discovery_results = run_full_discovery()
        else:
            for g in args.groups:
                discovery_results.append(DiscoveryResult(
                    group_name=g, distinguished_name="", discovery_method="builtin",
                    detail="Built-in privileged group", already_known=True
                ))

        trees = {}
        for group_name in groups_to_enumerate:
            print(f"\n[*] Enumerating: {group_name}")
            tree = build_group_tree(group_name)
            if tree:
                trees[group_name] = tree
            else:
                print(f"  [!] Could not enumerate {group_name}")

        if not trees:
            print("\n[!] No groups could be enumerated. Exiting.")
            sys.exit(1)

        hits, misses = get_cache_stats()
        print(f"\n  [Cache] {hits} cache hits, {misses} PS queries (saved {hits} redundant calls)")

    if args.search_user:
        print_user_search(trees, args.search_user)
    if args.search_group:
        print_group_search(trees, args.search_group)

    print("\n[*] Running analysis...")
    findings = analyze(trees)
    print(f"  [{len(findings)} findings]")

    print("\n[*] Generating HTML report...")
    generate_html_report(trees, findings, discovery_results, args.output)
    print(f"\n[+] Done. Open {args.output} in a browser.")


if __name__ == "__main__":
    main()
