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
    name: str                    # CN from Get-ADGroupMember
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
    display_name: str = ""       # AD DisplayName attribute (the "real" name)
    smartcard_required: bool = False

    @property
    def display_label(self) -> str:
        """Display Name (samAccountName) format for findings."""
        # Prefer DisplayName > CN > SAM
        friendly = self.display_name or self.name
        if friendly and friendly.lower() != self.sam_account_name.lower():
            return f"{friendly} ({self.sam_account_name})"
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
                AdminCount, Description, whenCreated, MemberOf, `
                DisplayName, SmartcardLogonRequired -ErrorAction SilentlyContinue
            if ($user) {{
                $extra['Enabled'] = $user.Enabled
                $extra['LastLogonDate'] = if ($user.LastLogonDate) {{ $user.LastLogonDate.ToString('o') }} else {{ $null }}
                $extra['PasswordLastSet'] = if ($user.PasswordLastSet) {{ $user.PasswordLastSet.ToString('o') }} else {{ $null }}
                $extra['PasswordNeverExpires'] = $user.PasswordNeverExpires
                $extra['AdminCount'] = $user.AdminCount
                $extra['Description'] = $user.Description
                $extra['DisplayName'] = $user.DisplayName
                $extra['SmartcardLogonRequired'] = $user.SmartcardLogonRequired
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
           pw_never_expires=False, admin_count=1, desc="",
           display_name="", smartcard=False):
        now = datetime.now(timezone.utc)
        return ADObject(
            name=name, sam_account_name=sam,
            distinguished_name=f"CN={name},OU=Users,DC=example,DC=local",
            object_class="user", enabled=enabled,
            last_logon=(now - timedelta(days=ll_days)).isoformat() if ll_days else None,
            password_last_set=(now - timedelta(days=pw_days)).isoformat(),
            password_never_expires=pw_never_expires, admin_count=admin_count,
            description=desc, when_created=(now - timedelta(days=800)).isoformat(),
            display_name=display_name or name,
            smartcard_required=smartcard,
        )

    # Shared nested group — appears under both DA and Administrators
    infra_ops = GroupNode("Infrastructure Ops", "CN=Infrastructure Ops,OU=Groups,DC=example,DC=local", 1, [])
    infra_ops.direct_members = [
        mu("k.infraops", "k.infraops", display_name="Karl Johansson", desc="Infrastructure team"),
        mu("svc.patching", "svc.patching", display_name="Svc Patching",
           pw_never_expires=True, pw_days=500, desc="Patching service acct"),
    ]
    net_team = GroupNode("Network Team", "CN=Network Team,OU=Groups,DC=example,DC=local", 2, [])
    net_team.direct_members = [
        mu("l.neteng", "l.neteng", display_name="Larry Okonkwo", desc="Network engineer"),
    ]
    firewall_ops = GroupNode("Firewall Operators", "CN=Firewall Operators,OU=Groups,DC=example,DC=local", 3, [])
    firewall_ops.direct_members = [
        mu("m.fwadmin", "m.fwadmin", display_name="Michael Torres", desc="Firewall admin"),
        mu("n.noc", "n.noc", display_name="Nancy Park", desc="NOC analyst"),
    ]
    net_team.child_groups.append(firewall_ops)
    infra_ops.child_groups.append(net_team)

    # Domain Admins
    da = GroupNode("Domain Admins", "CN=Domain Admins,CN=Users,DC=example,DC=local", 0, [])
    da.direct_members = [
        mu("admin.primary", "admin.primary", display_name="John Richardson",
           desc="Primary DA - IT Lead", smartcard=True, pw_days=500),
        mu("svc.migration", "svc.migration", display_name="Svc Migration 2019",
           ll_days=780, pw_days=780, pw_never_expires=True, desc="Server migration project 2019"),
        mu("j.formeradmin", "j.formeradmin", display_name="Jane Whitfield",
           enabled=False, ll_days=400),
    ]
    server_admins = GroupNode("Server Admins", "CN=Server Admins,OU=Groups,DC=example,DC=local", 1, ["Domain Admins"])
    server_admins.direct_members = [
        mu("b.serverguy", "b.serverguy", display_name="Robert Martinez",
           desc="Server team lead", smartcard=True, pw_days=300),
        mu("c.ops", "c.ops", display_name="Carol Nguyen", desc="Operations"),
    ]
    helpdesk_t2 = GroupNode("Helpdesk Tier2", "CN=Helpdesk Tier2,OU=Groups,DC=example,DC=local", 2, [])
    helpdesk_t2.direct_members = [
        mu("d.helpdesk", "d.helpdesk", display_name="David Chen", desc="Helpdesk tier 2"),
        mu("e.support", "e.support", display_name="Eve Rodriguez", desc="Helpdesk tier 2"),
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
        mu("admin.primary", "admin.primary", display_name="John Richardson",
           desc="Primary DA - IT Lead", smartcard=True, pw_days=500),
    ]
    infra_admins = copy.deepcopy(infra_ops)
    infra_admins.parent_path = ["Administrators"]
    admins.child_groups.append(infra_admins)

    ea = GroupNode("Enterprise Admins", "CN=Enterprise Admins,CN=Users,DC=example,DC=local", 0, [])
    ea.direct_members = [
        mu("admin.primary", "admin.primary", display_name="John Richardson",
           desc="Primary DA - IT Lead", smartcard=True, pw_days=500),
        mu("f.enterprise", "f.enterprise", display_name="Frank Petrov",
           pw_days=400, desc="Enterprise admin"),
    ]

    bo = GroupNode("Backup Operators", "CN=Backup Operators,CN=Builtin,DC=example,DC=local", 0, [])
    bo.direct_members = [
        mu("svc.backup", "svc.backup", display_name="Svc Backup Agent",
           pw_never_expires=True, desc="Backup service account"),
        mu("g.backups", "g.backups", display_name="Greg Thompson",
           ll_days=200, desc="Former backup admin"),
    ]

    sql_admins = GroupNode("SQL Server Admins", "CN=SQL Server Admins,OU=Groups,DC=example,DC=local", 0, [])
    sql_admins.direct_members = [
        mu("h.dba", "h.dba", display_name="Henry Nakamura", desc="Senior DBA"),
        mu("svc.sql", "svc.sql", display_name="Svc SQL Agent",
           pw_never_expires=True, pw_days=600, desc="SQL maintenance agent"),
    ]

    it_auto = GroupNode("IT Automation Svc", "CN=IT Automation Svc,OU=ServiceGroups,DC=example,DC=local", 0, [])
    it_auto.direct_members = [
        mu("svc.ansible", "svc.ansible", display_name="Svc Ansible Tower",
           pw_never_expires=True, desc="Ansible automation"),
        mu("svc.sccm", "svc.sccm", display_name="Svc SCCM Deploy",
           pw_never_expires=True, pw_days=900, desc="SCCM deployment"),
    ]

    ad_deleg = GroupNode("AD Delegation Group", "CN=AD Delegation Group,OU=Groups,DC=example,DC=local", 0, [])
    ad_deleg.direct_members = [
        mu("admin.primary", "admin.primary", display_name="John Richardson",
           desc="Primary DA - IT Lead", smartcard=True, pw_days=500),
        mu("i.iam", "i.iam", display_name="Ivan Kowalski", desc="IAM team lead"),
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
                when_created=m.get("whenCreated"), member_of_direct=m.get("MemberOf", []),
                display_name=m.get("DisplayName", ""),
                smartcard_required=m.get("SmartcardLogonRequired", False),
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
            if acct.smartcard_required:
                findings.append(Finding(
                    severity="INFO", category="Password Never Expires",
                    account=acct.display_label, sam=acct.sam_account_name,
                    detail="PasswordNeverExpires set — smart card enforced, reduced risk",
                    inheritance_path=path
                ))
            else:
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
                    if acct.smartcard_required:
                        findings.append(Finding(
                            severity="LOW", category="Stale Password (Smart Card)",
                            account=acct.display_label, sam=acct.sam_account_name,
                            detail=f"Password last set {days} days ago — smart card enforced, NTLM hash still static",
                            inheritance_path=path
                        ))
                    else:
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
# AD Attack Surface Analysis (BloodHound-style flat findings)
# ============================================================================

def get_privileged_sams(trees: dict) -> set[str]:
    """Build set of SAMs known to be privileged for context-aware findings."""
    privs = set()
    for tree in trees.values():
        for acct, _ in collect_all_accounts(tree):
            privs.add(acct.sam_account_name.lower())
    return privs


def _flatten_ps_list(value) -> list[str]:
    """
    Coerce a PowerShell-serialized value into a list of strings.

    PowerShell's ConvertTo-Json may return:
      - None / empty
      - A single string
      - A list of strings
      - A list of dicts (when objects don't serialize cleanly to strings)
      - A single dict
    We extract the most useful string representation in each case.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, list):
        return [str(value)]

    out = []
    for item in value:
        if item is None:
            continue
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            # Try common representations in priority order
            for key in ("Value", "value", "Name", "name", "DistinguishedName",
                        "distinguishedName", "DN", "dn", "ToString"):
                if key in item and isinstance(item[key], str):
                    out.append(item[key])
                    break
            else:
                # Last resort: stringify the dict
                out.append(str(item))
        else:
            out.append(str(item))
    return out


def check_kerberoastable(privileged_sams: set[str]) -> list[Finding]:
    """Find user accounts with SPNs (Kerberoastable). Privileged ones are critical."""
    print("  Checking for Kerberoastable accounts...")
    cmd = """
    Get-ADUser -Filter {ServicePrincipalName -like '*' -and Enabled -eq $true} `
        -Properties ServicePrincipalName, DisplayName, AdminCount, PasswordLastSet,
                    LastLogonDate, msDS-SupportedEncryptionTypes |
    Select SamAccountName, DisplayName, ServicePrincipalName, AdminCount,
           @{N='PasswordLastSet';E={if($_.PasswordLastSet){$_.PasswordLastSet.ToString('o')}}},
           @{N='LastLogonDate';E={if($_.LastLogonDate){$_.LastLogonDate.ToString('o')}}},
           @{N='EncTypes';E={$_.'msDS-SupportedEncryptionTypes'}} |
    ConvertTo-Json -Depth 3
    """
    results = ps_json(cmd)
    if not results:
        return []

    findings = []
    for u in results:
        sam = u.get("SamAccountName", "")
        display = u.get("DisplayName") or sam
        label = f"{display} ({sam})" if display.lower() != sam.lower() else sam
        spns = _flatten_ps_list(u.get("ServicePrincipalName"))
        spn_summary = ", ".join(spns[:3]) + (f" (+{len(spns)-3} more)" if len(spns) > 3 else "")
        is_priv = sam.lower() in privileged_sams or u.get("AdminCount") == 1

        # Encryption type bit 0x10 = AES128, 0x20 = AES256. Anything else = RC4 fallback risk
        enc = u.get("EncTypes", 0) or 0
        weak_enc = (enc & 0x18) == 0  # No AES configured

        if is_priv:
            sev = "CRITICAL" if weak_enc else "HIGH"
            detail = f"Privileged Kerberoastable account. SPN(s): {spn_summary}."
            if weak_enc:
                detail += " Weak encryption (RC4 fallback) — fast offline cracking possible."
            findings.append(Finding(
                severity=sev, category="Kerberoastable (Privileged)",
                account=label, sam=sam, detail=detail
            ))
        else:
            findings.append(Finding(
                severity="MEDIUM" if weak_enc else "LOW",
                category="Kerberoastable", account=label, sam=sam,
                detail=f"Service account with SPN(s): {spn_summary}." +
                       (" Weak encryption (RC4)." if weak_enc else "")
            ))
    return findings


def check_asreproastable(privileged_sams: set[str]) -> list[Finding]:
    """Find accounts with DONT_REQ_PREAUTH (AS-REP roastable)."""
    print("  Checking for AS-REP roastable accounts...")
    cmd = """
    Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true -and Enabled -eq $true} `
        -Properties DisplayName, AdminCount |
    Select SamAccountName, DisplayName, AdminCount |
    ConvertTo-Json -Depth 2
    """
    results = ps_json(cmd)
    if not results:
        return []

    findings = []
    for u in results:
        sam = u.get("SamAccountName", "")
        display = u.get("DisplayName") or sam
        label = f"{display} ({sam})" if display.lower() != sam.lower() else sam
        is_priv = sam.lower() in privileged_sams or u.get("AdminCount") == 1
        sev = "CRITICAL" if is_priv else "HIGH"
        findings.append(Finding(
            severity=sev, category="AS-REP Roastable",
            account=label, sam=sam,
            detail="DONT_REQ_PREAUTH set — Kerberos AS-REP can be requested without authentication and cracked offline" +
                   (". PRIVILEGED ACCOUNT." if is_priv else "")
        ))
    return findings


def check_unconstrained_delegation() -> list[Finding]:
    """Find computers/users with unconstrained Kerberos delegation."""
    print("  Checking for unconstrained delegation...")
    findings = []

    # Computers (TRUSTED_FOR_DELEGATION = 0x80000)
    comp_cmd = """
    Get-ADComputer -Filter {TrustedForDelegation -eq $true} `
        -Properties TrustedForDelegation, OperatingSystem, LastLogonDate |
    Select SamAccountName, DNSHostName, OperatingSystem,
           @{N='LastLogonDate';E={if($_.LastLogonDate){$_.LastLogonDate.ToString('o')}}} |
    ConvertTo-Json -Depth 2
    """
    comps = ps_json(comp_cmd)
    if comps:
        for c in comps:
            sam = c.get("SamAccountName", "")
            host = c.get("DNSHostName") or sam
            # DCs are expected to have unconstrained delegation - downgrade severity
            is_dc = "domain controller" in (c.get("OperatingSystem", "") or "").lower()
            if is_dc:
                continue  # Skip DCs - this is normal/required
            findings.append(Finding(
                severity="CRITICAL", category="Unconstrained Delegation (Computer)",
                account=host, sam=sam,
                detail=f"Computer has unconstrained delegation. OS: {c.get('OperatingSystem', '?')}. "
                       f"Compromise allows TGT capture for any user that authenticates to this host."
            ))

    # Users (rare but very dangerous when present)
    user_cmd = """
    Get-ADUser -Filter {TrustedForDelegation -eq $true} `
        -Properties TrustedForDelegation, DisplayName |
    Select SamAccountName, DisplayName |
    ConvertTo-Json -Depth 2
    """
    users = ps_json(user_cmd)
    if users:
        for u in users:
            sam = u.get("SamAccountName", "")
            display = u.get("DisplayName") or sam
            label = f"{display} ({sam})" if display.lower() != sam.lower() else sam
            findings.append(Finding(
                severity="CRITICAL", category="Unconstrained Delegation (User)",
                account=label, sam=sam,
                detail="User account has unconstrained delegation — extremely high risk, very rarely legitimate"
            ))
    return findings


def check_constrained_delegation_protocol_transition() -> list[Finding]:
    """Find accounts with constrained delegation + protocol transition (ANY auth)."""
    print("  Checking for constrained delegation w/ protocol transition...")
    cmd = """
    Get-ADObject -LDAPFilter '(&(msDS-AllowedToDelegateTo=*)(userAccountControl:1.2.840.113556.1.4.803:=16777216))' `
        -Properties SamAccountName, DisplayName, msDS-AllowedToDelegateTo, objectClass |
    Select SamAccountName, DisplayName, objectClass,
           @{N='DelegateTo';E={$_.'msDS-AllowedToDelegateTo'}} |
    ConvertTo-Json -Depth 3
    """
    results = ps_json(cmd)
    if not results:
        return []

    findings = []
    for o in results:
        sam = o.get("SamAccountName", "")
        display = o.get("DisplayName") or sam
        label = f"{display} ({sam})" if display.lower() != sam.lower() else sam
        targets = _flatten_ps_list(o.get("DelegateTo"))
        target_summary = ", ".join(targets[:3]) + (f" (+{len(targets)-3} more)" if len(targets) > 3 else "")
        findings.append(Finding(
            severity="HIGH", category="Constrained Delegation w/ Protocol Transition",
            account=label, sam=sam,
            detail=f"Can delegate to {target_summary} via 'Use any authentication protocol' — S4U2Self abuse possible"
        ))
    return findings


def check_resource_based_constrained_delegation() -> list[Finding]:
    """Find computers configured as RBCD targets — abuse vector if attacker controls listed principals."""
    print("  Checking for resource-based constrained delegation...")
    cmd = """
    Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
    Where-Object { $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' } |
    Select SamAccountName, DNSHostName |
    ConvertTo-Json -Depth 2
    """
    results = ps_json(cmd, timeout=180)
    if not results:
        return []

    findings = []
    for c in results:
        sam = c.get("SamAccountName", "")
        host = c.get("DNSHostName") or sam
        findings.append(Finding(
            severity="MEDIUM", category="Resource-Based Constrained Delegation",
            account=host, sam=sam,
            detail="Computer has RBCD configured — review msDS-AllowedToActOnBehalfOfOtherIdentity. "
                   "Abuse possible if attacker controls a listed principal."
        ))
    return findings


def check_password_not_required() -> list[Finding]:
    """Find accounts with PasswordNotRequired flag set."""
    print("  Checking for PasswordNotRequired accounts...")
    cmd = """
    Get-ADUser -Filter {PasswordNotRequired -eq $true -and Enabled -eq $true} `
        -Properties DisplayName, AdminCount |
    Select SamAccountName, DisplayName, AdminCount |
    ConvertTo-Json -Depth 2
    """
    results = ps_json(cmd)
    if not results:
        return []

    findings = []
    for u in results:
        sam = u.get("SamAccountName", "")
        display = u.get("DisplayName") or sam
        label = f"{display} ({sam})" if display.lower() != sam.lower() else sam
        is_priv = u.get("AdminCount") == 1
        findings.append(Finding(
            severity="CRITICAL" if is_priv else "HIGH",
            category="Password Not Required",
            account=label, sam=sam,
            detail="PASSWD_NOTREQD flag set — account can have empty password" +
                   (". PRIVILEGED ACCOUNT." if is_priv else "")
        ))
    return findings


def check_pre_win2k_compat() -> list[Finding]:
    """Check Pre-Windows 2000 Compatible Access group membership."""
    print("  Checking Pre-Windows 2000 Compatible Access...")
    cmd = """
    try {
        Get-ADGroupMember -Identity 'Pre-Windows 2000 Compatible Access' |
        Select Name, SamAccountName, objectClass | ConvertTo-Json -Depth 2
    } catch {}
    """
    results = ps_json(cmd)
    if not results:
        return []

    findings = []
    for m in results:
        sam = m.get("SamAccountName", "")
        name = m.get("Name", sam)
        # Anonymous Logon or Authenticated Users in this group is the classic finding
        if "anonymous" in name.lower() or "authenticated users" in name.lower() or sam.lower() in ("s-1-5-7", "s-1-5-11"):
            findings.append(Finding(
                severity="HIGH", category="Pre-Win2K Compatible Access Misconfig",
                account=name, sam=sam,
                detail=f"'{name}' is in Pre-Windows 2000 Compatible Access — allows anonymous LDAP enumeration of domain"
            ))
    return findings


def check_lm_hash_storage() -> list[Finding]:
    """Find accounts where LM hash storage is not disabled."""
    print("  Checking for LM hash storage on accounts...")
    # NoAuth = bit 0x80 in userAccountControl indicates "Don't store password using reversible encryption" is OFF
    # We check the inverse: ENCRYPTED_TEXT_PWD_ALLOWED (0x80) = reversible password encryption enabled
    cmd = """
    Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq $true -and Enabled -eq $true} `
        -Properties DisplayName, AdminCount |
    Select SamAccountName, DisplayName, AdminCount |
    ConvertTo-Json -Depth 2
    """
    results = ps_json(cmd)
    if not results:
        return []

    findings = []
    for u in results:
        sam = u.get("SamAccountName", "")
        display = u.get("DisplayName") or sam
        label = f"{display} ({sam})" if display.lower() != sam.lower() else sam
        is_priv = u.get("AdminCount") == 1
        findings.append(Finding(
            severity="HIGH" if is_priv else "MEDIUM",
            category="Reversible Password Encryption",
            account=label, sam=sam,
            detail="Password stored with reversible encryption — equivalent to plaintext storage"
        ))
    return findings


def check_inactive_computers() -> list[Finding]:
    """Find inactive computer accounts (potential stale or dead systems)."""
    print("  Checking for inactive computer accounts...")
    cmd = """
    $cutoff = (Get-Date).AddDays(-180)
    Get-ADComputer -Filter {Enabled -eq $true} -Properties LastLogonDate, OperatingSystem |
    Where-Object { $_.LastLogonDate -and $_.LastLogonDate -lt $cutoff } |
    Select SamAccountName, DNSHostName, OperatingSystem,
           @{N='LastLogonDate';E={$_.LastLogonDate.ToString('o')}} |
    ConvertTo-Json -Depth 2
    """
    results = ps_json(cmd, timeout=180)
    if not results:
        return []

    findings = []
    now = datetime.now(timezone.utc)
    for c in results:
        sam = c.get("SamAccountName", "")
        host = c.get("DNSHostName") or sam
        ll = c.get("LastLogonDate", "")
        try:
            last = datetime.fromisoformat(ll.replace('Z', '+00:00'))
            days = (now - last).days
            sev = "HIGH" if days > 365 else "MEDIUM"
            findings.append(Finding(
                severity=sev, category="Inactive Computer Account",
                account=host, sam=sam,
                detail=f"Computer enabled but inactive for {days} days. OS: {c.get('OperatingSystem', '?')}"
            ))
        except (ValueError, TypeError):
            pass
    return findings


def check_domain_trusts() -> list[Finding]:
    """Enumerate domain trusts and flag risky configurations."""
    print("  Enumerating domain trusts...")
    cmd = """
    Get-ADTrust -Filter * |
    Select Name, Direction, TrustType, ForestTransitive, SIDFilteringForestAware,
           SIDFilteringQuarantined, TGTDelegation, IntraForest, SelectiveAuthentication |
    ConvertTo-Json -Depth 2
    """
    results = ps_json(cmd)
    if not results:
        return []

    findings = []
    for t in results:
        name = t.get("Name", "?")
        direction = t.get("Direction", "?")  # 1=Inbound, 2=Outbound, 3=Bidirectional
        dir_label = {1: "Inbound", 2: "Outbound", 3: "Bidirectional"}.get(direction, str(direction))
        intra = t.get("IntraForest", False)

        # SID filtering disabled on external trust = SID history injection risk
        if not intra and not t.get("SIDFilteringQuarantined", True):
            findings.append(Finding(
                severity="HIGH", category="Trust SID Filtering Disabled",
                account=name, sam=name,
                detail=f"{dir_label} trust to {name} has SID filtering disabled — SID history injection possible"
            ))

        # TGT delegation enabled = unconstrained delegation across trust
        if t.get("TGTDelegation", False) and not intra:
            findings.append(Finding(
                severity="HIGH", category="Trust TGT Delegation Enabled",
                account=name, sam=name,
                detail=f"{dir_label} trust to {name} allows TGT delegation across trust boundary"
            ))

        # Inform on all trusts as INFO
        findings.append(Finding(
            severity="INFO", category="Domain Trust",
            account=name, sam=name,
            detail=f"{dir_label} trust. Type: {t.get('TrustType', '?')}. "
                   f"Forest transitive: {t.get('ForestTransitive', False)}. "
                   f"Selective auth: {t.get('SelectiveAuthentication', False)}."
        ))
    return findings


def check_adcs_templates() -> list[Finding]:
    """Check for vulnerable ADCS certificate templates (ESC1, ESC2, ESC4, ESC8)."""
    print("  Checking ADCS certificate templates...")
    cmd = """
    try {
        $configNC = (Get-ADRootDSE).configurationNamingContext
        $templatesPath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
        Get-ADObject -SearchBase $templatesPath -LDAPFilter '(objectClass=pKICertificateTemplate)' `
            -Properties Name, DisplayName, msPKI-Certificate-Name-Flag, msPKI-Enrollment-Flag,
                        pKIExtendedKeyUsage, msPKI-RA-Signature, nTSecurityDescriptor -ErrorAction Stop |
        ForEach-Object {
            $nameFlag = $_.'msPKI-Certificate-Name-Flag'
            $enrollFlag = $_.'msPKI-Enrollment-Flag'
            $eku = $_.pKIExtendedKeyUsage
            $raSig = $_.'msPKI-RA-Signature'

            # ESC1: ENROLLEE_SUPPLIES_SUBJECT (0x1) + client auth EKU + no manager approval + no auth signature
            $supplySubject = ($nameFlag -band 0x1) -ne 0
            $managerApproval = ($enrollFlag -band 0x2) -ne 0
            $hasClientAuth = $eku -contains '1.3.6.1.5.5.7.3.2' -or $eku -contains '1.3.6.1.5.2.3.4' -or $eku -contains '2.5.29.37.0' -or $null -eq $eku -or $eku.Count -eq 0

            # ESC2: Any Purpose EKU (2.5.29.37.0) or no EKU
            $anyPurpose = $eku -contains '2.5.29.37.0' -or $null -eq $eku -or $eku.Count -eq 0

            [PSCustomObject]@{
                Name = $_.Name
                DisplayName = $_.DisplayName
                SupplySubject = $supplySubject
                ManagerApproval = $managerApproval
                HasClientAuth = $hasClientAuth
                AnyPurpose = $anyPurpose
                RASignature = $raSig
            }
        } | ConvertTo-Json -Depth 3
    } catch {}
    """
    results = ps_json(cmd, timeout=180)
    if not results:
        return []

    findings = []
    for t in results:
        name = t.get("Name", "?")
        display = t.get("DisplayName") or name

        # ESC1
        if (t.get("SupplySubject") and t.get("HasClientAuth") and
            not t.get("ManagerApproval") and (t.get("RASignature", 0) or 0) == 0):
            findings.append(Finding(
                severity="CRITICAL", category="ADCS ESC1",
                account=display, sam=name,
                detail=f"Template '{name}' allows enrollee-supplied subject + client auth EKU with no manager approval. "
                       f"Any enrollee can request a cert as any user including Domain Admins."
            ))

        # ESC2
        if t.get("AnyPurpose") and not t.get("ManagerApproval"):
            findings.append(Finding(
                severity="HIGH", category="ADCS ESC2",
                account=display, sam=name,
                detail=f"Template '{name}' has Any Purpose EKU with no manager approval. Cert usable for any purpose."
            ))

    return findings


def check_adcs_esc8() -> list[Finding]:
    """Check for ADCS web enrollment without HTTPS / NTLM relay risk (ESC8 indicator)."""
    print("  Checking for ADCS Certificate Authority web enrollment...")
    cmd = """
    try {
        $configNC = (Get-ADRootDSE).configurationNamingContext
        $caPath = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"
        Get-ADObject -SearchBase $caPath -LDAPFilter '(objectClass=pKIEnrollmentService)' `
            -Properties Name, dNSHostName -ErrorAction Stop |
        Select Name, dNSHostName | ConvertTo-Json -Depth 2
    } catch {}
    """
    results = ps_json(cmd)
    if not results:
        return []

    findings = []
    for ca in results:
        name = ca.get("Name", "?")
        host = ca.get("dNSHostName", "?")
        findings.append(Finding(
            severity="MEDIUM", category="ADCS Enrollment Service Present",
            account=host, sam=name,
            detail=f"Certificate Authority '{name}' on {host}. "
                   f"Manually verify web enrollment is disabled or HTTPS-only with EPA, "
                   f"and that RPC enrollment requires signing (mitigates ESC8/ESC11)."
        ))
    return findings


def check_foreign_security_principals(privileged_groups: Optional[set[str]] = None) -> list[Finding]:
    """
    Find foreign security principals (cross-domain/forest references).

    Args:
        privileged_groups: Set of lowercase group names known to be privileged
                          (from default Tier 0 list + discovery results).
                          If None, all FSP findings are reported as INFO.
    """
    print("  Enumerating foreign security principals...")
    if privileged_groups is None:
        privileged_groups = set()
    cmd = """
    try {
        $domain = (Get-ADDomain).DistinguishedName
        Get-ADObject -SearchBase "CN=ForeignSecurityPrincipals,$domain" `
            -LDAPFilter '(objectClass=foreignSecurityPrincipal)' -Properties memberOf |
        Where-Object { $_.memberOf } |
        Select Name, DistinguishedName,
               @{N='MemberOf';E={@($_.memberOf | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' })}} |
        ConvertTo-Json -Depth 3
    } catch {}
    """
    results = ps_json(cmd)
    if not results:
        return []

    findings = []
    for fsp in results:
        sid = fsp.get("Name", "?")
        groups = _flatten_ps_list(fsp.get("MemberOf"))
        # Match against actual known privileged groups, not pattern guessing
        matched_priv = [g for g in groups if g.lower() in privileged_groups]
        sev = "HIGH" if matched_priv else "INFO"
        detail = f"Foreign principal SID {sid} is member of: {', '.join(groups)}"
        if matched_priv:
            detail += f" — PRIVILEGED GROUP(S): {', '.join(matched_priv)}"
        findings.append(Finding(
            severity=sev, category="Foreign Security Principal",
            account=sid, sam=sid, detail=detail
        ))
    return findings


def check_laps_coverage() -> list[Finding]:
    """Check LAPS coverage on computer accounts (legacy and Windows LAPS)."""
    print("  Checking LAPS coverage on computers...")
    # Try Windows LAPS first (newer), fall back to legacy LAPS
    cmd = """
    $total = (Get-ADComputer -Filter {Enabled -eq $true}).Count
    # Windows LAPS (msLAPS-Password) — newer
    $newLapsCount = 0
    try {
        $newLapsCount = (Get-ADComputer -Filter {Enabled -eq $true} -Properties 'msLAPS-Password' |
            Where-Object { $_.'msLAPS-Password' }).Count
    } catch {}
    # Legacy LAPS (ms-Mcs-AdmPwd)
    $legacyLapsCount = 0
    try {
        $legacyLapsCount = (Get-ADComputer -Filter {Enabled -eq $true} -Properties 'ms-Mcs-AdmPwd' |
            Where-Object { $_.'ms-Mcs-AdmPwd' }).Count
    } catch {}
    [PSCustomObject]@{
        Total = $total
        WindowsLAPS = $newLapsCount
        LegacyLAPS = $legacyLapsCount
    } | ConvertTo-Json
    """
    result = ps_json(cmd, timeout=180)
    if not result:
        return []

    r = result[0] if isinstance(result, list) else result
    total = r.get("Total", 0)
    new_laps = r.get("WindowsLAPS", 0)
    legacy_laps = r.get("LegacyLAPS", 0)
    covered = max(new_laps, legacy_laps)

    if total == 0:
        return []
    pct = (covered / total * 100) if total else 0

    findings = []
    if covered == 0:
        findings.append(Finding(
            severity="HIGH", category="LAPS Not Deployed",
            account="(domain-wide)", sam="LAPS",
            detail=f"No computers have LAPS configured (0 / {total}). "
                   f"Local admin password reuse risk across the domain."
        ))
    elif pct < 90:
        sev = "MEDIUM" if pct < 50 else "LOW"
        findings.append(Finding(
            severity=sev, category="LAPS Coverage Incomplete",
            account="(domain-wide)", sam="LAPS",
            detail=f"LAPS deployed on {covered}/{total} computers ({pct:.1f}%). "
                   f"Windows LAPS: {new_laps}, Legacy LAPS: {legacy_laps}."
        ))
    else:
        findings.append(Finding(
            severity="INFO", category="LAPS Coverage Good",
            account="(domain-wide)", sam="LAPS",
            detail=f"LAPS deployed on {covered}/{total} computers ({pct:.1f}%)."
        ))
    return findings


def run_attack_surface_analysis(privileged_sams: set[str],
                                privileged_groups: Optional[set[str]] = None,
                                skip_slow: bool = False) -> list[Finding]:
    """
    Run all BloodHound-style attack surface checks.

    Args:
        privileged_sams: Lowercase SAM names of accounts in privileged groups
        privileged_groups: Lowercase names of groups considered privileged
                          (defaults + discovered). Used by FSP check.
        skip_slow: Skip slow modules (RBCD, inactive computers, LAPS)
    """
    print("\n[*] Running attack surface analysis...")
    findings = []

    findings.extend(check_kerberoastable(privileged_sams))
    findings.extend(check_asreproastable(privileged_sams))
    findings.extend(check_unconstrained_delegation())
    findings.extend(check_constrained_delegation_protocol_transition())
    findings.extend(check_password_not_required())
    findings.extend(check_pre_win2k_compat())
    findings.extend(check_lm_hash_storage())
    findings.extend(check_domain_trusts())
    findings.extend(check_adcs_templates())
    findings.extend(check_adcs_esc8())
    findings.extend(check_foreign_security_principals(privileged_groups))

    if not skip_slow:
        findings.extend(check_resource_based_constrained_delegation())
        findings.extend(check_inactive_computers())
        findings.extend(check_laps_coverage())

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: sev_order.get(f.severity, 5))
    print(f"  [{len(findings)} attack surface findings]")
    return findings


# ============================================================================
# NOISY: Endpoint-touching modules (require explicit opt-in)
# ============================================================================

def get_all_computers(enabled_only: bool = True) -> list[dict]:
    """Pull all computer accounts for endpoint enumeration."""
    filt = "{Enabled -eq $true}" if enabled_only else "*"
    cmd = f"""
    Get-ADComputer -Filter {filt} -Properties OperatingSystem, LastLogonDate |
    Select SamAccountName, DNSHostName, OperatingSystem,
           @{{N='LastLogonDate';E={{if($_.LastLogonDate){{$_.LastLogonDate.ToString('o')}}}}}} |
    ConvertTo-Json -Depth 2
    """
    results = ps_json(cmd, timeout=300)
    if not results:
        return []
    # Filter out stale (>90 days) to reduce useless connection attempts
    fresh = []
    cutoff = datetime.now(timezone.utc) - timedelta(days=90)
    for c in results:
        ll = c.get("LastLogonDate")
        if ll:
            try:
                last = datetime.fromisoformat(ll.replace('Z', '+00:00'))
                if last < cutoff:
                    continue
            except (ValueError, TypeError):
                pass
        fresh.append(c)
    return fresh


def collect_local_admins(privileged_sams: set[str], computer_limit: Optional[int] = None,
                         workers: int = 25) -> tuple[list[Finding], dict]:
    """
    Enumerate local Administrators group on all reachable computers via SAMR/RPC.
    Returns (findings, raw_data) where raw_data maps computer -> [admin_member_sids].

    NOISY: Generates SMB/RPC traffic to every computer enumerated.
    """
    print("  [NOISY] Enumerating local Administrators on all computers...")
    print("         This generates SMB/RPC traffic to every endpoint.")

    try:
        from impacket.dcerpc.v5 import transport, samr
        from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
    except ImportError:
        return [Finding("INFO", "Local Admin Mapping Skipped", "(domain-wide)", "LOCALADMIN",
                        "impacket not installed — run: pip install impacket")], {}

    computers = get_all_computers(enabled_only=True)
    if computer_limit:
        computers = computers[:computer_limit]
    print(f"         Targeting {len(computers)} active computers (workers={workers}).")

    raw = {}            # computer -> list of admin member SIDs
    reachable = 0
    unreachable = 0
    errors = 0

    def enum_one(comp):
        host = comp.get("DNSHostName") or comp.get("SamAccountName", "").rstrip("$")
        if not host:
            return None, None, "no-hostname"
        try:
            string_binding = f'ncacn_np:{host}[\\pipe\\samr]'
            rpctransport = transport.DCERPCTransportFactory(string_binding)
            rpctransport.set_connect_timeout(5)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            # Connect to local SAM
            resp = samr.hSamrConnect(dce)
            handle = resp['ServerHandle']
            # Enumerate domains (local SAM has Builtin + machine domain)
            domains = samr.hSamrEnumerateDomainsInSamServer(dce, handle)
            admin_members = []
            for d in domains['Buffer']['Buffer']:
                dom_name = d['Name']
                if dom_name.lower() != 'builtin':
                    continue
                sid_resp = samr.hSamrLookupDomainInSamServer(dce, handle, dom_name)
                dom_handle = samr.hSamrOpenDomain(dce, handle, MAXIMUM_ALLOWED, sid_resp['DomainId'])['DomainHandle']
                # Administrators RID = 544
                alias_handle = samr.hSamrOpenAlias(dce, dom_handle, MAXIMUM_ALLOWED, 544)['AliasHandle']
                members = samr.hSamrGetMembersInAlias(dce, alias_handle)
                for sid in members['Members']['Sids']:
                    admin_members.append(sid['SidPointer'].formatCanonical())
            dce.disconnect()
            return host, admin_members, None
        except Exception as e:
            err = str(e).lower()
            if "unreachable" in err or "timed out" in err or "refused" in err:
                return host, None, "unreachable"
            return host, None, "error"

    from concurrent.futures import ThreadPoolExecutor, as_completed
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(enum_one, c): c for c in computers}
        completed = 0
        for fut in as_completed(futures):
            host, admins, status = fut.result()
            completed += 1
            if completed % 50 == 0:
                print(f"         Progress: {completed}/{len(computers)}")
            if status == "unreachable":
                unreachable += 1
            elif status == "error":
                errors += 1
            elif admins is not None:
                reachable += 1
                raw[host] = admins

    print(f"         Reachable: {reachable}, Unreachable: {unreachable}, Errors: {errors}")

    findings = []

    # Resolve SIDs to SAM names where possible
    sid_to_sam = _resolve_sids([sid for admins in raw.values() for sid in admins])

    # Build inverted map: sam -> [hosts they're local admin on]
    user_admin_map = defaultdict(list)
    for host, sids in raw.items():
        for sid in sids:
            sam = sid_to_sam.get(sid, sid)
            user_admin_map[sam].append(host)

    # Findings: privileged accounts as local admin on many hosts (privilege concentration)
    for sam, hosts in user_admin_map.items():
        is_priv = sam.lower() in privileged_sams
        host_count = len(hosts)
        if host_count >= 50:
            sev = "CRITICAL" if is_priv else "HIGH"
            findings.append(Finding(
                severity=sev, category="Local Admin Sprawl",
                account=sam, sam=sam,
                detail=f"Local Administrator on {host_count} computers" +
                       (" — privileged AD account" if is_priv else "")
            ))
        elif host_count >= 10 and is_priv:
            findings.append(Finding(
                severity="MEDIUM", category="Local Admin Sprawl",
                account=sam, sam=sam,
                detail=f"Privileged AD account is local admin on {host_count} computers"
            ))

    # Findings: non-default groups granted local admin
    for host, sids in raw.items():
        for sid in sids:
            sam = sid_to_sam.get(sid, sid)
            # Default Administrators members are RID 500 (admin), Domain Admins, Enterprise Admins
            if sid.endswith("-500") or sam.lower() in ("domain admins", "enterprise admins", "administrator"):
                continue
            # Anything else is non-default — surface it
            findings.append(Finding(
                severity="LOW", category="Non-Default Local Admin",
                account=sam, sam=sam,
                detail=f"Member of local Administrators on {host}",
                inheritance_path=host
            ))

    return findings, dict(raw)


def _resolve_sids(sids: list[str]) -> dict[str, str]:
    """Resolve list of SIDs to SAM names via PowerShell. Returns {sid: sam}."""
    if not sids:
        return {}
    unique = list(set(sids))
    result = {}
    # Batch in chunks of 100 to avoid command line length limits
    for i in range(0, len(unique), 100):
        chunk = unique[i:i+100]
        sid_array = ",".join(f"'{s}'" for s in chunk)
        cmd = f"""
        @({sid_array}) | ForEach-Object {{
            try {{
                $sid = New-Object System.Security.Principal.SecurityIdentifier($_)
                $name = $sid.Translate([System.Security.Principal.NTAccount]).Value
                [PSCustomObject]@{{ SID = $_; Name = $name }}
            }} catch {{
                [PSCustomObject]@{{ SID = $_; Name = $_ }}
            }}
        }} | ConvertTo-Json -Depth 2
        """
        resolved = ps_json(cmd, timeout=60)
        if resolved:
            for r in resolved:
                # Strip DOMAIN\ prefix
                name = r.get("Name", r.get("SID", ""))
                if "\\" in name:
                    name = name.split("\\")[-1]
                result[r["SID"]] = name
    return result


def collect_sessions(computer_limit: Optional[int] = None, workers: int = 25) -> tuple[list[Finding], dict]:
    """
    Enumerate active sessions on all reachable computers via NetSessionEnum.
    Returns (findings, raw_data) where raw_data maps computer -> [usernames].

    NOISY: Generates SMB traffic to every computer enumerated.
    """
    print("  [NOISY] Enumerating sessions on all computers...")
    print("         This generates significant SMB traffic and is detectable.")

    try:
        from impacket.dcerpc.v5 import transport, srvs
    except ImportError:
        return [Finding("INFO", "Session Enumeration Skipped", "(domain-wide)", "SESSIONS",
                        "impacket not installed — run: pip install impacket")], {}

    computers = get_all_computers(enabled_only=True)
    if computer_limit:
        computers = computers[:computer_limit]
    print(f"         Targeting {len(computers)} active computers (workers={workers}).")

    raw = {}  # host -> [usernames]
    reachable = 0
    unreachable = 0

    def enum_one(comp):
        host = comp.get("DNSHostName") or comp.get("SamAccountName", "").rstrip("$")
        if not host:
            return None, None, "no-hostname"
        try:
            string_binding = f'ncacn_np:{host}[\\pipe\\srvsvc]'
            rpctransport = transport.DCERPCTransportFactory(string_binding)
            rpctransport.set_connect_timeout(5)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(srvs.MSRPC_UUID_SRVS)
            resp = srvs.hNetrSessionEnum(dce, NULL, NULL, 10)
            users = []
            for session in resp['InfoStruct']['SessionInfo']['Level10']['Buffer']:
                user = session['sesi10_username'][:-1] if session['sesi10_username'] else ""
                if user and not user.endswith("$"):  # Skip computer accounts
                    users.append(user.lower())
            dce.disconnect()
            return host, users, None
        except Exception as e:
            err = str(e).lower()
            if "unreachable" in err or "timed out" in err or "refused" in err or "access_denied" in err:
                return host, None, "unreachable"
            return host, None, "error"

    from concurrent.futures import ThreadPoolExecutor, as_completed
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(enum_one, c): c for c in computers}
        completed = 0
        for fut in as_completed(futures):
            host, users, status = fut.result()
            completed += 1
            if completed % 50 == 0:
                print(f"         Progress: {completed}/{len(computers)}")
            if status == "unreachable":
                unreachable += 1
            elif users is not None:
                reachable += 1
                raw[host] = users

    print(f"         Reachable: {reachable}, Unreachable/Denied: {unreachable}")
    return [], dict(raw)  # Sessions don't generate findings directly — used for path correlation


def cross_tier_session_correlation(sessions: dict, local_admins: dict,
                                   privileged_sams: set[str]) -> list[Finding]:
    """
    Find cases where a privileged user has an active session on a host
    where a less-privileged user is also a local admin.

    This is the marquee BloodHound finding.
    """
    if not sessions or not local_admins:
        return []
    print("  [*] Correlating sessions with local admin data...")

    findings = []
    for host, users_logged_in in sessions.items():
        if host not in local_admins:
            continue
        admins_on_host = set(a.lower() for a in local_admins[host])
        priv_users_logged_in = [u for u in users_logged_in if u.lower() in privileged_sams]
        if not priv_users_logged_in:
            continue
        # Non-privileged local admins on this host pose risk to logged-in priv users
        non_priv_admins = [a for a in admins_on_host if a not in privileged_sams
                          and a not in ("administrator", "domain admins", "enterprise admins")]
        if non_priv_admins:
            for priv_user in priv_users_logged_in:
                findings.append(Finding(
                    severity="HIGH", category="Cross-Tier Session Exposure",
                    account=priv_user, sam=priv_user,
                    detail=f"Privileged user logged in on {host} where non-priv local admins exist: " +
                           ", ".join(non_priv_admins[:5]) + (f" (+{len(non_priv_admins)-5})" if len(non_priv_admins) > 5 else ""),
                    inheritance_path=host
                ))
    return findings


# ----- Full ACL crawl with abuse pattern detection -----

# Dangerous ACE rights and the GUIDs that matter
DANGEROUS_RIGHTS = {
    "GenericAll": "Full control",
    "GenericWrite": "Can write all properties (set SPN, etc.)",
    "WriteDacl": "Can modify ACL and grant self any rights",
    "WriteOwner": "Can take ownership and grant rights",
    "AllExtendedRights": "Can perform extended rights including ForceChangePassword",
}
DANGEROUS_OBJECT_TYPES = {
    "00299570-246d-11d0-a768-00aa006e0529": ("ForceChangePassword",
                                              "Can reset target's password without knowing it"),
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": ("DS-Replication-Get-Changes",
                                              "DCSync — can replicate password hashes"),
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": ("DS-Replication-Get-Changes-All",
                                              "DCSync — can replicate password hashes"),
    "f3a64788-5306-11d1-a9c5-0000f80367c1": ("Validated-SPN-Write",
                                              "Can write SPN — enables Kerberoasting"),
}
DEFAULT_PRINCIPALS = {
    "domain admins", "enterprise admins", "schema admins", "administrators",
    "system", "self", "principal self", "creator owner", "account operators",
    "server operators", "print operators", "backup operators",
    "enterprise domain controllers", "domain controllers", "read-only domain controllers",
    "cert publishers", "key admins", "enterprise key admins", "protected users",
}


def collect_full_acl(privileged_sams: set[str]) -> tuple[list[Finding], dict]:
    """
    Crawl ACLs across the entire directory, identify abusable ACEs.
    Returns (findings, raw_aces) where raw_aces maps target_dn -> [(principal, right)].

    NOISY: Heavy LDAP query load on domain controllers.
    """
    print("  [NOISY] Crawling ACLs on all directory objects...")
    print("         This is heavy on DC LDAP load and can take 10+ minutes.")

    cmd = """
    $domain = (Get-ADDomain).DistinguishedName
    Get-ADObject -SearchBase $domain -LDAPFilter '(|(objectClass=user)(objectClass=group)(objectClass=computer))' `
        -Properties nTSecurityDescriptor, objectClass, sAMAccountName |
    ForEach-Object {
        $obj = $_
        $sd = $obj.nTSecurityDescriptor
        if ($sd -and $sd.Access) {
            foreach ($ace in $sd.Access) {
                if ($ace.AccessControlType -ne 'Allow') { continue }
                if ($ace.IsInherited) { continue }
                $rights = $ace.ActiveDirectoryRights.ToString()
                # Filter: only emit ACEs with dangerous rights
                if ($rights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty|AllExtendedRights|ExtendedRight') {
                    [PSCustomObject]@{
                        TargetDN = $obj.DistinguishedName
                        TargetName = $obj.sAMAccountName
                        TargetClass = $obj.objectClass
                        Principal = $ace.IdentityReference.Value
                        Rights = $rights
                        ObjectType = $ace.ObjectType.ToString()
                    }
                }
            }
        }
    } | ConvertTo-Json -Depth 3 -Compress
    """
    results = ps_json(cmd, timeout=900)  # 15 min timeout
    if not results:
        return [], {}

    print(f"         Collected {len(results)} non-inherited dangerous ACEs.")

    findings = []
    raw_aces = defaultdict(list)
    seen_findings = set()

    for ace in results:
        principal = ace.get("Principal", "")
        principal_short = principal.split("\\")[-1].lower() if "\\" in principal else principal.lower()
        if principal_short in DEFAULT_PRINCIPALS:
            continue  # Skip default principals — these are expected

        target_name = ace.get("TargetName") or ace.get("TargetDN", "")
        target_class = ace.get("TargetClass", "?")
        rights = ace.get("Rights", "")
        obj_type = ace.get("ObjectType", "")

        raw_aces[target_name].append((principal_short, rights))

        # Determine severity based on target privilege
        target_is_priv = target_name.lower() in privileged_sams
        principal_is_priv = principal_short in privileged_sams

        # Skip if both are already privileged (likely intentional)
        if principal_is_priv and target_is_priv:
            continue

        # Identify specific dangerous right type
        right_label = None
        right_desc = None
        sev = "MEDIUM"

        if "GenericAll" in rights:
            right_label, right_desc, sev = "GenericAll", DANGEROUS_RIGHTS["GenericAll"], "HIGH"
        elif "WriteDacl" in rights:
            right_label, right_desc, sev = "WriteDacl", DANGEROUS_RIGHTS["WriteDacl"], "HIGH"
        elif "WriteOwner" in rights:
            right_label, right_desc, sev = "WriteOwner", DANGEROUS_RIGHTS["WriteOwner"], "HIGH"
        elif "GenericWrite" in rights:
            right_label, right_desc, sev = "GenericWrite", DANGEROUS_RIGHTS["GenericWrite"], "MEDIUM"
        elif "ExtendedRight" in rights or "AllExtendedRights" in rights:
            # Check the ObjectType for specific extended rights
            for guid, (label, desc) in DANGEROUS_OBJECT_TYPES.items():
                if guid in obj_type:
                    right_label, right_desc, sev = label, desc, "HIGH"
                    break
            if not right_label:
                right_label, right_desc = "ExtendedRight", "Extended right granted"

        if not right_label:
            continue

        if target_is_priv:
            sev = "CRITICAL"

        # Dedupe: only one finding per (principal, right_type, target)
        key = (principal_short, right_label, target_name)
        if key in seen_findings:
            continue
        seen_findings.add(key)

        findings.append(Finding(
            severity=sev,
            category=f"ACL Abuse: {right_label}",
            account=principal_short, sam=principal_short,
            detail=f"Has {right_label} on {target_class} '{target_name}' — {right_desc}" +
                   (". Target is PRIVILEGED account." if target_is_priv else ""),
            inheritance_path=f"→ {target_name}"
        ))

    return findings, dict(raw_aces)


# ----- Multi-hop attack path computation -----

# Edge type severity weights — higher = more dangerous
EDGE_SEVERITY = {
    "MemberOf": 1,
    "AdminTo": 3,
    "HasSession": 2,
    "GenericAll": 5,
    "WriteDacl": 5,
    "WriteOwner": 4,
    "GenericWrite": 3,
    "ForceChangePassword": 4,
    "AbuseACE": 2,
    "Kerberoast": 3,          # "can crack" edge — requires weak password
    "KerberoastRC4": 4,       # weak encryption, much faster to crack
    "ASREPRoast": 4,
    "UnconstrainedDelegation": 5,  # captures TGT of authenticating user
    "ConstrainedDelegation": 4,
    "DCSync": 5,
    "Enroll": 3,              # ADCS enroll right
    "AuthenticateAs": 5,      # ESC1 — cert can auth as anyone
    "TrustedBy": 2,
    "PasswordNotRequired": 5, # can authenticate with empty password
}

# Starting principals that represent "any authenticated user"
ANY_USER_SOURCES = {"authenticated users", "domain users", "everyone", "users"}


def _path_to_string(G, path):
    """Render a graph path as a human-readable string with edge labels."""
    parts = [path[0]]
    for i in range(len(path) - 1):
        edge = G.edges[path[i], path[i+1]].get("edge", "→")
        parts.append(f"--[{edge}]→ {path[i+1]}")
    return " ".join(parts)


def _score_path(G, path, privileged_sams):
    """
    Composite path score. Lower = more dangerous / higher priority to report.

    Factors (lower is worse):
    - hop count (fewer hops = more dangerous)
    - starting from broad principal ("any user") = more dangerous → subtract
    - ending at Tier 0 vs other privileged = more dangerous → subtract
    - edge types with higher severity = more dangerous → subtract sum
    """
    hops = len(path) - 1
    start = path[0]
    end = path[-1]
    end_type = G.nodes[end].get("type", "?")

    score = hops * 10

    if start in ANY_USER_SOURCES:
        score -= 20
    elif start not in privileged_sams:
        score -= 5  # any non-priv user is still broadly reachable

    if end_type == "tier0":
        score -= 30
    elif end in privileged_sams:
        score -= 10

    # Edge severity contributes
    for i in range(len(path) - 1):
        edge = G.edges[path[i], path[i+1]].get("edge", "")
        score -= EDGE_SEVERITY.get(edge, 1)

    return score


def _build_attack_graph(trees, acl_data, local_admins, session_data, findings,
                        privileged_sams):
    """
    Build a comprehensive attack graph from all available collected data and findings.

    Returns a networkx DiGraph with nodes representing AD objects/concepts
    and edges representing attack primitives.
    """
    import networkx as nx
    G = nx.DiGraph()

    # Sentinel node representing "any authenticated user" — starting point for many attacks
    G.add_node("authenticated users", type="meta")

    # 1. Group membership edges from enumeration trees
    def walk_tree(node, root_name):
        for member in node.direct_members:
            sam = member.sam_account_name.lower()
            G.add_node(sam, type="user")
            G.add_node(node.name.lower(), type="group")
            G.add_edge(sam, node.name.lower(), edge="MemberOf")
        for child in node.child_groups:
            G.add_node(child.name.lower(), type="group")
            G.add_edge(child.name.lower(), node.name.lower(), edge="MemberOf")
            walk_tree(child, root_name)

    for root_name, tree in trees.items():
        G.add_node(root_name.lower(), type="tier0")
        walk_tree(tree, root_name)

    # 2. ACL abuse edges
    if acl_data:
        for target_name, aces in acl_data.items():
            target = target_name.lower()
            if target not in G:
                G.add_node(target, type="object")
            for principal, rights in aces:
                if principal not in G:
                    G.add_node(principal, type="user")
                if "GenericAll" in rights:
                    edge = "GenericAll"
                elif "WriteDacl" in rights:
                    edge = "WriteDacl"
                elif "WriteOwner" in rights:
                    edge = "WriteOwner"
                elif "GenericWrite" in rights:
                    edge = "GenericWrite"
                elif "ForceChangePassword" in rights:
                    edge = "ForceChangePassword"
                else:
                    edge = "AbuseACE"
                G.add_edge(principal, target, edge=edge)

    # 3. Local admin edges (principal → host)
    if local_admins:
        for host, admin_sids in local_admins.items():
            host_node = host.lower()
            G.add_node(host_node, type="computer")
            for sid_or_sam in admin_sids:
                principal = sid_or_sam.lower().split("\\")[-1]
                if principal not in G:
                    G.add_node(principal, type="user")
                G.add_edge(principal, host_node, edge="AdminTo")

    # 4. Session edges (host → user logged in)
    # Edge direction is host → user because compromising host captures user's creds
    if session_data:
        for host, users in session_data.items():
            host_node = host.lower()
            if host_node not in G:
                G.add_node(host_node, type="computer")
            for user in users:
                u = user.lower()
                if u not in G:
                    G.add_node(u, type="user")
                G.add_edge(host_node, u, edge="HasSession")

    # 5. Edges derived from flat findings (attack surface module output)
    for f in findings:
        sam = f.sam.lower() if f.sam else ""
        if not sam:
            continue
        cat = f.category

        # Kerberoastable: any auth user can attempt to crack this account
        if cat.startswith("Kerberoastable"):
            if sam not in G:
                G.add_node(sam, type="user")
            # Infer weak encryption from detail text
            is_rc4 = "weak encryption" in f.detail.lower() or "rc4" in f.detail.lower()
            edge = "KerberoastRC4" if is_rc4 else "Kerberoast"
            G.add_edge("authenticated users", sam, edge=edge)

        # AS-REP roastable: any unauthenticated user can request hash
        elif cat == "AS-REP Roastable":
            if sam not in G:
                G.add_node(sam, type="user")
            G.add_edge("authenticated users", sam, edge="ASREPRoast")

        # Unconstrained delegation: if host is compromised, captures any user that authenticates there
        elif "Unconstrained Delegation" in cat:
            host = sam.rstrip("$").lower()
            if host not in G:
                G.add_node(host, type="computer")
            # Edge from "compromise host" to any privileged user who might auth (we approximate)
            # The actual auth capture happens via sessions — the session edges cover this
            # But we also want to mark the host itself as dangerous
            G.nodes[host]["unconstrained"] = True

        # Password Not Required: anyone can authenticate as this account with empty password
        elif cat == "Password Not Required":
            if sam not in G:
                G.add_node(sam, type="user")
            G.add_edge("authenticated users", sam, edge="PasswordNotRequired")

        # Local Admin Sprawl: flag the user as having wide admin reach
        elif cat == "Local Admin Sprawl":
            if sam not in G:
                G.add_node(sam, type="user")
            G.nodes[sam]["local_admin_sprawl"] = True

        # ADCS template findings
        elif cat == "ADCS ESC1":
            # Template can be used to authenticate as anyone
            tmpl = sam.lower()
            if tmpl not in G:
                G.add_node(tmpl, type="adcs_template")
            # Any Tier 0 node becomes reachable via ESC1
            for n, attrs in list(G.nodes(data=True)):
                if attrs.get("type") == "tier0":
                    G.add_edge(tmpl, n, edge="AuthenticateAs")

        # DCSync rights (from discovery method acl_dcsync)
        elif "DCSync" in cat or "Repl-Changes" in f.detail:
            if sam not in G:
                G.add_node(sam, type="user")
            # DCSync effectively gives you any privileged account
            for n, attrs in list(G.nodes(data=True)):
                if attrs.get("type") == "tier0":
                    G.add_edge(sam, n, edge="DCSync")

    return G


def _derive_adcs_enroll_edges(G, findings, trees):
    """
    For ADCS ESC1 findings, add enroll edges from authenticated users/groups
    to the template. Without explicit enroll data, we conservatively assume
    Authenticated Users can enroll (common default that makes ESC1 exploitable).
    """
    esc1_templates = [f.sam.lower() for f in findings if f.category == "ADCS ESC1"]
    for tmpl in esc1_templates:
        if tmpl not in G:
            continue
        # Conservative: authenticated users can enroll
        G.add_edge("authenticated users", tmpl, edge="Enroll")


def compute_attack_paths(trees, acl_data, local_admins, privileged_sams,
                        session_data=None, findings=None,
                        max_hops: int = 5, max_paths: int = 100) -> list[Finding]:
    """
    Build a comprehensive attack graph and compute multi-hop paths to privileged targets.

    Args:
        trees: Group enumeration trees
        acl_data: dict of target -> [(principal, rights)] from full ACL crawl
        local_admins: dict of host -> [admin SIDs/SAMs]
        privileged_sams: set of lowercase SAMs in privileged groups
        session_data: dict of host -> [logged-in users]
        findings: list of all findings to derive graph edges from
        max_hops: maximum path length to consider
        max_paths: maximum number of paths to return (top N by severity score)
    """
    try:
        import networkx as nx
    except ImportError:
        return [Finding("INFO", "Path Computation Skipped", "(domain-wide)", "PATHS",
                        "networkx not installed — run: pip install networkx")]

    print(f"  [*] Building attack graph (max_hops={max_hops}, max_paths={max_paths})...")
    G = _build_attack_graph(trees, acl_data or {}, local_admins or {},
                            session_data or {}, findings or [], privileged_sams)
    _derive_adcs_enroll_edges(G, findings or [], trees)

    print(f"         Graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges.")

    # Identify target nodes: Tier 0 plus any privileged account
    tier0_nodes = [n for n, attrs in G.nodes(data=True) if attrs.get("type") == "tier0"]
    priv_user_nodes = [n for n in G.nodes() if n in privileged_sams]
    target_nodes = list(set(tier0_nodes + priv_user_nodes))

    if not target_nodes:
        print("         No target nodes identified.")
        return []

    # Source nodes: non-privileged users + any broad principal
    source_nodes = [n for n, attrs in G.nodes(data=True)
                    if (attrs.get("type") in ("user", "meta", "computer"))
                    and n not in privileged_sams
                    and n not in tier0_nodes]

    # Collect candidate paths with scoring
    # Use BFS with cutoff rather than shortest_path to avoid missing longer-but-more-severe paths
    candidate_paths = []
    seen_suffixes = {}  # Dedup: map path suffix (last 3 nodes) -> representative path

    for source in source_nodes:
        if source not in G:
            continue
        # For each target, find paths up to max_hops
        for target in target_nodes:
            if source == target:
                continue
            try:
                # all_simple_paths enumerates ALL simple paths — can be expensive
                # We cap by converting to iterator and breaking after N paths per source
                paths_iter = nx.all_simple_paths(G, source=source, target=target, cutoff=max_hops)
                paths_from_source = 0
                for path in paths_iter:
                    if len(path) < 3:
                        continue  # Direct membership — already captured elsewhere
                    # Dedupe by path suffix (last 3 nodes tend to identify the "interesting" part)
                    suffix = tuple(path[-3:])
                    score = _score_path(G, path, privileged_sams)
                    if suffix in seen_suffixes:
                        existing_score, existing_idx = seen_suffixes[suffix]
                        if score < existing_score:
                            # New path is more dangerous — replace
                            seen_suffixes[suffix] = (score, len(candidate_paths))
                            candidate_paths.append((score, path, source, target))
                    else:
                        seen_suffixes[suffix] = (score, len(candidate_paths))
                        candidate_paths.append((score, path, source, target))
                    paths_from_source += 1
                    if paths_from_source >= 5:
                        break  # cap paths per source-target to prevent explosion
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue

    # Sort by score (lower = more dangerous) and take top N
    candidate_paths.sort(key=lambda t: t[0])
    selected = candidate_paths[:max_paths]

    # Build findings
    findings_out = []
    suffix_dedupe_count = defaultdict(int)
    for score, path, source, target in selected:
        suffix_dedupe_count[tuple(path[-3:])] += 1

    # Count how many sources share each suffix for the "N users reach X via" summary
    suffix_source_count = defaultdict(set)
    for _, path, _, _ in candidate_paths:
        suffix_source_count[tuple(path[-3:])].add(path[0])

    for score, path, source, target in selected:
        hops = len(path) - 1
        path_str = _path_to_string(G, path)

        # Collect unique edge types in this path for labeling
        edges_in_path = set()
        for i in range(len(path) - 1):
            edges_in_path.add(G.edges[path[i], path[i+1]].get("edge", "?"))

        # Severity based on composite factors
        end_type = G.nodes[target].get("type", "")
        if end_type == "tier0" and hops <= 3:
            sev = "CRITICAL"
        elif end_type == "tier0" and hops <= 5:
            sev = "HIGH"
        elif end_type == "tier0":
            sev = "MEDIUM"
        elif hops <= 3:
            sev = "HIGH"
        else:
            sev = "MEDIUM"

        # Escalate if path starts from "any user" source
        if source in ANY_USER_SOURCES and end_type == "tier0":
            sev = "CRITICAL"

        # Compose detail
        suffix_key = tuple(path[-3:])
        shared_sources = len(suffix_source_count[suffix_key])
        shared_note = f" (tail shared by {shared_sources} sources)" if shared_sources > 1 else ""

        detail = f"Reaches {target} in {hops} hops via [{', '.join(sorted(edges_in_path))}]{shared_note}"

        findings_out.append(Finding(
            severity=sev,
            category=f"Attack Path ({hops} hops)",
            account=source, sam=source, detail=detail,
            inheritance_path=path_str
        ))

    print(f"         Evaluated {len(candidate_paths)} candidate paths, reporting top {len(findings_out)}.")
    return findings_out


# ----- Pairwise finding correlation (no networkx required) -----

def correlate_findings(findings, trees, acl_data=None, local_admins=None,
                       session_data=None) -> list[Finding]:
    """
    Identify cross-finding attack chains by looking for shared elements
    between independent findings. Produces new CRITICAL "Correlated Chain"
    findings that capture pairwise attack scenarios.

    This runs with whatever data is available — no network calls, no new collection.
    """
    print("\n[*] Correlating findings for attack chains...")
    correlated = []

    # Index findings by category for quick lookup
    by_cat = defaultdict(list)
    by_sam = defaultdict(list)
    for f in findings:
        by_cat[f.category].append(f)
        by_sam[f.sam.lower()].append(f)

    # Build quick-lookup sets
    kerberoastable = [f for f in findings if f.category.startswith("Kerberoastable")]
    asrep_roastable = by_cat.get("AS-REP Roastable", [])
    unconstrained_computers = [f for f in findings if "Unconstrained Delegation (Computer)" in f.category]
    adcs_esc1 = by_cat.get("ADCS ESC1", [])
    adcs_esc2 = by_cat.get("ADCS ESC2", [])
    password_not_req = by_cat.get("Password Not Required", [])
    local_admin_sprawl = by_cat.get("Local Admin Sprawl", [])
    acl_abuse_cats = [c for c in by_cat.keys() if c.startswith("ACL Abuse:")]

    # Correlation 1: Kerberoastable account with ACL abuse rights
    for kf in kerberoastable:
        for cat in acl_abuse_cats:
            for af in by_cat[cat]:
                if af.sam.lower() == kf.sam.lower():
                    right_type = cat.replace("ACL Abuse: ", "")
                    # Extract target from ACL finding detail
                    correlated.append(Finding(
                        severity="CRITICAL",
                        category="Correlated Chain: Kerberoast → ACL Abuse",
                        account=kf.account, sam=kf.sam,
                        detail=f"Any auth user can Kerberoast this account, then abuse its {right_type} rights. " + af.detail,
                        inheritance_path=f"Auth User → [Kerberoast] → {kf.sam} → [{right_type}] → target"
                    ))

    # Correlation 2: Kerberoastable + ADCS ESC1 (assumes auth users can enroll — most common case)
    if adcs_esc1:
        for kf in kerberoastable:
            for esc1 in adcs_esc1:
                correlated.append(Finding(
                    severity="CRITICAL",
                    category="Correlated Chain: Kerberoast → ESC1",
                    account=kf.account, sam=kf.sam,
                    detail=f"Kerberoasting {kf.sam} yields an account that can enroll in ESC1-vulnerable template "
                           f"'{esc1.sam}', allowing authentication as any user including Domain Admins.",
                    inheritance_path=f"Auth User → [Kerberoast] → {kf.sam} → [Enroll] → {esc1.sam} → [AuthenticateAs] → Domain Admins"
                ))

    # Correlation 3: AS-REP roastable + ACL abuse
    for af in asrep_roastable:
        for cat in acl_abuse_cats:
            for acl_f in by_cat[cat]:
                if acl_f.sam.lower() == af.sam.lower():
                    right_type = cat.replace("ACL Abuse: ", "")
                    correlated.append(Finding(
                        severity="CRITICAL",
                        category="Correlated Chain: AS-REP → ACL Abuse",
                        account=af.account, sam=af.sam,
                        detail=f"AS-REP roastable account has {right_type}. " + acl_f.detail,
                        inheritance_path=f"Anyone → [AS-REP] → {af.sam} → [{right_type}] → target"
                    ))

    # Correlation 4: Password Not Required + privileged membership
    privileged_sams = get_privileged_sams(trees)
    for pf in password_not_req:
        if pf.sam.lower() in privileged_sams:
            correlated.append(Finding(
                severity="CRITICAL",
                category="Correlated Chain: Empty Password on Priv Account",
                account=pf.account, sam=pf.sam,
                detail=f"Privileged account can authenticate with empty password — trivial compromise.",
                inheritance_path=f"Anyone → [empty password] → {pf.sam} → [MemberOf] → privileged group"
            ))

    # Correlation 5: Unconstrained delegation computer + privileged session (if session data available)
    if session_data and unconstrained_computers:
        for uf in unconstrained_computers:
            host = uf.sam.lower().rstrip("$")
            # Check if any privileged user has a session on this host
            for session_host, users in session_data.items():
                if session_host.lower() == host or session_host.lower().startswith(host + "."):
                    priv_users = [u for u in users if u.lower() in privileged_sams]
                    if priv_users:
                        correlated.append(Finding(
                            severity="CRITICAL",
                            category="Correlated Chain: Unconstrained Delegation + Priv Session",
                            account=uf.account, sam=uf.sam,
                            detail=f"Host has unconstrained delegation AND privileged user(s) "
                                   f"with active sessions: {', '.join(priv_users[:3])}. "
                                   f"Compromise of host captures TGTs for these users.",
                            inheritance_path=f"Compromise {host} → [UnconstrainedDelegation] → capture TGT → {priv_users[0]}"
                        ))

    # Correlation 6: Local admin sprawl + privileged session on same host
    if local_admins and session_data and local_admin_sprawl:
        sprawl_users = {f.sam.lower() for f in local_admin_sprawl}
        for host, users in session_data.items():
            priv_logged_in = [u for u in users if u.lower() in privileged_sams]
            if not priv_logged_in:
                continue
            admins_on_host = {a.lower().split("\\")[-1] for a in local_admins.get(host, [])}
            sprawl_admins = admins_on_host & sprawl_users
            if sprawl_admins:
                for priv_user in priv_logged_in:
                    correlated.append(Finding(
                        severity="HIGH",
                        category="Correlated Chain: Sprawled Admin + Priv Session",
                        account=priv_user, sam=priv_user,
                        detail=f"Privileged user session on {host} where widely-distributed "
                               f"local admin accounts exist: {', '.join(list(sprawl_admins)[:3])}. "
                               f"Compromise of any sprawled admin account → compromise of priv user.",
                        inheritance_path=f"{list(sprawl_admins)[0]} → [AdminTo] → {host} → [HasSession] → {priv_user}"
                    ))

    # Correlation 7: Stale privileged account + ACL abuse on the same account
    disabled_priv = [f for f in findings if f.category == "Disabled Account"]
    stale_priv = [f for f in findings if f.category == "Stale Logon"]
    dormant_sams = {f.sam.lower() for f in disabled_priv + stale_priv}
    for cat in acl_abuse_cats:
        for acl_f in by_cat[cat]:
            # Target extraction is approximate — detail format is "Has X on class 'target'"
            detail = acl_f.detail.lower()
            for dormant in dormant_sams:
                if f"'{dormant}'" in detail:
                    right_type = cat.replace("ACL Abuse: ", "")
                    correlated.append(Finding(
                        severity="HIGH",
                        category="Correlated Chain: ACL on Dormant Priv Account",
                        account=acl_f.account, sam=acl_f.sam,
                        detail=f"{acl_f.sam} has {right_type} on dormant/disabled privileged account {dormant}. "
                               f"Re-enabling or password reset via ACL restores full privilege.",
                        inheritance_path=f"{acl_f.sam} → [{right_type}] → {dormant} → re-enable → priv access"
                    ))

    # Deduplicate
    seen = set()
    unique = []
    for f in correlated:
        key = (f.category, f.sam, f.inheritance_path)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    print(f"         Produced {len(unique)} correlated chain finding(s).")
    return unique


def run_noisy_modules(trees: dict, privileged_sams: set[str],
                      do_local_admin: bool, do_sessions: bool,
                      do_full_acl: bool, do_paths: bool,
                      computer_limit: Optional[int] = None,
                      workers: int = 25,
                      max_hops: int = 5, max_paths: int = 100,
                      existing_findings: Optional[list] = None) -> tuple[list[Finding], dict]:
    """
    Orchestrate the noisy modules and cross-correlation.

    Returns (findings, collected_data) where collected_data has:
      - local_admin_data: dict
      - session_data: dict
      - acl_data: dict
    Used by downstream correlators.
    """
    findings = []
    local_admin_data = {}
    session_data = {}
    acl_data = {}

    if do_local_admin:
        print("\n[*] === LOCAL ADMIN MAPPING (NOISY) ===")
        la_findings, local_admin_data = collect_local_admins(privileged_sams, computer_limit, workers)
        findings.extend(la_findings)

    if do_sessions:
        print("\n[*] === SESSION ENUMERATION (VERY NOISY) ===")
        sess_findings, session_data = collect_sessions(computer_limit, workers)
        findings.extend(sess_findings)

    if do_local_admin and do_sessions:
        findings.extend(cross_tier_session_correlation(session_data, local_admin_data, privileged_sams))

    if do_full_acl:
        print("\n[*] === FULL ACL CRAWL (HEAVY) ===")
        acl_findings, acl_data = collect_full_acl(privileged_sams)
        findings.extend(acl_findings)

    if do_paths:
        print("\n[*] === MULTI-HOP ATTACK PATH COMPUTATION ===")
        # Feed all prior findings (including attack surface from main) into path graph
        all_findings_for_paths = (existing_findings or []) + findings
        path_findings = compute_attack_paths(
            trees, acl_data, local_admin_data, privileged_sams,
            session_data=session_data, findings=all_findings_for_paths,
            max_hops=max_hops, max_paths=max_paths
        )
        findings.extend(path_findings)

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: sev_order.get(f.severity, 5))
    print(f"\n  [{len(findings)} findings from noisy modules]")

    collected = {
        "local_admin_data": local_admin_data,
        "session_data": session_data,
        "acl_data": acl_data,
    }
    return findings, collected


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
# D3.js Offline Embedding
# ============================================================================

_d3_inline: Optional[str] = None

def load_d3_js() -> str:
    """Load D3.js for embedding. Tries local file first, falls back to CDN tag."""
    global _d3_inline
    if _d3_inline is not None:
        return _d3_inline

    # Look for d3.min.js next to this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(script_dir, "d3.min.js"),
        os.path.join(script_dir, "d3.v7.min.js"),
        os.path.join(script_dir, "node_modules", "d3", "dist", "d3.min.js"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                if len(content) > 10000:  # Sanity check — D3 is ~280KB
                    _d3_inline = f"<script>\n/* D3.js v7 (embedded for offline use) */\n{content}\n</script>"
                    print(f"  [+] D3.js embedded from: {path}")
                    return _d3_inline
            except Exception as e:
                print(f"  [!] Could not read {path}: {e}", file=sys.stderr)

    # Fallback to CDN
    _d3_inline = '<script src="https://d3js.org/d3.v7.min.js"></script>'
    print("  [*] D3.js: using CDN (place d3.min.js next to script for offline use)")
    return _d3_inline


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
            "name": m.sam_account_name, "display_name": m.display_name or m.name,
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
                "sam": acct.sam_account_name,
                "name": acct.display_name or acct.name,
                "root_group": root_name,
                "path": path, "enabled": acct.enabled, "last_logon": acct.last_logon or "",
                "pw_last_set": acct.password_last_set or "",
                "pw_never_expires": acct.password_never_expires,
                "admin_count": acct.admin_count, "description": acct.description or "",
                "object_class": acct.object_class,
                "smartcard": acct.smartcard_required,
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
    <table id="accounts-table"><thead><tr><th>SAM Account</th><th>Display Name</th><th>Status</th><th>Smart Card</th><th>Priv Group</th><th>Last Logon</th><th>PW Expires</th><th>Path</th></tr></thead><tbody></tbody></table>
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
D3_SCRIPT_PLACEHOLDER
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
  if (!data.length) { tbody.innerHTML = '<tr><td colspan="8" class="no-results">No accounts match</td></tr>'; return; }
  tbody.innerHTML = data.map(a => {
    const sc = a.enabled === true ? 'status-enabled' : a.enabled === false ? 'status-disabled' : '';
    const st = a.enabled === true ? 'Enabled' : a.enabled === false ? 'Disabled' : '\u2014';
    const ll = a.last_logon ? a.last_logon.substring(0,10) : '\u2014';
    const pw = a.pw_never_expires ? '<span style="color:var(--medium)">Never</span>' : 'Yes';
    const smc = a.smartcard ? '<span style="color:var(--node-user)">Yes</span>' : 'No';
    return `<tr><td>${a.sam}</td><td>${a.name}</td><td class="${sc}">${st}</td><td>${smc}</td><td>${a.root_group}</td><td>${ll}</td><td>${pw}</td><td class="path-text">${a.path}</td></tr>`;
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
    js_code = js_code.replace("D3_SCRIPT_PLACEHOLDER", load_d3_js())
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

def generate_demo_attack_findings() -> list[Finding]:
    """Sample attack surface findings for demo mode."""
    return [
        Finding("CRITICAL", "Kerberoastable (Privileged)", "Henry Nakamura (h.dba)", "h.dba",
                "Privileged Kerberoastable account. SPN(s): MSSQLSvc/sql01.example.local:1433. Weak encryption (RC4 fallback) — fast offline cracking possible."),
        Finding("CRITICAL", "Unconstrained Delegation (Computer)", "legacy-app01.example.local", "legacy-app01$",
                "Computer has unconstrained delegation. OS: Windows Server 2012 R2. Compromise allows TGT capture for any user that authenticates to this host."),
        Finding("CRITICAL", "ADCS ESC1", "User Auth Template", "UserAuthTemplate",
                "Template 'UserAuthTemplate' allows enrollee-supplied subject + client auth EKU with no manager approval. Any enrollee can request a cert as any user including Domain Admins."),
        Finding("CRITICAL", "Password Not Required", "svc.legacy (svc.legacy)", "svc.legacy",
                "PASSWD_NOTREQD flag set — account can have empty password. PRIVILEGED ACCOUNT."),
        Finding("HIGH", "AS-REP Roastable", "Brian Sullivan (b.sullivan)", "b.sullivan",
                "DONT_REQ_PREAUTH set — Kerberos AS-REP can be requested without authentication and cracked offline"),
        Finding("HIGH", "Constrained Delegation w/ Protocol Transition", "Svc Web Pool (svc.webpool)", "svc.webpool",
                "Can delegate to HTTP/web01.example.local, HTTP/web02.example.local via 'Use any authentication protocol' — S4U2Self abuse possible"),
        Finding("HIGH", "Trust SID Filtering Disabled", "legacy.local", "legacy.local",
                "Bidirectional trust to legacy.local has SID filtering disabled — SID history injection possible"),
        Finding("HIGH", "ADCS ESC2", "Subordinate CA", "SubCA",
                "Template 'SubCA' has Any Purpose EKU with no manager approval. Cert usable for any purpose."),
        Finding("HIGH", "LAPS Not Deployed", "(domain-wide)", "LAPS",
                "No computers have LAPS configured (0 / 412). Local admin password reuse risk across the domain."),
        Finding("MEDIUM", "Resource-Based Constrained Delegation", "fileserver02.example.local", "fileserver02$",
                "Computer has RBCD configured — review msDS-AllowedToActOnBehalfOfOtherIdentity. Abuse possible if attacker controls a listed principal."),
        Finding("MEDIUM", "Inactive Computer Account", "old-laptop-42.example.local", "old-laptop-42$",
                "Computer enabled but inactive for 287 days. OS: Windows 10 Enterprise"),
        Finding("MEDIUM", "ADCS Enrollment Service Present", "ca01.example.local", "EXAMPLE-CA",
                "Certificate Authority 'EXAMPLE-CA' on ca01.example.local. Manually verify web enrollment is disabled or HTTPS-only with EPA, and that RPC enrollment requires signing (mitigates ESC8/ESC11)."),
        Finding("LOW", "Kerberoastable", "Svc Backup Agent (svc.backup)", "svc.backup",
                "Service account with SPN(s): backup/backup-server.example.local."),
        Finding("INFO", "Domain Trust", "partner.example.org", "partner.example.org",
                "Outbound trust. Type: External. Forest transitive: False. Selective auth: True."),
        # Local admin sprawl
        Finding("CRITICAL", "Local Admin Sprawl", "j.helpdesk", "j.helpdesk",
                "Local Administrator on 287 computers"),
        Finding("HIGH", "Local Admin Sprawl", "svc.deploy", "svc.deploy",
                "Local Administrator on 156 computers"),
        Finding("MEDIUM", "Local Admin Sprawl", "h.dba", "h.dba",
                "Privileged AD account is local admin on 23 computers"),
        Finding("LOW", "Non-Default Local Admin", "k.contractor", "k.contractor",
                "Member of local Administrators on srv-fileshare01.example.local",
                "srv-fileshare01.example.local"),
        # Cross-tier session exposure
        Finding("HIGH", "Cross-Tier Session Exposure", "admin.primary", "admin.primary",
                "Privileged user logged in on ws-helpdesk-12.example.local where non-priv local admins exist: j.helpdesk, m.intern",
                "ws-helpdesk-12.example.local"),
        # ACL abuse
        Finding("CRITICAL", "ACL Abuse: GenericAll", "k.contractor", "k.contractor",
                "Has GenericAll on user 'admin.primary' — Full control. Target is PRIVILEGED account.",
                "→ admin.primary"),
        Finding("HIGH", "ACL Abuse: WriteDacl", "j.helpdesk", "j.helpdesk",
                "Has WriteDacl on group 'Server Admins' — Can modify ACL and grant self any rights",
                "→ Server Admins"),
        Finding("HIGH", "ACL Abuse: ForceChangePassword", "support.team", "support.team",
                "Has ForceChangePassword on user 'b.serverguy' — Can reset target's password without knowing it",
                "→ b.serverguy"),
        Finding("MEDIUM", "ACL Abuse: GenericWrite", "p.projectlead", "p.projectlead",
                "Has GenericWrite on user 'svc.sql' — Can write all properties (set SPN, etc.)",
                "→ svc.sql"),
        # Attack paths
        Finding("CRITICAL", "Attack Path (3 hops)", "k.contractor", "k.contractor",
                "Reaches Domain Admins in 3 hops",
                "k.contractor --[GenericAll]→ admin.primary --[MemberOf]→ enterprise admins --[MemberOf]→ domain admins"),
        Finding("HIGH", "Attack Path (4 hops)", "j.helpdesk", "j.helpdesk",
                "Reaches Domain Admins in 4 hops",
                "j.helpdesk --[WriteDacl]→ server admins --[MemberOf]→ helpdesk tier2 --[MemberOf]→ server admins --[MemberOf]→ domain admins"),
        Finding("HIGH", "Attack Path (5 hops)", "support.team", "support.team",
                "Reaches Administrators in 5 hops",
                "support.team --[ForceChangePassword]→ b.serverguy --[AdminTo]→ srv-dc02.example.local --[MemberOf]→ administrators"),
    ]


def main():
    parser = argparse.ArgumentParser(description="AD Privileged Group Discovery & Analysis Tool")
    parser.add_argument("--groups", nargs="+", default=DEFAULT_TIER0_GROUPS)
    parser.add_argument("--discover", action="store_true", help="Auto-discover privileged groups")
    parser.add_argument("--search-user", type=str)
    parser.add_argument("--search-group", type=str)
    parser.add_argument("--output", type=str, default="ad_priv_audit_report.html")
    parser.add_argument("--demo", action="store_true", help="Generate report with mock data")
    parser.add_argument("--attack-surface", action="store_true",
                        help="Run extended attack surface analysis (Kerberoasting, delegation, ADCS, trusts, LAPS, etc.)")
    parser.add_argument("--skip-slow", action="store_true",
                        help="With --attack-surface: skip slow checks (RBCD scan, inactive computers, LAPS coverage)")
    # NOISY modules — explicit opt-in only
    parser.add_argument("--local-admin", action="store_true",
                        help="[NOISY] Enumerate local Administrators on every computer (SMB/RPC traffic to all endpoints)")
    parser.add_argument("--sessions", action="store_true",
                        help="[VERY NOISY] Enumerate active sessions on every computer (SMB traffic, highly detectable)")
    parser.add_argument("--full-acl", action="store_true",
                        help="[HEAVY] Crawl ACLs across entire directory and detect abuse patterns")
    parser.add_argument("--paths", action="store_true",
                        help="Compute multi-hop attack paths (uses local-admin and full-acl data if collected)")
    parser.add_argument("--noisy", action="store_true",
                        help="Enable all noisy modules (--local-admin --sessions --full-acl --paths). Requires confirmation.")
    parser.add_argument("--computer-limit", type=int, default=None,
                        help="Limit endpoint scans to N computers (for testing or scoped runs)")
    parser.add_argument("--workers", type=int, default=25,
                        help="Concurrent worker threads for endpoint enumeration (default 25)")
    parser.add_argument("--yes", action="store_true",
                        help="Skip confirmation prompts for noisy operations")
    # Correlation / pathfinding
    parser.add_argument("--no-correlate", action="store_true",
                        help="Disable pairwise finding correlation (runs by default)")
    parser.add_argument("--max-hops", type=int, default=5,
                        help="Maximum path length for multi-hop attack path analysis (default: 5)")
    parser.add_argument("--max-paths", type=int, default=100,
                        help="Maximum number of attack paths to report (default: 100)")
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
    print(f"  [{len(findings)} privileged group findings]")

    # Optional extended attack surface analysis
    if args.attack_surface and not args.demo:
        privileged_sams = get_privileged_sams(trees)
        # Build authoritative set of known privileged group names:
        # defaults + discovered + every group seen in enumerated trees (incl. nested)
        privileged_groups = set(g.lower() for g in DEFAULT_TIER0_GROUPS)
        for d in discovery_results:
            privileged_groups.add(d.group_name.lower())
        def _collect_group_names(node, acc):
            acc.add(node.name.lower())
            for child in node.child_groups:
                _collect_group_names(child, acc)
        for tree in trees.values():
            _collect_group_names(tree, privileged_groups)

        attack_findings = run_attack_surface_analysis(
            privileged_sams, privileged_groups=privileged_groups, skip_slow=args.skip_slow
        )
        # Merge with deduplication (sam, category)
        seen = set((f.sam, f.category) for f in findings)
        for f in attack_findings:
            if (f.sam, f.category) not in seen:
                findings.append(f)
                seen.add((f.sam, f.category))
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings.sort(key=lambda f: sev_order.get(f.severity, 5))
        print(f"  [{len(findings)} total findings after attack surface merge]")

    # NOISY modules — endpoint/full-ACL/paths
    collected_noisy = {"local_admin_data": {}, "session_data": {}, "acl_data": {}}
    if not args.demo:
        do_la = args.local_admin or args.noisy
        do_se = args.sessions or args.noisy
        do_fa = args.full_acl or args.noisy
        do_pa = args.paths or args.noisy

        if any([do_la, do_se, do_fa, do_pa]):
            # Confirmation prompt
            if not args.yes:
                print("\n" + "=" * 60)
                print("  WARNING: NOISY OPERATIONS REQUESTED")
                print("=" * 60)
                if do_la:
                    print("  - Local admin enumeration: SMB/RPC to every active computer")
                if do_se:
                    print("  - Session enumeration: SMB to every active computer (highly detectable)")
                if do_fa:
                    print("  - Full ACL crawl: heavy LDAP load on domain controllers")
                if do_pa:
                    print("  - Attack path computation: post-processing on collected data")
                print("\n  Coordinate with SOC before proceeding. These activities will")
                print("  generate alerts and resemble adversary tradecraft.")
                response = input("\n  Type 'yes' to proceed: ")
                if response.strip().lower() != "yes":
                    print("  Aborted.")
                    sys.exit(0)

            privileged_sams = get_privileged_sams(trees)
            noisy_findings, collected_noisy = run_noisy_modules(
                trees, privileged_sams,
                do_local_admin=do_la, do_sessions=do_se,
                do_full_acl=do_fa, do_paths=do_pa,
                computer_limit=args.computer_limit, workers=args.workers,
                max_hops=args.max_hops, max_paths=args.max_paths,
                existing_findings=findings
            )
            seen = set((f.sam, f.category) for f in findings)
            for f in noisy_findings:
                if (f.sam, f.category) not in seen:
                    findings.append(f)
                    seen.add((f.sam, f.category))
            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            findings.sort(key=lambda f: sev_order.get(f.severity, 5))
            print(f"  [{len(findings)} total findings after noisy module merge]")

    elif args.demo:
        # Inject demo attack surface findings for visualization
        findings.extend(generate_demo_attack_findings())
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings.sort(key=lambda f: sev_order.get(f.severity, 5))
        print(f"  [{len(findings)} total findings (demo includes attack surface samples)]")

    # --- Finding correlation (runs by default on both non-noisy and noisy data) ---
    if not args.no_correlate:
        correlated = correlate_findings(
            findings, trees,
            acl_data=collected_noisy.get("acl_data"),
            local_admins=collected_noisy.get("local_admin_data"),
            session_data=collected_noisy.get("session_data"),
        )
        seen = set((f.category, f.sam, f.inheritance_path) for f in findings)
        for f in correlated:
            key = (f.category, f.sam, f.inheritance_path)
            if key not in seen:
                findings.append(f)
                seen.add(key)
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings.sort(key=lambda f: sev_order.get(f.severity, 5))
        print(f"  [{len(findings)} total findings after correlation]")

    # --- Multi-hop path analysis (runs whenever we have data beyond groups) ---
    # This covers the "default + attack-surface" case where --paths wasn't enabled
    # but we still want multi-hop analysis of whatever data was collected.
    if not args.demo and not (args.paths or args.noisy):
        has_extra_data = bool(collected_noisy.get("acl_data") or
                              collected_noisy.get("local_admin_data") or
                              args.attack_surface)
        if has_extra_data:
            privileged_sams = get_privileged_sams(trees)
            print("\n[*] Running multi-hop path analysis on available data...")
            path_findings = compute_attack_paths(
                trees,
                collected_noisy.get("acl_data"),
                collected_noisy.get("local_admin_data"),
                privileged_sams,
                session_data=collected_noisy.get("session_data"),
                findings=findings,
                max_hops=args.max_hops, max_paths=args.max_paths
            )
            seen = set((f.sam, f.category, f.inheritance_path) for f in findings)
            for f in path_findings:
                key = (f.sam, f.category, f.inheritance_path)
                if key not in seen:
                    findings.append(f)
                    seen.add(key)
            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            findings.sort(key=lambda f: sev_order.get(f.severity, 5))
            print(f"  [{len(findings)} total findings after path analysis]")

    print("\n[*] Generating HTML report...")
    generate_html_report(trees, findings, discovery_results, args.output)
    print(f"\n[+] Done. Open {args.output} in a browser.")


if __name__ == "__main__":
    main()
