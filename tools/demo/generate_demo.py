#!/usr/bin/env python3
"""Erzeugt Demodaten (fiktive Domäne DEMO.LOCAL mit zwei Dateiservern).

Ausgabe: ad-demo.json (AD-Export) und report-fs01.json / report-fs02.json (Client-Reports).
Import:
    pc-server import-ad ad-demo.json
    pc-server import-report report-fs01.json
    pc-server import-report report-fs02.json
oder per HTTP:
    curl -X POST -H "Content-Type: application/json" --data-binary @ad-demo.json http://localhost:8080/api/v1/ad/import
"""

import json
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(42)
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
OUT.mkdir(parents=True, exist_ok=True)
NOW = datetime.now(timezone.utc)
DOM = "S-1-5-21-3623811015-3361044348-30300820"


def iso(d):
    return d.strftime("%Y-%m-%dT%H:%M:%SZ") if d else None


# --- Active Directory --------------------------------------------------------
rid = 1100
users, groups = [], []


def user(sam, name, enabled=True, days_ago=3, created_days=900):
    global rid
    rid += 1
    u = {
        "sid": f"{DOM}-{rid}",
        "sam_account_name": sam,
        "user_principal_name": f"{sam}@demo.local",
        "display_name": name,
        "distinguished_name": f"CN={name},OU=Benutzer,DC=demo,DC=local",
        "enabled": enabled,
        "last_logon": iso(NOW - timedelta(days=days_ago)) if days_ago is not None else None,
        "created": iso(NOW - timedelta(days=created_days)),
        "is_computer": False,
        "member_of": [f"{DOM}-513"],
    }
    users.append(u)
    return u


def group(sam, desc, scope="global", members=()):
    global rid
    rid += 1
    g = {
        "sid": f"{DOM}-{rid}",
        "sam_account_name": sam,
        "distinguished_name": f"CN={sam},OU=Gruppen,DC=demo,DC=local",
        "description": desc,
        "scope": scope,
        "is_security": True,
        "members": [m["sid"] for m in members],
        "created": iso(NOW - timedelta(days=1200)),
    }
    groups.append(g)
    return g


anna = user("a.schmidt", "Anna Schmidt")
ben = user("b.mueller", "Ben Müller")
clara = user("c.wagner", "Clara Wagner", days_ago=200)  # inaktiv
dirk = user("d.becker", "Dirk Becker", enabled=False, days_ago=400)  # deaktiviert
eva = user("e.hoffmann", "Eva Hoffmann")
felix = user("f.koch", "Felix Koch", enabled=False, days_ago=500)
gina = user("g.richter", "Gina Richter", days_ago=None, created_days=300)  # nie angemeldet
admin = user("adm.it", "IT Administrator")

g_vertrieb = group("GG_Vertrieb", "Mitarbeiter Vertrieb", members=[anna, ben, clara])
g_technik = group("GG_Technik", "Mitarbeiter Technik", members=[eva, dirk])
g_gf = group("GG_Geschaeftsfuehrung", "Geschäftsführung", members=[anna])
g_alt = group("GG_Projekt_Alpha", "Altes Projekt", members=[dirk, felix])  # nur deaktivierte
g_leer = group("GG_Marketing", "Marketing (leer)")  # leer
group("GG_Unbenutzt", "Wird nirgends verwendet", members=[eva])
dl_vertrieb_rw = group("DL_FS01_Vertrieb_RW", "Ändern auf \\\\FS01\\Daten\\Vertrieb", "domain_local", [g_vertrieb])
dl_vertrieb_r = group("DL_FS01_Vertrieb_R", "Lesen auf \\\\FS01\\Daten\\Vertrieb", "domain_local", [g_gf])
dl_technik_rw = group("DL_FS01_Technik_RW", "Ändern auf \\\\FS01\\Daten\\Technik", "domain_local", [g_technik])
dl_fs_admin = group("DL_FS_Admins", "Dateiserver-Administratoren", "domain_local", [admin])
dl_projekte = group("DL_FS02_Projekte_RW", "Projekte", "domain_local", [g_technik, g_alt])
groups.append({"sid": f"{DOM}-513", "sam_account_name": "Domänen-Benutzer", "scope": "global", "is_security": True,
               "members": [], "description": "Alle Domänenbenutzer"})
groups.append({"sid": f"{DOM}-512", "sam_account_name": "Domänen-Admins", "scope": "global", "is_security": True,
               "members": [admin["sid"]]})

ad = {"domain": "demo.local", "domain_sid": DOM, "collected_at": iso(NOW), "users": users, "groups": groups}
(OUT / "ad-demo.json").write_text(json.dumps(ad, ensure_ascii=False, indent=1), encoding="utf-8")

# --- Client-Reports ------------------------------------------------------------
FULL, MODIFY, RX, READ = 0x1F01FF, 0x1301BF, 0x1200A9, 0x120089
RIGHTS = {FULL: "full_control", MODIFY: "modify", RX: "read_execute", READ: "read"}
GONE = f"{DOM}-1066"  # gelöschter Benutzer
GONE_GROUP = f"{DOM}-1042"  # gelöschte Gruppe


def ace(sid, mask, inherited=False, deny=False):
    return {"sid": sid, "ace_type": "deny" if deny else "allow", "mask": mask, "rights": RIGHTS.get(mask, "special"),
            "inherited": inherited, "flags": (0x13 if inherited else 0x03)}


BASE = [ace("S-1-5-18", FULL, True), ace("S-1-5-32-544", FULL, True), ace("S-1-3-0", FULL, True)]


def report(host, tree, shares, extra_principals):
    folders, next_id = [], [1]
    stats = dict(explicit=0, protected=0, orphaned=0)

    def walk(path, node, parent, depth, source, inherited_aces):
        fid = next_id[0]
        next_id[0] += 1
        explicit = node.get("aces", [])
        protected = node.get("protected", False)
        aces = explicit + ([] if protected else inherited_aces)
        if protected:
            aces = explicit
        src = fid if (explicit or protected or parent is None) else source
        stats["explicit"] += bool(explicit)
        stats["protected"] += protected
        stats["orphaned"] += sum(1 for a in explicit if a["sid"] in (GONE, GONE_GROUP))
        rec = {"id": fid, "parent_id": parent, "path": path, "depth": depth, "owner_sid": node.get("owner", "S-1-5-32-544"),
               "inheritance_protected": protected, "has_explicit_aces": bool(explicit), "acl_source_id": src,
               "aces": aces, "file_count": random.randint(0, 400), "file_bytes": random.randint(0, 5_000_000_000),
               "subfolder_total": 0, "is_reparse_point": False, "error": node.get("error")}
        folders.append(rec)
        child_inherit = [dict(a, inherited=True, flags=0x13) for a in aces]
        total = node.get("hidden", 0)
        for name, child in node.get("children", {}).items():
            child_path = path.rstrip("\\") + "\\" + name
            total += 1 + walk(child_path, child, fid, depth + 1, src, child_inherit)
        rec["subfolder_total"] = total
        return total

    roots = []
    for root_path, node in tree.items():
        first = next_id[0]
        n = walk(root_path, node, None, 0, None, BASE)
        roots.append({"path": root_path, "kind": "local_drive", "folder_id": first, "folders_scanned": n + 1,
                      "folders_excluded": 7, "errors": sum(1 for f in folders if f["error"])})
    by_path = {f["path"].lower(): f["id"] for f in folders}
    for s in shares:
        s["folder_id"] = by_path.get(s["path"].lower())
    principals = [
        {"sid": u["sid"], "name": u["sam_account_name"], "domain": "DEMO", "kind": "user"} for u in users
    ] + [{"sid": g["sid"], "name": g["sam_account_name"], "domain": "DEMO", "kind": "group"} for g in groups] + [
        {"sid": GONE, "name": None, "domain": None, "kind": "unresolved"},
        {"sid": GONE_GROUP, "name": None, "domain": None, "kind": "unresolved"},
        {"sid": "S-1-1-0", "name": "Jeder", "domain": "", "kind": "well_known_group"},
        {"sid": "S-1-5-11", "name": "Authentifizierte Benutzer", "domain": "NT-AUTORITÄT", "kind": "well_known_group"},
    ] + extra_principals
    scanned = sum(f["subfolder_total"] for f in folders if f["parent_id"] is None) + len(roots)
    started = NOW - timedelta(minutes=random.randint(30, 90))
    return {
        "schema_version": 1, "scan_id": str(uuid.uuid4()), "client_version": "0.1.0",
        "host": {"hostname": host, "domain": "demo.local", "os_name": "Windows Server 2022 Standard",
                 "os_version": "21H2 (Build 20348.2849)", "os_build": 20348, "is_domain_controller": False,
                 "machine_sid": None},
        "started_at": iso(started), "finished_at": iso(started + timedelta(minutes=12)), "report_mode": "relevant",
        "roots": roots, "shares": shares, "folders": folders, "principals": principals,
        "errors": [{"path": f["path"], "code": 5, "message": "Zugriff verweigert"} for f in folders if f["error"]],
        "stats": {"folders_scanned": scanned, "folders_reported": len(folders), "folders_excluded": 7,
                  "folders_with_explicit_aces": stats["explicit"], "folders_inheritance_protected": stats["protected"],
                  "reparse_points_skipped": 2, "files_seen": 52811, "errors": 1, "orphaned_aces": stats["orphaned"],
                  "duration_ms": 734_000},
    }


fs01_tree = {
    "D:\\": {"hidden": 12, "children": {
        "Daten": {"aces": [ace("S-1-5-11", RX)], "children": {
            "Vertrieb": {"protected": True, "aces": BASE[:2] + [ace(dl_vertrieb_rw["sid"], MODIFY), ace(dl_vertrieb_r["sid"], RX)],
                         "hidden": 230, "children": {
                "Angebote": {"hidden": 120},
                "Kunden": {"aces": [ace(GONE, MODIFY), ace(ben["sid"], FULL)], "hidden": 410},
                "Archiv": {"aces": [ace(dirk["sid"], MODIFY), ace(GONE_GROUP, READ)], "hidden": 85},
            }},
            "Technik": {"protected": True, "aces": BASE[:2] + [ace(dl_technik_rw["sid"], MODIFY)], "hidden": 900, "children": {
                "CAD": {"hidden": 1400},
                "Messdaten": {"children": {"2019": {"children": {"Q1": {"children": {"Rohdaten": {"children": {
                    "Sensor7": {"aces": [ace(clara["sid"], MODIFY)]}}}}}}}}},
                "Prototypen": {"aces": [ace(f"{DOM}-513", FULL, deny=False)], "hidden": 60},
            }},
            "Geschaeftsfuehrung": {"protected": True, "aces": BASE[:2] + [ace(g_gf["sid"], MODIFY), ace("S-1-5-32-545", 0x100116, deny=True)],
                                   "hidden": 40},
            "Austausch": {"aces": [ace("S-1-1-0", FULL)], "hidden": 15},
            "Marketing": {"aces": [ace(g_leer["sid"], MODIFY)], "hidden": 33},
            "Personal": {"protected": True, "aces": BASE[:2] + [ace(eva["sid"], FULL)], "error": None, "hidden": 70,
                         "owner": GONE},
        }},
        "Software": {"aces": [ace(dl_fs_admin["sid"], FULL)], "hidden": 300},
        "Gesperrt": {"error": "Sicherheit nicht lesbar: Zugriff verweigert (Code 5)"},
    }},
}
fs01_shares = [
    {"name": "Daten", "path": "D:\\Daten", "remark": "Abteilungslaufwerke", "share_type": 0, "is_special": False,
     "permissions": None},
    {"name": "Austausch", "path": "D:\\Daten\\Austausch", "remark": None, "share_type": 0, "is_special": False,
     "permissions": [ace("S-1-1-0", FULL)]},
    {"name": "Software$", "path": "D:\\Software", "remark": "Installationsquellen", "share_type": 0, "is_special": False,
     "permissions": [ace("S-1-5-11", RX), ace(dl_fs_admin["sid"], FULL)]},
    {"name": "D$", "path": "D:\\", "remark": "Standardfreigabe", "share_type": 0x80000000, "is_special": True,
     "permissions": None},
]
fs02_tree = {
    "E:\\": {"hidden": 5, "children": {
        "Projekte": {"protected": True, "aces": BASE[:2] + [ace(dl_projekte["sid"], MODIFY)], "hidden": 2200, "children": {
            "Alpha": {"aces": [ace(g_alt["sid"], MODIFY), ace(felix["sid"], MODIFY)], "hidden": 340},
            "Beta": {"hidden": 510},
            "Gamma": {"aces": [ace(gina["sid"], MODIFY)], "hidden": 90},
        }},
        "Scans": {"aces": [ace("S-1-5-11", MODIFY)], "hidden": 25},
    }},
}
fs02_shares = [
    {"name": "Projekte", "path": "E:\\Projekte", "remark": None, "share_type": 0, "is_special": False,
     "permissions": [ace("S-1-5-11", MODIFY), ace("S-1-5-32-544", FULL)]},
    {"name": "Scans", "path": "E:\\Scans", "remark": "Scanner-Ablage", "share_type": 0, "is_special": False,
     "permissions": [ace("S-1-1-0", FULL)]},
]

for host, tree, shares in [("FS01", fs01_tree, fs01_shares), ("FS02", fs02_tree, fs02_shares)]:
    rep = report(host, tree, shares, [])
    (OUT / f"report-{host.lower()}.json").write_text(json.dumps(rep, ensure_ascii=False), encoding="utf-8")
    print(f"report-{host.lower()}.json: {len(rep['folders'])} Ordner")
print(f"ad-demo.json: {len(users)} Benutzer, {len(groups)} Gruppen")
