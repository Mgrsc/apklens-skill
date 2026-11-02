from .common import AnalysisError

COMPONENT_KINDS = {"activity", "activity-alias", "service", "receiver", "provider"}


def boolean(value):
    if isinstance(value, bool):
        return value
    if not isinstance(value, (str, int)):
        return None
    if value in {"true", "1"}:
        return True
    if value in {"false", "0"}:
        return False
    return None


def integer(value):
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def analyze_manifest(nodes):
    if not nodes or nodes[0]["name"] != "manifest":
        raise AnalysisError("Manifest root element is missing")
    root = nodes[0]["attrs"]
    package = root.get("package")
    if not isinstance(package, str) or not package:
        raise AnalysisError("Manifest package identity is missing")
    application = next(
        (
            node["attrs"]
            for node in nodes
            if node["name"] == "application" and node["depth"] == 1
        ),
        {},
    )
    sdk = next((node["attrs"] for node in nodes if node["name"] == "uses-sdk"), {})
    target = integer(sdk.get("android:targetSdkVersion"))
    minimum = integer(sdk.get("android:minSdkVersion"))
    target_effective = (
        target
        if target is not None
        else None
        if "android:targetSdkVersion" in sdk
        else minimum
        if minimum is not None
        else None
        if "android:minSdkVersion" in sdk
        else 1
    )
    permissions = []
    components = []
    metadata = []
    resource_references = []
    for index, node in enumerate(nodes):
        attrs = node["attrs"]
        for name, value in attrs.items():
            if isinstance(value, str) and value.startswith("@"):
                resource_references.append(
                    {"element": node["name"], "attribute": name, "value": value}
                )
        if node["name"] in {"uses-permission", "uses-permission-sdk-23"}:
            name = attrs.get("android:name")
            if isinstance(name, str):
                permissions.append(
                    {
                        "name": name,
                        "max_sdk": integer(attrs.get("android:maxSdkVersion")),
                        "declaration": node["name"],
                        "flags": attrs.get("android:usesPermissionFlags"),
                        "granted": None,
                        "grant_source": "unavailable_for_local_artifact",
                    }
                )
        if node["name"] == "meta-data":
            metadata.append(
                {
                    "name": attrs.get("android:name"),
                    "value": attrs.get("android:value"),
                    "resource": attrs.get("android:resource"),
                }
            )
        if node["name"] in COMPONENT_KINDS and node["depth"] == 2:
            descendants = []
            cursor = index + 1
            while cursor < len(nodes) and nodes[cursor]["depth"] > node["depth"]:
                descendants.append(nodes[cursor])
                cursor += 1
            has_filter = any(item["name"] == "intent-filter" for item in descendants)
            explicit = boolean(attrs.get("android:exported"))
            exported = explicit
            basis = "explicit"
            if "android:exported" not in attrs:
                if node["name"] == "provider":
                    exported, basis = (
                        (
                            target_effective < 17
                            if target_effective is not None
                            else None
                        ),
                        "provider_target_sdk_default"
                        if target_effective is not None
                        else "unresolved_target_sdk",
                    )
                elif has_filter and target_effective is None:
                    exported, basis = None, "unresolved_target_sdk"
                elif has_filter and target_effective >= 31:
                    exported, basis = (
                        None,
                        "explicit_exported_required_for_modern_targets",
                    )
                else:
                    exported, basis = has_filter, "intent_filter_default"
            elif explicit is None:
                basis = "unresolved_attribute"
            inherited = application.get("android:permission")
            permission = attrs.get("android:permission", inherited)
            if permission == "":
                permission = None
            components.append(
                {
                    "kind": node["name"],
                    "name": attrs.get("android:name"),
                    "exported": exported,
                    "exported_basis": basis,
                    "permission": permission,
                    "read_permission": attrs.get("android:readPermission", permission),
                    "write_permission": attrs.get(
                        "android:writePermission", permission
                    ),
                    "authorities": attrs.get("android:authorities"),
                    "intent_filter": has_filter,
                    "grant_uri_permissions": boolean(
                        attrs.get("android:grantUriPermissions")
                    ),
                    "path_permissions": [
                        item["attrs"]
                        for item in descendants
                        if item["name"] == "path-permission"
                    ],
                }
            )
    return {
        "package": package,
        "split": root.get("split"),
        "version_code": root.get("android:versionCode"),
        "version_name": root.get("android:versionName"),
        "shared_user_id": root.get("android:sharedUserId"),
        "min_sdk": minimum,
        "target_sdk": target,
        "target_sdk_default": target_effective,
        "permissions": permissions,
        "components": components,
        "application": {
            "debuggable": boolean(application.get("android:debuggable")),
            "allow_backup": boolean(application.get("android:allowBackup")),
            "uses_cleartext_traffic": boolean(
                application.get("android:usesCleartextTraffic")
            ),
            "network_security_config": application.get("android:networkSecurityConfig"),
            "data_extraction_rules": application.get("android:dataExtractionRules"),
            "full_backup_content": application.get("android:fullBackupContent"),
            "permission": application.get("android:permission"),
        },
        "metadata": metadata,
        "unresolved_resource_references": resource_references,
    }
