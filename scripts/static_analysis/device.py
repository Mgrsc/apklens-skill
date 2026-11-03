import re
import shlex
from pathlib import Path

from .common import (
    AnalysisError,
    atomic_json,
    run_command,
    snapshot_file,
    stable_id,
    stage,
)

PACKAGE_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z")
PACKAGE_BLOCK = re.compile(r"^\s{2}Package \[([^\]]+)\]")
SHARED_BLOCK = re.compile(r"^\s{2}SharedUser \[([^\]]+)\]")
PERMISSION_PATTERN = re.compile(r"^([A-Za-z0-9_.]+): granted=(true|false)(?:[,;].*)?$")
USER_PATTERN = re.compile(r"^User (\d+):")


def parse_devices(value):
    devices = []
    for line in value.splitlines():
        parts = line.split()
        if len(parts) < 2 or line.startswith(("List ", "*")):
            continue
        fields = dict(part.split(":", 1) for part in parts[2:] if ":" in part)
        devices.append(
            {
                "serial": parts[0],
                "state": parts[1],
                "model": fields.get("model"),
                "product": fields.get("product"),
            }
        )
    return devices


def parse_inventory(value):
    packages = {}
    rejected = []
    for line in value.splitlines():
        if not line.strip():
            continue
        match = re.match(r"^package:(.+?)=([A-Za-z_][A-Za-z0-9_.]*)(?:\s|$)(.*)", line)
        if not match or not PACKAGE_PATTERN.fullmatch(match[2]):
            rejected.append(line[:200])
            continue
        fields = dict(re.findall(r"(uid|installer)[:=]([^\s]+)", match[3]))
        packages[match[2]] = {
            "package": match[2],
            "path": match[1],
            "uid": fields.get("uid"),
            "installer": fields.get("installer"),
            "permissions": {},
            "appops": {},
            "special_access": {},
        }
    return packages, rejected


def parse_dumpsys(value, user):
    packages = {}
    shared = {}
    current = None
    current_shared = None
    active_user = None
    permission_section = None
    permission_indent = None
    shared_section = False
    for line in value.splitlines():
        stripped = line.strip()
        indentation = len(line) - len(line.lstrip())
        if stripped == "Shared users:":
            shared_section, current, current_shared = True, None, None
            continue
        match = (
            PACKAGE_BLOCK.match(line)
            if not shared_section
            else SHARED_BLOCK.match(line)
        )
        if match:
            target = shared if shared_section else packages
            current = target.setdefault(
                match[1], {"permissions": {}, "members": [], "flags": []}
            )
            current_shared = match[1] if shared_section else None
            active_user, permission_section = None, None
            continue
        if current is None:
            continue
        user_match = USER_PATTERN.match(stripped)
        if user_match:
            active_user, permission_section = int(user_match[1]), None
            continue
        if stripped in {"install permissions:", "runtime permissions:"}:
            permission_section = (
                "install" if stripped.startswith("install") else "runtime"
            )
            permission_indent = indentation
            continue
        if stripped and permission_section and indentation <= permission_indent:
            permission_section = None
        permission = PERMISSION_PATTERN.match(stripped)
        if (
            permission
            and permission_section
            and (permission_section == "install" or active_user == user)
        ):
            name, granted = permission[1], permission[2] == "true"
            current["permissions"][name] = {
                "granted": granted,
                "source": "shared_uid_" + permission_section
                if current_shared
                else permission_section,
                "user": user if permission_section == "runtime" else None,
            }
        if stripped.startswith(("appId=", "userId=")):
            current["app_id"] = stripped.split("=", 1)[1].split()[0]
        elif stripped.startswith(("flags=[", "pkgFlags=[")):
            current["flags"] = stripped.partition("[")[2].partition("]")[0].split()
        elif stripped.startswith("installerPackageName="):
            current["installer"] = stripped.split("=", 1)[1]
        elif stripped.startswith("versionCode="):
            current["version_code"] = stripped.split("=", 1)[1].split()[0]
        elif stripped.startswith("sharedUser="):
            match = re.search(r"SharedUserSetting\{[^ ]+ ([^/]+)/", stripped)
            if match:
                current["shared_user"] = match[1]
        elif shared_section:
            match = re.search(r"PackageSetting\{[^ ]+ ([^/]+)/", stripped)
            if match:
                current["members"].append(match[1])
    for name, item in shared.items():
        members = set(item["members"]) | {
            package
            for package, data in packages.items()
            if data.get("shared_user") == name
        }
        for package in members:
            target = packages.setdefault(package, {"permissions": {}, "flags": []})
            target["shared_user"] = name
            for permission, fact in item["permissions"].items():
                target["permissions"][permission] = fact
            target.setdefault("app_id", item.get("app_id"))
    return packages


def parse_appops(value):
    modes = {}
    for line in value.splitlines():
        match = re.match(
            r"\s*(?:Uid mode:\s*)?([A-Z][A-Z0-9_]*):\s*(allow|ignore|deny|default|foreground|errored)(?:;|\s|$)",
            line,
        )
        if match:
            modes[match[1]] = match[2]
    return modes


class DeviceCollector:
    def __init__(
        self,
        executable,
        serial,
        user,
        output,
        limits,
        cancel,
        timeout=60,
        checkpoint=None,
    ):
        if (
            not serial
            or serial.startswith("-")
            or any(character.isspace() or ord(character) < 32 for character in serial)
        ):
            raise AnalysisError("Invalid device serial")
        if user < 0:
            raise AnalysisError("User ID must be nonnegative")
        self.executable = executable
        self.serial = serial
        self.user = user
        self.output = Path(output)
        self.limits = limits
        self.cancel = cancel
        self.timeout = timeout
        self.stages = []
        self.packages = {}
        self.artifacts = []
        self.checkpoint = checkpoint
        self.settings = {}
        self.installed_count = 0
        self.targets = []
        self.excluded_packages = []

    def snapshot(self):
        return {
            "serial": self.serial,
            "user": self.user,
            "installed_count": self.installed_count,
            "selected_packages": self.targets,
            "excluded_packages": self.excluded_packages,
            "packages": self.packages,
            "stages": self.stages,
            "artifacts": self.artifacts,
            "settings": self.settings,
        }

    def persist(self, complete=False):
        if self.checkpoint:
            self.checkpoint(self.snapshot(), complete)

    def shell(self, arguments):
        result = run_command(
            [self.executable, "-s", self.serial, "shell", shlex.join(arguments)],
            timeout=self.timeout,
            cancel=self.cancel,
        )
        if result["status"] == "COMPLETE" and re.search(
            r"(?im)^(?:error:|exception occurred|java\.lang\.SecurityException|permission denial:)",
            result["stdout"],
        ):
            result["status"], result["reason"] = (
                "FAILED",
                "Device denied or rejected the command",
            )
        return result

    def collect(self, selected):
        for package in selected:
            if not PACKAGE_PATTERN.fullmatch(package):
                raise AnalysisError("Invalid package name")
        self.output.mkdir(parents=True, exist_ok=True)
        inventory = self.shell(
            ["pm", "list", "packages", "--user", str(self.user), "-f", "-U", "-i"]
        )
        packages, rejected = parse_inventory(inventory["stdout"])
        self.installed_count = len(packages)
        self.targets = sorted(set(selected) if selected else packages)
        self.excluded_packages = sorted(set(packages) - set(self.targets))
        if rejected:
            inventory["status"], inventory["reason"] = (
                "PARTIAL",
                "Some inventory records could not be parsed",
            )
        if not packages and inventory["status"] == "COMPLETE":
            inventory["status"], inventory["reason"] = (
                "PARTIAL",
                "No package inventory could be established",
            )
        self.stages.append(
            stage(
                "inventory",
                inventory["status"],
                "device",
                inventory["reason"],
                installed=len(packages),
                rejected_records=len(rejected),
            )
        )
        dump = self.shell(["dumpsys", "package"])
        metadata = parse_dumpsys(dump["stdout"], self.user)
        self.stages.append(
            stage(
                "permission_snapshot",
                dump["status"],
                "device",
                dump["reason"],
                parsed_packages=len(metadata),
            )
        )
        atomic_json(
            self.output / "package-snapshot.json",
            {"user": self.user, "inventory": inventory, "dumpsys": dump},
        )
        settings = self.settings
        for name in (
            "enabled_accessibility_services",
            "enabled_notification_listeners",
            "default_input_method",
        ):
            result = self.shell(
                ["settings", "--user", str(self.user), "get", "secure", name]
            )
            settings[name] = result
            self.stages.append(
                stage(
                    "special_access_snapshot", result["status"], name, result["reason"]
                )
            )
        atomic_json(self.output / "settings-snapshot.json", settings)
        targets = sorted(set(selected) if selected else packages)
        self.persist()
        for package in targets:
            if self.cancel.is_set():
                self.stages.append(
                    stage("collection", "CANCELLED", package, "Collection cancelled")
                )
                break
            item = dict(
                packages.get(
                    package,
                    {
                        "package": package,
                        "permissions": {},
                        "appops": {},
                        "special_access": {},
                    },
                )
            )
            item["stages"] = []
            item["user"] = self.user
            self.packages[package] = item
            if package not in packages:
                item["stages"].append(
                    stage(
                        "installed_identity",
                        "UNAVAILABLE",
                        package,
                        "Package is absent from the selected user inventory",
                    )
                )
                self.packages[package] = item
                self.persist()
                continue
            meta = metadata.get(package)
            if meta:
                item.update(
                    {key: value for key, value in meta.items() if key != "members"}
                )
                item["stages"].append(
                    stage(
                        "package_permissions", dump["status"], package, dump["reason"]
                    )
                )
            else:
                item["stages"].append(
                    stage(
                        "package_permissions",
                        "UNAVAILABLE",
                        package,
                        "Package permission record could not be parsed",
                    )
                )
            item["is_system"] = "SYSTEM" in item.get("flags", [])
            for name, result in settings.items():
                if result["status"] == "COMPLETE" and result["stdout"].strip():
                    components = result["stdout"].strip().split(":")
                    item["special_access"][name] = any(
                        component.split("/", 1)[0] == package
                        for component in components
                    )
                else:
                    item["special_access"][name] = None
            appops = self.shell(
                ["cmd", "appops", "get", "--user", str(self.user), package]
            )
            item["appops"] = (
                parse_appops(appops["stdout"]) if appops["status"] == "COMPLETE" else {}
            )
            item["stages"].append(
                stage("appops_snapshot", appops["status"], package, appops["reason"])
            )
            self.persist()
            paths = self.shell(["pm", "path", "--user", str(self.user), package])
            remote_paths = [
                line[8:].strip()
                for line in paths["stdout"].splitlines()
                if line.startswith("package:")
            ]
            valid_paths = sorted(
                {
                    path
                    for path in remote_paths
                    if path.startswith("/")
                    and not any(character in path for character in "\x00\r\n")
                }
            )
            path_status = paths["status"]
            if not valid_paths or len(valid_paths) != len(remote_paths):
                path_status = "PARTIAL"
            item["remote_paths"] = valid_paths
            item["stages"].append(
                stage(
                    "artifact_enumeration",
                    path_status,
                    package,
                    paths["reason"]
                    or (
                        "No complete readable artifact list"
                        if path_status != "COMPLETE"
                        else None
                    ),
                    count=len(valid_paths),
                )
            )
            for remote in valid_paths:
                target = self.output / (stable_id(package, remote) + ".apk")
                result = run_command(
                    [self.executable, "-s", self.serial, "pull", remote, str(target)],
                    timeout=self.timeout,
                    cancel=self.cancel,
                    watched_file=target,
                    max_file_bytes=self.limits.max_apk_bytes,
                )
                if result["status"] == "COMPLETE" and target.is_file():
                    try:
                        artifact = snapshot_file(
                            target,
                            self.output.parent / "artifacts",
                            self.limits,
                            self.cancel,
                        )
                        artifact.update(
                            {
                                "package_hint": package,
                                "remote_path": remote,
                                "input": remote,
                            }
                        )
                        self.artifacts.append(artifact)
                        item["stages"].append(
                            stage(
                                "artifact_collection",
                                source=remote,
                                bytes=artifact["size"],
                            )
                        )
                    except (AnalysisError, OSError) as error:
                        item["stages"].append(
                            stage("artifact_collection", "FAILED", remote, str(error))
                        )
                else:
                    item["stages"].append(
                        stage(
                            "artifact_collection",
                            result["status"]
                            if result["status"] != "COMPLETE"
                            else "FAILED",
                            remote,
                            result["reason"] or "ADB did not create an APK",
                        )
                    )
                self.persist()
                target.unlink(missing_ok=True)
            after = self.shell(["pm", "path", "--user", str(self.user), package])
            final_paths = sorted(
                {
                    line[8:].strip()
                    for line in after["stdout"].splitlines()
                    if line.startswith("package:")
                }
            )
            after_metadata = self.shell(["dumpsys", "package", package])
            final_version = (
                parse_dumpsys(after_metadata["stdout"], self.user)
                .get(package, {})
                .get("version_code")
            )
            stable = (
                after["status"] == "COMPLETE"
                and final_paths == valid_paths
                and after_metadata["status"] == "COMPLETE"
                and final_version is not None
                and final_version == item.get("version_code")
            )
            item["stages"].append(
                stage(
                    "installation_consistency",
                    "COMPLETE" if stable else "PARTIAL",
                    package,
                    None
                    if stable
                    else "Paths or version changed, or identity could not be rechecked; snapshot may be inconsistent",
                )
            )
            self.packages[package] = item
            self.persist()
        self.persist(complete=not self.cancel.is_set())
        return self.snapshot()
