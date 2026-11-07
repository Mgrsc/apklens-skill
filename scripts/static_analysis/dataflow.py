import copy
import re
import sys
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass
from urllib.parse import urlsplit

from .common import (
    Budget,
    BudgetExceeded,
    Cancelled,
    MemoryBudgetExceeded,
    stable_id,
    stage,
)
from .method_selection import (
    MAX_CANDIDATE_FACTOR,
    MAX_METHOD_TARGETS,
    DefinitionSummaryError,
    MethodSelection,
    candidate_order,
    definition_digest,
    definition_occurrences,
    definition_summary,
)
from .privacy_models import (
    AUDIO_READS,
    BOUNDARY_OWNERS,
    MODEL_VERSION,
    SCREEN_SURFACE,
    SOURCE_METHODS,
    TRANSFORMS,
    invocation_roles,
)

MAX_CALL_DEPTH = 4
MAX_METHOD_STATES = 128
MAX_APP_STEPS = 100000
MAX_ROOT_STEPS = 2048
MAX_GAP_REASON_GROUPS = 64
MAX_HEAP_OBJECTS = 256
MAX_PATH_NODES = 32
MAX_VALUE_SOURCES = 8
MAX_GAPS = 256
MAX_CONSTANT_LENGTH = 1024
MAX_FLOWS = 1000
MAX_FLOW_VARIANTS = 4
MAX_APP_METHODS = 8192
MAX_REGISTERS = 1024
MAX_OBJECT_SLOTS = 128
MAX_METHOD_CACHE_ENTRIES = 64
MAX_METHOD_CACHE_BYTES = 4 * 1024 * 1024
METHOD_CACHE_CHECK_ITEMS = 64
HTTP_URL_SCHEMES = frozenset({"http", "https"})
NETWORK_URL_SCHEMES = HTTP_URL_SCHEMES | {"ftp", "ftps"}
URL_SCHEMES = NETWORK_URL_SCHEMES | {"file"}
TYPE_PATTERN = re.compile(r"\[*L[^;]+;|\[*[ZBCSIJFD]")


def immutable_content(value):
    return (
        type(value) in (str, int, float, bool, type(None))
        or isinstance(value, ImmutableLeaf)
        and value._immutable
        or type(value) is tuple
        and all(immutable_content(item) for item in value)
    )


class ImmutableLeaf:
    def __post_init__(self):
        object.__setattr__(
            self,
            "_immutable",
            all(immutable_content(value) for value in vars(self).values()),
        )

    def __deepcopy__(self, memo):
        if self._immutable:
            return self
        result = object.__new__(type(self))
        memo[id(self)] = result
        for key, value in vars(self).items():
            object.__setattr__(result, key, copy.deepcopy(value, memo))
        return result


@dataclass(frozen=True)
class Node(ImmutableLeaf):
    artifact: str
    entry: str
    method: str
    offset: int
    kind: str
    target: str
    arguments: tuple = ()

    def record(self):
        value = {
            "artifact": self.artifact,
            "entry": self.entry,
            "method": self.method,
            "instruction_offset": self.offset,
            "kind": self.kind,
            "excerpt": self.target,
        }
        if self.arguments:
            value["arguments"] = [
                {"index": index, "constant": constant}
                for index, constant in self.arguments
            ]
        return {"id": stable_id("flow_evidence", value), **value}


@dataclass(frozen=True)
class Source(ImmutableLeaf):
    category: str
    path: tuple


@dataclass(frozen=True)
class Value(ImmutableLeaf):
    sources: tuple = ()
    objects: tuple = ()
    constants: tuple = ()


EMPTY = Value()


def descriptor(signature):
    owner, tail = signature.split("->", 1)
    name, arguments = tail.split("(", 1)
    parameters, result = arguments.split(")", 1)
    return owner, name, TYPE_PATTERN.findall(parameters), result


def evidence_path_key(category, evidence_ids, endpoints):
    return category, tuple(evidence_ids), tuple(sorted(set(endpoints)))


class RootBudgetExceeded(BudgetExceeded):
    pass


class Analyzer:
    def __init__(self, methods, limits, cancel=None, definition_summaries=None):
        self.methods = methods
        self.definition_summaries = definition_summaries
        self.limits = limits
        self.budget = Budget(limits, cancel)
        self.index = {}
        self.gaps = {}
        self.gap_counts = Counter()
        self.ambiguous = set()
        self.root_steps = 0
        self.active_root = None
        self.roots_started = 0
        self.roots_truncated = 0
        self.roots_missing_body = 0
        self.definitions_considered = 0
        self.index_omitted = 0
        self.definition_inventory = []
        self.interpretation_deferred = False
        self.flows = {}
        self.flow_groups = {}
        self.variant_groups = OrderedDict()
        self.steps = 0
        self.sequence = 0
        self.completed = 0
        self.method_cache = OrderedDict()
        self.method_cache_bytes = 0

    def gap(self, reason, node=None):
        group = reason.split(": ", 1)[0]
        if (
            group not in self.gap_counts
            and len(self.gap_counts) >= MAX_GAP_REASON_GROUPS
        ):
            group = "Additional reason groups exceed the summary budget"
        self.gap_counts[group] += 1
        if len(self.gaps) >= MAX_GAPS:
            self.gaps["truncated"] = {
                "id": "truncated",
                "reason": "Additional dataflow gaps exceed the display budget",
            }
            return
        source = node.record() if node else {}
        if node is not None and self.active_root:
            source["candidate_root"] = self.active_root
        identity = stable_id("flow_gap", reason, source)
        self.gaps[identity] = {**source, "id": identity, "reason": reason}

    def join(self, *values):
        sources, objects = [], []
        constants = values[0].constants if values else ()
        seen = set()
        for value in values:
            if value.constants != constants:
                constants = ()
            for source in value.sources:
                key = (source.category, source.path[0])
                if key not in seen:
                    seen.add(key)
                    sources.append(source)
            objects.extend(item for item in value.objects if item not in objects)
        if len(sources) > MAX_VALUE_SOURCES or len(objects) > MAX_VALUE_SOURCES:
            self.gap("Value source or alias budget exceeded")
        return Value(
            tuple(sources[:MAX_VALUE_SOURCES]),
            tuple(objects[:MAX_VALUE_SOURCES]),
            constants,
        )

    def advance(self, value, node):
        sources = []
        for source in value.sources:
            if source.path[-1] == node:
                sources.append(source)
            elif len(source.path) < MAX_PATH_NODES:
                sources.append(Source(source.category, (*source.path, node)))
            else:
                self.gap("Dataflow evidence path budget exceeded", node)
        return Value(tuple(sources), value.objects, value.constants)

    def snapshot(self, value, node):
        result = self.advance(value, node)
        return Value(result.sources, constants=result.constants)

    def read(self, value, state, seen=None):
        seen = set() if seen is None else seen
        parts = [Value(value.sources, (), value.constants)]
        for identity in value.objects:
            if identity in seen:
                continue
            seen.add(identity)
            obj = state["heap"].get(identity, {})
            parts.append(obj.get("value", EMPTY))
            for child in obj.get("fields", {}).values():
                parts.append(self.read(child, state, seen))
            for child in obj.get("elements", {}).values():
                parts.append(self.read(child, state, seen))
        result = self.join(*parts)
        return Value(result.sources, value.objects, value.constants)

    def allocate(self, state, kind, node, value=EMPTY):
        if len(state["heap"]) >= MAX_HEAP_OBJECTS:
            self.gap("Object budget exceeded", node)
            return EMPTY
        self.sequence += 1
        identity = f"{node.method}:{node.offset}:{self.sequence}"
        state["heap"][identity] = {
            "type": kind,
            "value": value,
            "fields": {},
            "elements": {},
        }
        return Value(objects=(identity,))

    def objects(self, value, state):
        return [
            state["heap"][identity]
            for identity in value.objects
            if identity in state["heap"]
        ]

    def stream_objects(self, value, state):
        pending = list(value.objects)
        visited = set()
        objects = []
        while pending:
            identity = pending.pop()
            if identity in visited:
                continue
            visited.add(identity)
            obj = state["heap"].get(identity)
            if obj is not None:
                objects.append(obj)
                pending.extend(obj.get("delegate", EMPTY).objects)
        return objects

    def store_slot(self, slots, key, value, node):
        if key not in slots and len(slots) >= MAX_OBJECT_SLOTS:
            self.gap("Object field or element budget exceeded", node)
            return
        slots[key] = value

    def attach(self, receiver, value, state, replace=False):
        for obj in self.objects(receiver, state):
            obj["value"] = value if replace else self.join(obj["value"], value)

    def node(self, method, instruction, kind="dataflow_step"):
        return Node(
            method["artifact"],
            method["entry"],
            method["signature"],
            instruction["offset"],
            kind,
            str(
                instruction.get(
                    "target", instruction.get("field", instruction["opcode"])
                )
            ),
        )

    def source(self, category, node):
        return Value(
            sources=(
                Source(
                    category,
                    (
                        Node(
                            node.artifact,
                            node.entry,
                            node.method,
                            node.offset,
                            "data_source",
                            node.target,
                            node.arguments,
                        ),
                    ),
                ),
            )
        )

    def endpoint_literals(self, literals, node, *, schemes=NETWORK_URL_SCHEMES):
        endpoints = []
        for literal in literals:
            if isinstance(literal, str):
                try:
                    parsed = urlsplit(literal)
                    if (
                        parsed.scheme.lower() in schemes
                        and parsed.port != 0
                        and (
                            parsed.scheme.lower() not in NETWORK_URL_SCHEMES
                            or parsed.hostname
                        )
                    ):
                        endpoints.append(literal)
                        continue
                except (ValueError, UnicodeError):
                    pass
            self.gap("Endpoint literal is not a usable absolute URL", node)
        return tuple(dict.fromkeys(endpoints))

    def emit(self, value, node, state, endpoints=()):
        endpoints = self.endpoint_literals(endpoints, node)
        value = self.advance(
            self.read(value, state),
            Node(
                node.artifact,
                node.entry,
                node.method,
                node.offset,
                "network_sink",
                node.target,
            ),
        )
        for source in value.sources:
            if self.limits.max_evidence < len(source.path):
                self.gap(
                    "Evidence budget cannot retain the complete dataflow path", node
                )
                continue
            cross = len({item.method for item in source.path}) > 1
            evidence = [item.record() for item in source.path]
            identity = stable_id(
                "privacy_flow",
                source.category,
                evidence,
                state["conditions"],
                sorted(set(endpoints)),
            )
            if identity in self.flows:
                continue
            evidence_ids = [item["id"] for item in evidence]
            group = evidence_path_key(source.category, evidence_ids, endpoints)
            variants = self.flow_groups.get(group, [])
            if len(variants) >= MAX_FLOW_VARIANTS:
                self.gap("Dataflow condition-variant budget exceeded", node)
                continue
            if len(self.flows) >= min(MAX_FLOWS, self.limits.max_results):
                if variants:
                    self.gap(
                        "Dataflow condition variants truncated by the result budget",
                        node,
                    )
                    continue
                if not self.variant_groups:
                    self.gap("Dataflow result budget exceeded", node)
                    continue
                donor, donor_node = next(iter(self.variant_groups.items()))
                donor_variants = self.flow_groups[donor]
                del self.flows[donor_variants.pop()]
                if len(donor_variants) == 1:
                    del self.variant_groups[donor]
                self.gap(
                    "Dataflow condition variants truncated by the result budget",
                    donor_node,
                )
            self.flows[identity] = {
                "id": identity,
                "type": "privacy_transmission_path",
                "evidence_level": "E4" if cross else "E3",
                "data_category": source.category,
                "relation": "static_possible_dataflow",
                "evidence_ids": evidence_ids,
                "evidence": evidence,
                "conditions": list(state["conditions"]),
                "sink": {
                    "kind": "network",
                    "endpoint_status": "resolved_candidate"
                    if endpoints
                    else "unresolved",
                    "endpoints": list(dict.fromkeys(endpoints)),
                },
                "meaning": "Modeled static source-to-network path; entry reachability, authorization and actual transmission are unverified",
            }
            variants.append(identity)
            self.flow_groups[group] = variants
            if len(variants) > 1:
                self.variant_groups.setdefault(group, node)

    def logical_arguments(self, signature, registers, static, node):
        try:
            _, _, parameters, _ = descriptor(signature)
        except ValueError:
            self.gap("Invalid method descriptor", node)
            return None
        expected = (0 if static else 1) + sum(
            2 if kind in {"J", "D"} else 1 for kind in parameters
        )
        if len(registers) != expected:
            self.gap("Invocation register count does not match its descriptor", node)
            return None
        offset = 0 if static else 1
        arguments = []
        for kind in parameters:
            arguments.append(registers[offset])
            offset += 2 if kind in {"J", "D"} else 1
        return arguments

    def external(self, signature, raw, static, state, node, stack):
        arguments = self.logical_arguments(signature, raw, static, node)
        if arguments is None:
            return EMPTY
        receiver = EMPTY if static else raw[0]
        owner, name, parameters, result_type = descriptor(signature)
        values = [self.read(value, state) for value in arguments]
        node = Node(
            node.artifact,
            node.entry,
            node.method,
            node.offset,
            node.kind,
            node.target,
            tuple(
                (index, value.constants[0])
                for index, value in enumerate(arguments)
                if len(value.constants) == 1
            ),
        )
        data = self.join(*values)
        current = self.read(receiver, state)
        if signature in SOURCE_METHODS:
            source = self.source(SOURCE_METHODS[signature], node)
            return (
                self.allocate(state, result_type, node, source)
                if result_type == "Ljava/util/Map;"
                else source
            )
        if signature in AUDIO_READS:
            length = (
                arguments[1]
                if parameters[0] == "Ljava/nio/ByteBuffer;"
                else arguments[2]
            )
            if length.constants == (0,):
                return Value(constants=(0,))
            self.attach(arguments[0], self.source("audio_capture", node), state)
            return EMPTY
        if signature == SCREEN_SURFACE:
            surface = arguments[5]
            captured = self.source("screen_capture", node)
            self.attach(surface, captured, state)
            for obj in self.objects(surface, state):
                self.attach(obj.get("parent", EMPTY), captured, state)
            return EMPTY
        if (
            signature
            == "Landroid/provider/Settings$Secure;->getString(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;"
        ):
            if arguments[1].constants == ("android_id",):
                return self.source("device_identifier", node)
            self.gap(
                "Settings key is unresolved or outside the modeled identifier", node
            )
            return EMPTY
        if signature in TRANSFORMS:
            return self.snapshot(self.join(current, data), node)
        if owner == "Ljavax/crypto/Cipher;" and name in {"init", "getInstance"}:
            return EMPTY
        if (
            owner in {"Ljava/security/MessageDigest;", "Ljavax/crypto/Cipher;"}
            and name == "update"
            and parameters
            and parameters[0] == "[B"
        ):
            self.attach(receiver, self.advance(values[0], node), state)
            return EMPTY
        if (
            owner in {"Ljava/security/MessageDigest;", "Ljavax/crypto/Cipher;"}
            and name in {"digest", "doFinal"}
            and not parameters
        ):
            return self.snapshot(current, node)
        if owner in {"Ljava/lang/StringBuilder;", "Ljava/lang/StringBuffer;"}:
            if name in {"<init>", "append"}:
                self.attach(receiver, self.snapshot(data, node), state)
                for obj in self.objects(receiver, state):
                    previous = obj.get("text", ("",))
                    incoming = arguments[0].constants if arguments else ("",)
                    if name == "<init>":
                        previous = ("",)
                        if parameters == ["I"]:
                            incoming = ("",)
                    if len(previous) == 1 and len(incoming) == 1:
                        text = str(previous[0]) + str(incoming[0])
                        obj["text"] = (
                            (text,) if len(text) <= MAX_CONSTANT_LENGTH else ()
                        )
                        if not obj["text"]:
                            self.gap("Constructed string budget exceeded", node)
                    else:
                        obj["text"] = ()
                return receiver
            if name == "toString" and not parameters:
                result = self.snapshot(current, node)
                candidates = {
                    text
                    for obj in self.objects(receiver, state)
                    for text in obj.get("text", ())
                }
                return Value(
                    result.sources,
                    constants=tuple(candidates) if len(candidates) == 1 else (),
                )
        if owner == "Ljava/lang/String;" and name in {
            "<init>",
            "concat",
            "valueOf",
            "format",
        }:
            converted = self.snapshot(self.join(current, data), node)
            if name == "<init>":
                self.attach(receiver, converted, state)
                return EMPTY
            return converted
        if owner in {
            "Lorg/json/JSONObject;",
            "Lorg/json/JSONArray;",
            "Ljava/util/Map;",
            "Ljava/util/HashMap;",
            "Ljava/util/LinkedHashMap;",
            "Landroid/os/Bundle;",
        }:
            if (
                name in {"put", "putString", "putByteArray", "putParcelable", "putAll"}
                and values
            ):
                key = arguments[0].constants if len(arguments) > 1 else ()
                value = self.advance(
                    arguments[-1] if len(arguments) > 1 else data, node
                )
                for obj in self.objects(receiver, state):
                    if key:
                        self.store_slot(obj["fields"], key[0], value, node)
                    else:
                        self.store_slot(
                            obj["fields"],
                            "*",
                            self.join(obj["fields"].get("*", EMPTY), value),
                            node,
                        )
                        self.gap("Collection key is unresolved", node)
                return receiver if result_type.startswith("Lorg/json/") else EMPTY
            if name in {"get", "getString", "opt", "optString"} and arguments:
                key = arguments[0].constants
                selected = []
                for obj in self.objects(receiver, state):
                    selected.append(obj["value"])
                    selected.extend(
                        [
                            obj["fields"].get(key[0], EMPTY),
                            obj["fields"].get("*", EMPTY),
                        ]
                        if key
                        else obj["fields"].values()
                    )
                return self.advance(self.join(*selected, Value(receiver.sources)), node)
            if name == "toString" and not parameters:
                return self.snapshot(current, node)
            if (
                owner
                in {
                    "Ljava/util/Map;",
                    "Ljava/util/HashMap;",
                    "Ljava/util/LinkedHashMap;",
                }
                and name == "entrySet"
                and result_type == "Ljava/util/Set;"
                and not parameters
            ):
                view = self.allocate(state, result_type, node)
                for obj in self.objects(view, state):
                    obj["map_values"] = receiver
                    obj["map_steps"] = (node,)
                return view
            if name == "<init>":
                self.attach(receiver, self.advance(data, node), state)
                return EMPTY
        if signature == "Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;":
            selected = []
            for obj in self.objects(receiver, state):
                if "map_values" in obj:
                    value = self.read(obj["map_values"], state)
                    for step in obj["map_steps"]:
                        value = self.snapshot(value, step)
                    selected.append(value)
            if not selected:
                self.gap("Map entry value has no modeled backing map", node)
            return self.snapshot(self.join(*selected), node)
        if (
            owner
            in {"Ljava/util/Set;", "Ljava/util/Collection;", "Ljava/util/Iterator;"}
            and (name, result_type)
            in {
                ("iterator", "Ljava/util/Iterator;"),
                ("next", "Ljava/lang/Object;"),
            }
            and not parameters
        ):
            views = [
                obj for obj in self.objects(receiver, state) if "map_values" in obj
            ]
            if views:
                result = self.allocate(state, result_type, node)
                for obj in self.objects(result, state):
                    obj["map_values"] = self.join(
                        *(view["map_values"] for view in views)
                    )
                    obj["map_steps"] = (*views[0]["map_steps"], node)
                return result
        if owner in {
            "Ljava/util/List;",
            "Ljava/util/ArrayList;",
            "Ljava/util/Collection;",
            "Ljava/util/Iterator;",
        }:
            if name in {"add", "addAll", "set"} and arguments:
                for obj in self.objects(receiver, state):
                    if name == "add" and len(arguments) == 1:
                        self.store_slot(
                            obj["elements"],
                            len(obj["elements"]),
                            self.advance(arguments[0], node),
                            node,
                        )
                    elif (
                        name == "set"
                        and len(arguments) == 2
                        and len(arguments[0].constants) == 1
                    ):
                        self.store_slot(
                            obj["elements"],
                            arguments[0].constants[0],
                            self.advance(arguments[1], node),
                            node,
                        )
                    else:
                        self.attach(receiver, self.snapshot(data, node), state)
                        self.gap(
                            "Collection mutation has unresolved element positions", node
                        )
                return EMPTY
            if name == "get" and arguments:
                selected = []
                for obj in self.objects(receiver, state):
                    selected.extend(
                        [obj["elements"].get(arguments[0].constants[0], EMPTY)]
                        if len(arguments[0].constants) == 1
                        else obj["elements"].values()
                    )
                return self.advance(self.join(Value(receiver.sources), *selected), node)
            if name in {"iterator", "next", "toArray"}:
                return self.advance(current, node)
            if name in {"<init>", "size", "hasNext"}:
                return EMPTY
        if owner in {
            "Landroid/app/usage/UsageStats;",
            "Landroid/app/usage/UsageEvents$Event;",
            "Landroid/app/usage/NetworkStats$Bucket;",
            "Landroid/content/pm/Signature;",
        } and name in {
            "getPackageName",
            "getTotalTimeInForeground",
            "getRxBytes",
            "getTxBytes",
            "getUid",
            "toByteArray",
            "toCharsString",
            "hashCode",
        }:
            return self.advance(current, node)
        if signature in {
            "Landroid/app/usage/UsageEvents;->getNextEvent(Landroid/app/usage/UsageEvents$Event;)Z",
            "Landroid/app/usage/NetworkStats;->getNextBucket(Landroid/app/usage/NetworkStats$Bucket;)Z",
        }:
            self.attach(arguments[0], self.advance(current, node), state)
            return EMPTY
        if owner == "Landroid/media/MediaRecorder;":
            if name == "setOutputFile" and parameters == ["Ljava/lang/String;"]:
                for obj in self.objects(receiver, state):
                    obj["file"] = arguments[0].constants
            elif name == "setAudioSource" and parameters == ["I"]:
                self.attach(receiver, self.source("audio_capture", node), state)
            elif name == "getSurface" and not parameters:
                surface = self.allocate(state, "Landroid/view/Surface;", node)
                for obj in self.objects(surface, state):
                    obj["parent"] = receiver
                return surface
            elif name == "start" and not parameters:
                for obj in self.objects(receiver, state):
                    for path in obj.get("file", ()):
                        state["files"][path] = self.snapshot(current, node)
            elif name in {"setOutputFile", "getSurface", "setAudioSource", "start"}:
                self.gap("Recorder overload or file destination is unresolved", node)
            elif signature in {
                "Landroid/media/MediaRecorder;->reset()V",
                "Landroid/media/MediaRecorder;->release()V",
            }:
                for obj in self.objects(receiver, state):
                    obj["value"] = EMPTY
                    obj.pop("file", None)
            elif signature not in {
                "Landroid/media/MediaRecorder;-><init>()V",
                "Landroid/media/MediaRecorder;-><init>(Landroid/content/Context;)V",
                "Landroid/media/MediaRecorder;->setVideoSource(I)V",
                "Landroid/media/MediaRecorder;->setOutputFormat(I)V",
                "Landroid/media/MediaRecorder;->setVideoEncoder(I)V",
                "Landroid/media/MediaRecorder;->setAudioEncoder(I)V",
                "Landroid/media/MediaRecorder;->setVideoSize(II)V",
                "Landroid/media/MediaRecorder;->setVideoFrameRate(I)V",
                "Landroid/media/MediaRecorder;->setVideoEncodingBitRate(I)V",
                "Landroid/media/MediaRecorder;->setAudioEncodingBitRate(I)V",
                "Landroid/media/MediaRecorder;->setAudioSamplingRate(I)V",
                "Landroid/media/MediaRecorder;->setAudioChannels(I)V",
                "Landroid/media/MediaRecorder;->prepare()V",
                "Landroid/media/MediaRecorder;->stop()V",
            }:
                self.gap("Unmodeled recorder invocation", node)
            return EMPTY
        if (
            owner
            in {
                "Ljava/io/File;",
                "Ljava/io/FileInputStream;",
                "Ljava/io/FileOutputStream;",
            }
            and name == "<init>"
        ):
            supported = parameters in (
                ["Ljava/lang/String;"],
                ["Ljava/io/File;"],
            ) or (
                owner == "Ljava/io/FileOutputStream;"
                and parameters
                in (
                    ["Ljava/lang/String;", "Z"],
                    ["Ljava/io/File;", "Z"],
                )
            )
            if not supported:
                self.gap("File constructor destination is unresolved", node)
                return EMPTY
            for obj in self.objects(receiver, state):
                obj["file"] = arguments[0].constants if arguments else ()
                for source_obj in (
                    self.objects(arguments[0], state) if arguments else []
                ):
                    obj["file"] = source_obj.get("file", ())
                if owner == "Ljava/io/FileOutputStream;":
                    append = arguments[1].constants if len(arguments) > 1 else (0,)
                    if append == (0,):
                        for path in obj["file"]:
                            state["files"][path] = EMPTY
                    elif append != (1,):
                        self.gap("File append mode is unresolved", node)
            return EMPTY
        if owner == "Ljava/io/File;" and name in {"getPath", "getAbsolutePath"}:
            paths = {
                path
                for obj in self.objects(receiver, state)
                for path in obj.get("file", ())
            }
            return Value(constants=tuple(paths)) if len(paths) == 1 else EMPTY
        if owner == "Ljava/io/File;" and name == "delete" and not parameters:
            self.gap(
                "File deletion success and retention require branch or runtime verification",
                node,
            )
            return EMPTY
        if owner == "Ljava/io/FileInputStream;" and name == "close" and not parameters:
            for obj in self.objects(receiver, state):
                obj["closed"] = True
            return EMPTY
        if owner == "Ljava/io/FileInputStream;" and name in {"read", "readAllBytes"}:
            if any(obj.get("closed") for obj in self.objects(receiver, state)):
                self.gap("Closed input stream cannot read on this normal path", node)
                return EMPTY
            if len(arguments) >= 3 and arguments[2].constants == (0,):
                return Value(constants=(0,))
            content = self.join(
                *(
                    state["files"].get(path, EMPTY)
                    for obj in self.objects(receiver, state)
                    for path in obj.get("file", ())
                )
            )
            if not content.sources:
                self.gap(
                    "File content has no resolved write in this analysis context", node
                )
            if arguments and parameters[0] == "[B":
                self.attach(
                    arguments[0], self.advance(content, node), state, replace=True
                )
                return EMPTY
            return self.advance(content, node) if name == "readAllBytes" else EMPTY
        if (
            owner == "Ljava/net/URL;"
            and name == "<init>"
            and parameters == ["Ljava/lang/String;"]
        ):
            endpoints = self.endpoint_literals(
                arguments[0].constants, node, schemes=URL_SCHEMES
            )
            for obj in self.objects(receiver, state):
                obj["endpoint"] = endpoints
                obj["fields"]["request_url"] = self.snapshot(values[0], node)
            return EMPTY
        if signature in {
            "Ljava/net/URL;->openConnection()Ljava/net/URLConnection;",
            "Ljava/net/URL;->openConnection(Ljava/net/Proxy;)Ljava/net/URLConnection;",
        }:
            connection = self.allocate(
                state, "Ljava/net/URLConnection;", node, self.snapshot(current, node)
            )
            for obj in self.objects(connection, state):
                obj["endpoint"] = self.endpoint_literals(
                    (
                        path
                        for source_obj in self.objects(receiver, state)
                        for path in source_obj.get("endpoint", ())
                    ),
                    node,
                    schemes=URL_SCHEMES,
                )
                schemes = {urlsplit(path).scheme.lower() for path in obj["endpoint"]}
                obj["network"] = bool(schemes & NETWORK_URL_SCHEMES)
                obj["output_enabled"] = False
                if not schemes:
                    self.gap(
                        "URL connection protocol and endpoint are unresolved", node
                    )
            return connection
        if (
            owner
            in {
                "Ljava/net/URLConnection;",
                "Ljava/net/HttpURLConnection;",
                "Ljavax/net/ssl/HttpsURLConnection;",
            }
            and name == "setDoOutput"
            and parameters == ["Z"]
        ):
            for obj in self.objects(receiver, state):
                obj["output_enabled"] = (
                    bool(arguments[0].constants[0])
                    if len(arguments[0].constants) == 1
                    else None
                )
            return EMPTY
        if (
            owner
            in {
                "Ljava/net/URLConnection;",
                "Ljava/net/HttpURLConnection;",
                "Ljavax/net/ssl/HttpsURLConnection;",
                "Ljava/net/Socket;",
            }
            and name == "getOutputStream"
            and not parameters
        ):
            if any(
                obj.get("output_enabled") is False
                for obj in self.objects(receiver, state)
            ):
                self.gap("Connection output is disabled on this normal path", node)
                return EMPTY
            stream = self.allocate(
                state, "Ljava/io/OutputStream;", node, self.snapshot(current, node)
            )
            for obj in self.objects(stream, state):
                obj["network"] = owner != "Ljava/net/URLConnection;" or any(
                    parent.get("network") for parent in self.objects(receiver, state)
                )
                obj["endpoint"] = tuple(
                    path
                    for source_obj in self.objects(receiver, state)
                    for path in source_obj.get("endpoint", ())
                )
            return stream
        if (
            owner
            in {
                "Ljava/net/URLConnection;",
                "Ljava/net/HttpURLConnection;",
                "Ljavax/net/ssl/HttpsURLConnection;",
            }
            and name in {"connect", "getInputStream", "getContent"}
            and not parameters
        ):
            objects = self.objects(receiver, state)
            if owner != "Ljava/net/URLConnection;" or any(
                obj.get("network") for obj in objects
            ):
                self.emit(
                    current,
                    node,
                    state,
                    tuple(path for obj in objects for path in obj.get("endpoint", ())),
                )
            else:
                self.gap("Connection destination is unresolved or non-network", node)
            return EMPTY
        if owner in {
            "Ljava/io/OutputStream;",
            "Ljava/io/DataOutputStream;",
            "Ljava/io/BufferedOutputStream;",
            "Ljava/util/zip/GZIPOutputStream;",
            "Ljava/io/ByteArrayOutputStream;",
            "Ljava/io/FileOutputStream;",
            "Ljava/io/OutputStreamWriter;",
            "Ljava/io/Writer;",
        }:
            objects = self.objects(receiver, state)
            if name == "close" and not parameters:
                for obj in self.stream_objects(receiver, state):
                    if obj["type"] != "Ljava/io/ByteArrayOutputStream;":
                        obj["closed"] = True
                return EMPTY
            if name == "flush" and not parameters:
                return EMPTY
            if name == "<init>" and arguments:
                for obj in objects:
                    obj["delegate"] = arguments[0]
                    obj["network"] = any(
                        parent.get("network")
                        for parent in self.objects(arguments[0], state)
                    )
                    obj["endpoint"] = tuple(
                        path
                        for parent in self.objects(arguments[0], state)
                        for path in parent.get("endpoint", ())
                    )
                    obj["file"] = tuple(
                        path
                        for parent in self.objects(arguments[0], state)
                        for path in parent.get("file", ())
                    )
                return EMPTY
            if name in {"write", "writeBytes", "writeUTF", "append"} and parameters:
                if any(
                    obj.get("closed") for obj in self.stream_objects(receiver, state)
                ):
                    self.gap(
                        "Closed output stream cannot transmit on this normal path", node
                    )
                    return EMPTY
                if len(arguments) >= 3 and arguments[2].constants == (0,):
                    return EMPTY
                content = self.snapshot(values[0], node)
                if any(obj.get("network") for obj in objects):
                    self.emit(
                        self.join(content, current),
                        node,
                        state,
                        tuple(
                            path for obj in objects for path in obj.get("endpoint", ())
                        ),
                    )
                elif any(obj.get("file") for obj in objects):
                    for obj in objects:
                        for path in obj.get("file", ()):
                            state["files"][path] = self.join(
                                state["files"].get(path, EMPTY), content
                            )
                else:
                    self.attach(receiver, content, state)
                    if not objects:
                        self.gap("Output stream destination is unresolved", node)
                return receiver if name == "append" else EMPTY
            if name in {"toByteArray", "toString"}:
                return self.snapshot(current, node)
        if (
            owner == "Lokhttp3/RequestBody;"
            and name == "create"
            and result_type == "Lokhttp3/RequestBody;"
        ):
            return self.snapshot(data, node)
        if owner == "Lokhttp3/Request$Builder;":
            if name == "url" and parameters == ["Ljava/lang/String;"]:
                endpoints = self.endpoint_literals(
                    arguments[0].constants, node, schemes=HTTP_URL_SCHEMES
                )
                for obj in self.objects(receiver, state):
                    obj["endpoint"] = endpoints
                    obj["fields"]["request_url"] = self.snapshot(values[0], node)
                return receiver
            if name in {"header", "addHeader"} and len(arguments) == 2:
                for obj in self.objects(receiver, state):
                    key = arguments[0].constants
                    self.store_slot(
                        obj["fields"],
                        "header:" + str(key[0]) if key else "header:*",
                        self.snapshot(values[1], node),
                        node,
                    )
                return receiver
            if name in {"post", "put", "patch", "method"}:
                self.attach(
                    receiver,
                    self.advance(values[-1] if values else EMPTY, node),
                    state,
                    replace=True,
                )
                return receiver
            if name == "build" and not parameters:
                request = self.allocate(
                    state, "Lokhttp3/Request;", node, self.snapshot(current, node)
                )
                for obj in self.objects(request, state):
                    obj["endpoint"] = tuple(
                        path
                        for parent in self.objects(receiver, state)
                        for path in parent.get("endpoint", ())
                    )
                return request
            if name in {"<init>", "url", "header", "addHeader", "get", "delete"}:
                if name in {"get", "delete"}:
                    self.attach(receiver, EMPTY, state, replace=True)
                return receiver
        if (
            signature
            == "Lokhttp3/OkHttpClient;->newCall(Lokhttp3/Request;)Lokhttp3/Call;"
        ):
            call = self.allocate(
                state, "Lokhttp3/Call;", node, self.snapshot(data, node)
            )
            for obj in self.objects(call, state):
                obj["endpoint"] = tuple(
                    path
                    for parent in self.objects(arguments[0], state)
                    for path in parent.get("endpoint", ())
                )
            return call
        if owner == "Lokhttp3/Call;" and name in {"execute", "enqueue"}:
            self.emit(
                current,
                node,
                state,
                tuple(
                    path
                    for obj in self.objects(receiver, state)
                    for path in obj.get("endpoint", ())
                ),
            )
            return EMPTY
        if signature in {
            "Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z",
            "Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V",
            "Ljava/lang/Thread;->start()V",
        }:
            target = arguments[0] if arguments else receiver
            if signature.endswith("->start()V"):
                targets = [
                    obj.get("runnable", receiver)
                    for obj in self.objects(receiver, state)
                ]
                target = self.join(*targets)
            resolved = False
            for obj in self.objects(target, state):
                body = self.lookup(obj["type"] + "->run()V")
                if body:
                    resolved = True
                    scheduled = copy.deepcopy(state)
                    scheduled["conditions"].append(
                        "Scheduled callback execution is a static possibility, not an observed event"
                    )
                    self.execute(body, [target], scheduled, (*stack, node.method))
            if not resolved:
                self.gap("Asynchronous callback target is unresolved", node)
            return EMPTY
        if signature == "Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;)V":
            for obj in self.objects(receiver, state):
                obj["runnable"] = arguments[0]
            return EMPTY
        if signature == "Ljava/lang/Object;-><init>()V":
            return EMPTY
        if owner in BOUNDARY_OWNERS:
            self.gap("Unresolved boundary: " + BOUNDARY_OWNERS[owner], node)
        else:
            self.gap("Unmodeled external invocation", node)
        for argument in raw:
            for obj in self.objects(argument, state):
                obj["fields"].clear()
                obj["elements"].clear()
                obj["value"] = EMPTY
                obj.pop("map_values", None)
                obj.pop("map_steps", None)
        return EMPTY

    def cache_method(self, identity, method):
        pending = [method]
        size = 0
        items = 0
        while pending:
            if items % METHOD_CACHE_CHECK_ITEMS == 0:
                self.budget.check()
            value = pending.pop()
            items += 1
            size += sys.getsizeof(value)
            if size > MAX_METHOD_CACHE_BYTES:
                return
            if isinstance(value, dict):
                pending.extend(value.keys())
                pending.extend(value.values())
            elif isinstance(value, (list, tuple)):
                pending.extend(value)
        while self.method_cache and (
            len(self.method_cache) >= MAX_METHOD_CACHE_ENTRIES
            or self.method_cache_bytes + size > MAX_METHOD_CACHE_BYTES
        ):
            _, (_, removed) = self.method_cache.popitem(last=False)
            self.method_cache_bytes -= removed
        self.method_cache[identity] = (method, size)
        self.method_cache_bytes += size

    def lookup(self, signature, *, cache=True):
        self.budget.check()
        records = self.index.get(signature, [])
        if len(records) != 1 or signature in self.ambiguous:
            return None
        position, identity = records[0]
        if hasattr(self.methods, "page"):
            cached = self.method_cache.get(identity)
            if cached is not None:
                self.method_cache.move_to_end(identity)
                return cached[0]
            method = next(self.methods.page(identity=identity))
            if cache:
                self.cache_method(identity, method)
            return method
        return self.methods[position]

    def branch(self, op, values):
        if any(len(value.constants) != 1 for value in values):
            return None
        left = values[0].constants[0]
        right = values[1].constants[0] if len(values) > 1 else 0
        if not isinstance(left, int) or not isinstance(right, int):
            return None
        comparison = (op - 50) % 6
        return (
            left == right,
            left != right,
            left < right,
            left >= right,
            left > right,
            left <= right,
        )[comparison]

    def arithmetic(self, item, values, node):
        value = self.advance(self.join(*values), node)
        constants = [
            part.constants[0] if len(part.constants) == 1 else None for part in values
        ]
        if "literal" in item:
            constants.append(item["literal"])
        if not all(isinstance(part, int) for part in constants):
            return Value(value.sources)
        opcode = item["opcode"]
        if 176 <= opcode <= 207:
            opcode -= 32
        if 208 <= opcode <= 215:
            opcode = 144 + opcode - 208
        elif 216 <= opcode <= 226:
            opcode = 144 + opcode - 216
        width = 64 if 155 <= opcode <= 165 else 32
        operation = opcode - (155 if width == 64 else 144)
        if len(constants) == 2 and operation in range(11):
            left, right = constants
            if item["opcode"] in {209, 217}:
                left, right = right, left
            if operation in {3, 4} and not right:
                self.gap("Arithmetic exception terminates the normal path", node)
                return None
            shift = right & (width - 1)
            quotient = (
                (abs(left) // abs(right)) * (-1 if (left < 0) != (right < 0) else 1)
                if operation in {3, 4}
                else 0
            )
            result = (
                left + right
                if operation == 0
                else left - right
                if operation == 1
                else left * right
                if operation == 2
                else quotient
                if operation == 3
                else left - quotient * right
                if operation == 4
                else left & right
                if operation == 5
                else left | right
                if operation == 6
                else left ^ right
                if operation == 7
                else left << shift
                if operation == 8
                else left >> shift
                if operation == 9
                else (left & ((1 << width) - 1)) >> shift
            )
            result &= (1 << width) - 1
            if result & (1 << (width - 1)):
                result -= 1 << width
            return Value(value.sources, constants=(result,))
        return Value(value.sources)

    def execute(self, method, arguments, parent, stack=()):
        self.budget.check()
        if len(stack) >= MAX_CALL_DEPTH or method["signature"] in stack:
            self.gap("Call depth or recursion budget exceeded")
            return []
        if method.get("gap") or not method.get("instructions"):
            self.gap(
                method.get("gap", "Native, abstract or missing method implementation"),
                self.node(method, {"offset": 0, "opcode": 0}),
            )
            return []
        instructions = {
            item["offset"]: item
            for item in method["instructions"]
            if not item.get("payload")
        }
        registers = method["registers"]
        if registers > MAX_REGISTERS:
            self.gap(
                "Method register budget exceeded",
                self.node(method, {"offset": 0, "opcode": 0}),
            )
            return []
        if method["parameters"] > registers or len(arguments) != method["parameters"]:
            self.gap("Method parameter register count is invalid")
            return []
        state = copy.deepcopy(parent)
        regs = [EMPTY] * registers
        regs[registers - len(arguments) :] = arguments
        pending = deque([(0, regs, EMPTY, state)])
        returns = []
        visited = 0
        while pending:
            self.budget.check()
            position, regs, result, state = pending.popleft()
            visited += 1
            if visited > MAX_METHOD_STATES:
                self.gap("Method path-state budget exceeded")
                break
            path_positions = set()
            while position in instructions:
                self.steps += 1
                if self.steps % 64 == 0:
                    self.budget.check()
                if self.steps > MAX_APP_STEPS:
                    raise BudgetExceeded("Application dataflow step budget exceeded")
                self.root_steps += 1
                if self.root_steps > MAX_ROOT_STEPS:
                    self.gap(
                        "Candidate-root dataflow step budget exceeded",
                        self.node(method, instructions[position]),
                    )
                    raise RootBudgetExceeded(
                        "Candidate-root dataflow step budget exceeded"
                    )
                item = instructions[position]
                node = self.node(method, item)
                if position in path_positions:
                    self.gap(
                        "Loop requires additional iterations beyond the modeled path",
                        node,
                    )
                    break
                path_positions.add(position)
                op = item["opcode"]
                ids = item.get("regs", [])
                if any(index >= len(regs) for index in ids) or (
                    "dest" in item and item["dest"] >= len(regs)
                ):
                    self.gap("Instruction register is outside its method", node)
                    break
                values = [regs[index] for index in ids]
                if item.get("unsupported"):
                    self.gap(item["unsupported"], node)
                    break
                if op not in {
                    0,
                    1,
                    4,
                    7,
                    10,
                    11,
                    12,
                    13,
                    14,
                    15,
                    16,
                    17,
                    18,
                    19,
                    20,
                    21,
                    22,
                    23,
                    24,
                    25,
                    26,
                    27,
                    28,
                    40,
                    41,
                    42,
                    45,
                    46,
                    47,
                    48,
                    49,
                }:
                    for region in method.get("handlers", []):
                        if region["start"] <= position < region["end"]:
                            for target in region["targets"]:
                                if len(pending) < MAX_METHOD_STATES:
                                    failure = copy.deepcopy(state)
                                    failure["conditions"].append(
                                        f"Exception edge at {method['signature']}:{position}"
                                    )
                                    pending.append((target, list(regs), EMPTY, failure))
                                else:
                                    self.gap(
                                        "Exception path-state budget exceeded", node
                                    )
                if op in {1, 2, 3, 4, 5, 6, 7, 8, 9}:
                    regs[item["dest"]] = values[0]
                elif op in {10, 11, 12}:
                    regs[item["dest"]] = result
                    result = EMPTY
                elif op == 13:
                    regs[item["dest"]] = EMPTY
                elif op in {14, 15, 16, 17}:
                    returns.append(
                        (self.advance(values[0], node) if values else EMPTY, state)
                    )
                    break
                elif 18 <= op <= 27:
                    constant = item["value"]
                    regs[item["dest"]] = (
                        Value(constants=(constant,))
                        if not isinstance(constant, str)
                        or len(constant) <= MAX_CONSTANT_LENGTH
                        else EMPTY
                    )
                    if (
                        isinstance(constant, str)
                        and len(constant) > MAX_CONSTANT_LENGTH
                    ):
                        self.gap("Constant propagation string budget exceeded", node)
                elif op in {28, 34, 35}:
                    regs[item["dest"]] = self.allocate(
                        state, item.get("type", "Ljava/lang/Class;"), node
                    )
                elif op in {36, 37}:
                    result = self.allocate(state, item["type"], node)
                    for obj in self.objects(result, state):
                        obj["elements"] = dict(enumerate(values))
                elif op in {29, 30, 31}:
                    pass
                elif op == 32 or op == 33:
                    regs[item["dest"]] = EMPTY
                elif op == 39:
                    break
                elif op in {40, 41, 42}:
                    if item["target"] not in instructions:
                        self.gap("Invalid branch target", node)
                        break
                    position = item["target"]
                    continue
                elif 45 <= op <= 49:
                    if op >= 47 and any(index + 1 >= registers for index in ids):
                        self.gap("Wide comparison register is outside its method", node)
                        break
                    compared = self.snapshot(
                        self.join(*(self.read(value, state) for value in values)), node
                    )
                    regs[item["dest"]] = Value(compared.sources)
                elif 50 <= op <= 61:
                    decision = self.branch(op, values)
                    if item["target"] not in instructions:
                        self.gap("Invalid conditional branch target", node)
                        break
                    if decision is None:
                        if len(pending) >= MAX_METHOD_STATES:
                            self.gap("Branch path-state budget exceeded", node)
                            break
                        taken = copy.deepcopy(state)
                        taken["conditions"].append(
                            f"Branch taken at {method['signature']}:{position}"
                        )
                        pending.append((item["target"], list(regs), EMPTY, taken))
                        state["conditions"].append(
                            f"Branch not taken at {method['signature']}:{position}"
                        )
                    elif decision:
                        position = item["target"]
                        continue
                elif 68 <= op <= 81:
                    index = values[2].constants
                    key = index[0] if len(index) == 1 else "*"
                    if op <= 74:
                        selected = []
                        for obj in self.objects(values[1], state):
                            selected.extend(
                                [
                                    obj["elements"].get(key, EMPTY),
                                    obj["elements"].get("*", EMPTY),
                                ]
                                if key != "*"
                                else obj["elements"].values()
                            )
                        regs[ids[0]] = self.advance(
                            self.join(*selected, Value(values[1].sources)), node
                        )
                    else:
                        for obj in self.objects(values[1], state):
                            value = self.advance(values[0], node)
                            self.store_slot(
                                obj["elements"],
                                key,
                                self.join(obj["elements"].get(key, EMPTY), value)
                                if key == "*"
                                else value,
                                node,
                            )
                            if key == "*":
                                self.gap("Array index is unresolved", node)
                elif 82 <= op <= 109:
                    field = item["field"]
                    if op <= 88:
                        selected = [
                            obj["fields"].get(field, EMPTY)
                            for obj in self.objects(values[1], state)
                        ]
                        regs[ids[0]] = self.advance(
                            self.join(*selected, Value(values[1].sources)), node
                        )
                    elif op <= 95:
                        for obj in self.objects(values[1], state):
                            self.store_slot(
                                obj["fields"],
                                field,
                                self.advance(values[0], node),
                                node,
                            )
                    elif op <= 102:
                        regs[ids[0]] = self.advance(
                            state["statics"].get(field, EMPTY), node
                        )
                    else:
                        state["statics"][field] = self.advance(values[0], node)
                elif 110 <= op <= 114 or 116 <= op <= 120:
                    target = item["target"]
                    body = self.lookup(target)
                    if not item["static"] and values:
                        tails = target.split("->", 1)[1]
                        concrete = {
                            obj["type"] + "->" + tails
                            for obj in self.objects(values[0], state)
                        }
                        resolved = [self.lookup(signature) for signature in concrete]
                        if len(resolved) == 1 and resolved[0] is not None:
                            body = resolved[0]
                    if body:
                        outcomes = self.execute(
                            body, values, state, (*stack, method["signature"])
                        )
                        if not outcomes:
                            break
                        else:
                            for returned, alternative in outcomes[
                                1 : MAX_METHOD_STATES - len(pending)
                            ]:
                                pending.append(
                                    (item["next"], list(regs), returned, alternative)
                                )
                            result, state = outcomes[0]
                    else:
                        if (
                            len(self.index.get(target, ())) > 1
                            or target in self.ambiguous
                        ):
                            self.gap("Ambiguous duplicate method definition", node)
                            break
                        result = self.external(
                            target, values, item["static"], state, node, stack
                        )
                elif 123 <= op <= 226:
                    calculated = self.arithmetic(
                        item, [self.read(value, state) for value in values], node
                    )
                    if calculated is None:
                        break
                    regs[item["dest"]] = calculated
                elif op != 0:
                    self.gap("Unmodeled instruction semantics", node)
                    break
                position = item["next"]
                if position not in instructions:
                    self.gap("Method path ends without a return", node)
            if len(returns) >= MAX_METHOD_STATES:
                self.gap("Method return-state budget exceeded")
                break
        return returns

    def run(self):
        admission = {}
        definition_artifacts = {}
        try:
            pool = MethodSelection(
                self.limits, self.budget, MAX_APP_METHODS * MAX_CANDIDATE_FACTOR
            )
            for position, method in enumerate(self.methods):
                self.budget.check()
                self.definitions_considered += 1
                roles = set(method.get("candidate_roles", ()))
                targets = list(method.get("call_targets", ()))
                if "candidate_roles" not in method:
                    for item in method.get("instructions", ()):
                        target = item.get("target")
                        if isinstance(target, str) and "->" in target:
                            roles.update(invocation_roles(target))
                            if (
                                target not in targets
                                and len(targets) < MAX_METHOD_TARGETS
                            ):
                                targets.append(target)
                            elif target not in targets:
                                pool.neighbor_truncations += 1
                pool.add(
                    {
                        key: method[key]
                        for key in (
                            "id",
                            "signature",
                            "artifact",
                            "entry",
                            "code_offset",
                        )
                        if key in method
                    }
                    | {
                        "position": position,
                        "definition_order": position,
                        "candidate_roles": sorted(roles),
                        "call_targets": targets,
                        "code_units": method.get(
                            "code_units", len(method.get("instructions", ()))
                        ),
                        "ambiguous_definition": method.get(
                            "ambiguous_definition", False
                        ),
                    }
                )
            methods = [value[0] for value in pool.items.values()]
            for admitted, index in enumerate(
                candidate_order(methods, self.budget, admission)
            ):
                if admitted >= MAX_APP_METHODS:
                    break
                method = methods[index]
                signature = method["signature"]
                self.index.setdefault(signature, []).append(
                    (method["position"], method["id"])
                )
                digest = definition_digest(signature)
                definition_artifacts.setdefault(method.get("artifact"), set()).add(
                    digest
                )
                if (
                    method["ambiguous_definition"]
                    or pool.definitions.counts[digest] > 1
                ):
                    self.ambiguous.add(signature)
            self.index_omitted = self.definitions_considered - sum(
                len(value) for value in self.index.values()
            )
            admission.update(
                candidate_pool_omitted=pool.evicted,
                candidate_metadata_bytes=pool.size_bytes,
                neighbor_truncations=pool.neighbor_truncations,
            )
            if self.index_omitted:
                self.gap("Application method index budget exceeded")
            if (
                admission.get("neighbor_edges_omitted")
                or admission["neighbor_truncations"]
            ):
                self.gap("Application call-neighbor budget exceeded")
            del methods, pool
            if self.definition_summaries is not None:
                source_counts = {
                    definition_digest(signature): 0 for signature in self.index
                }
                for artifact in self.definition_summaries:
                    self.budget.check()
                    inventory = {
                        "artifact": artifact["sha256"],
                        "complete": False,
                        "reason": "Definition inventory is missing or incomplete",
                    }
                    self.definition_inventory.append(inventory)
                    try:
                        summary = artifact.get("definition_summary")
                        if summary is None:
                            counts = artifact.get("definition_counts")
                            summary = definition_summary(
                                counts if counts is not None else {},
                                counts is not None
                                and artifact.get("definition_inventory_complete")
                                is True
                                and not artifact.get("definition_identities_truncated"),
                                self.budget,
                            )
                        if (
                            not isinstance(summary, dict)
                            or summary.get("complete") is not True
                        ):
                            self.interpretation_deferred = True
                            continue
                        inventory.update(complete=True, reason=None)
                        for digest, count in definition_occurrences(
                            summary, source_counts, self.budget
                        ):
                            if not count and digest in definition_artifacts.get(
                                artifact["sha256"], ()
                            ):
                                inventory.update(
                                    complete=False,
                                    reason="Definition identity summary omits a retained candidate definition",
                                )
                                self.interpretation_deferred = True
                            source_counts[digest] = min(
                                2, source_counts[digest] + count
                            )
                    except DefinitionSummaryError as error:
                        inventory.update(complete=False, reason=str(error))
                        self.interpretation_deferred = True
                if any(count == 0 for count in source_counts.values()):
                    self.interpretation_deferred = True
                if self.interpretation_deferred:
                    raise BudgetExceeded(
                        "Artifact definition identity coverage is incomplete; interpretation deferred; inspect definition_inventory by artifact"
                    )
                self.ambiguous.update(
                    signature
                    for signature in self.index
                    if source_counts[definition_digest(signature)] > 1
                )
                del source_counts
            del definition_artifacts
            for signature in self.index:
                self.budget.check()
                method = self.lookup(signature, cache=False)
                if method is None:
                    self.gap("Ambiguous duplicate method definition: " + signature)
                    continue
                self.roots_started += 1
                self.root_steps = 0
                self.active_root = signature
                if method.get("gap") or not method.get("instructions"):
                    self.roots_missing_body += 1
                initial = {"heap": {}, "files": {}, "statics": {}, "conditions": []}
                arguments = [EMPTY] * method["parameters"]
                if arguments and not method["access"] & 8:
                    arguments[0] = self.allocate(
                        initial,
                        signature.split("->", 1)[0],
                        self.node(method, {"offset": 0, "opcode": 0}),
                    )
                try:
                    self.execute(method, arguments, initial)
                    self.completed += 1
                except RootBudgetExceeded:
                    self.roots_truncated += 1
                self.budget.check()
            if not self.index:
                self.gap(
                    "No indexed method definitions are available for dataflow analysis"
                )
            self.budget.check()
        except (Cancelled, MemoryBudgetExceeded):
            raise
        except BudgetExceeded as error:
            self.gap(str(error))
        status = "PARTIAL" if self.gaps else "COMPLETE"
        coverage = [
            stage(
                name,
                status,
                reason="Bounded static model; inspect dataflow gaps and runtime limitations",
                methods=self.completed,
                indexed_methods=len(self.index),
                entry_policy="Bounded source/caller/network neighborhoods and ordinary candidate roots; runtime reachability is unverified",
                definitions_considered=self.definitions_considered,
                index_omitted=self.index_omitted,
                definition_inventory=self.definition_inventory,
                interpretation_deferred=self.interpretation_deferred,
                roots_started=self.roots_started,
                roots_not_started=len(self.index) - self.roots_started,
                roots_locally_truncated=self.roots_truncated,
                roots_missing_body=self.roots_missing_body,
                root_step_limit=MAX_ROOT_STEPS,
                admission=admission,
                gap_occurrences=dict(sorted(self.gap_counts.items())),
                gap_samples_truncated="truncated" in self.gaps,
                steps=self.steps,
                gaps=list(self.gaps.values()),
                model_version=MODEL_VERSION,
            )
            for name in ("method_dataflow_E3", "interprocedural_dataflow_E4")
        ]
        return list(self.flows.values()), coverage


def analyze_dataflow(methods, limits, cancel=None, definition_summaries=None):
    return Analyzer(methods, limits, cancel, definition_summaries).run()
