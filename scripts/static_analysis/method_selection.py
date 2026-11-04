import base64
import binascii
import hashlib
import heapq
import sys
from bisect import bisect_left
from collections import defaultdict, deque

from . import dex_ir
from .common import BudgetExceeded

MAX_CANDIDATE_FACTOR = 4
MAX_CANDIDATE_BYTES = 8 * 1024 * 1024
CANDIDATE_SLOT_OVERHEAD_BYTES = 512
MAX_METHOD_TARGETS = 64
MAX_NEIGHBOR_DEPTH = 4
MAX_NEIGHBOR_EDGES = 65536
MAX_DEFINITION_IDENTITIES = 100000
DEFINITION_DIGEST_BYTES = hashlib.sha256().digest_size
SELECTION_SCHEDULE = (4, 4, 3, 4, 2, 3, 4, 1, 0)


def definition_digest(signature):
    return hashlib.sha256(signature.encode()).hexdigest()


class DefinitionSummaryError(BudgetExceeded):
    pass


class DefinitionIndex:
    def __init__(self, limits, budget):
        self.maximum = min(MAX_DEFINITION_IDENTITIES, limits.max_references)
        self.budget = budget
        self.counts = {}
        self.truncated = False

    def add(self, digest, count=1):
        self.budget.check()
        if digest not in self.counts and len(self.counts) >= self.maximum:
            self.truncated = True
            raise BudgetExceeded("Definition identity budget exceeded")
        self.counts[digest] = min(2, self.counts.get(digest, 0) + count)

    def summary(self, complete):
        return definition_summary(
            self.counts, complete and not self.truncated, self.budget
        )


def definition_summary(counts, complete, budget):
    budget.check()
    if not isinstance(counts, dict) or len(counts) > min(
        MAX_DEFINITION_IDENTITIES, budget.limits.max_references
    ):
        raise DefinitionSummaryError(
            "Definition identity summary is invalid; interpretation deferred"
        )
    for digest, count in counts.items() if complete else ():
        budget.check()
        if (
            not isinstance(digest, str)
            or len(digest) != DEFINITION_DIGEST_BYTES * 2
            or any(character not in "0123456789abcdef" for character in digest)
            or type(count) is not int
            or count < 1
        ):
            raise DefinitionSummaryError(
                "Definition identity counts are invalid; interpretation deferred"
            )
    identities = bytearray()
    duplicates = []
    for index, (digest, count) in enumerate(sorted(counts.items()) if complete else ()):
        budget.check()
        identities.extend(bytes.fromhex(digest))
        if count > 1:
            duplicates.append(index)
    return {
        "identities": base64.b64encode(identities).decode("ascii"),
        "duplicates": duplicates,
        "complete": complete,
    }


def definition_occurrences(summary, digests, budget):
    maximum = min(MAX_DEFINITION_IDENTITIES, budget.limits.max_references)
    encoded = summary.get("identities")
    duplicates = summary.get("duplicates")
    maximum_bytes = maximum * DEFINITION_DIGEST_BYTES
    if (
        not isinstance(encoded, str)
        or len(encoded) > (maximum_bytes + 2) // 3 * 4
        or not isinstance(duplicates, list)
        or len(duplicates) > maximum
    ):
        raise DefinitionSummaryError(
            "Definition identity summary is invalid; interpretation deferred"
        )
    try:
        identities = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        raise DefinitionSummaryError(
            "Definition identity summary is invalid; interpretation deferred"
        ) from error
    if len(identities) % DEFINITION_DIGEST_BYTES or len(identities) > maximum_bytes:
        raise DefinitionSummaryError(
            "Definition identity summary is invalid; interpretation deferred"
        )
    count = len(identities) // DEFINITION_DIGEST_BYTES

    def identity_at(index):
        start = index * DEFINITION_DIGEST_BYTES
        return identities[start : start + DEFINITION_DIGEST_BYTES]

    previous = None
    for index in range(count):
        budget.check()
        current = identity_at(index)
        if previous is not None and current <= previous:
            raise DefinitionSummaryError(
                "Definition identity summary is not sorted and unique; interpretation deferred"
            )
        previous = current

    def locate(digest):
        lower, upper = 0, count
        while lower < upper:
            middle = (lower + upper) // 2
            if identity_at(middle) < digest:
                lower = middle + 1
            else:
                upper = middle
        return lower if lower < count and identity_at(lower) == digest else None

    previous = -1
    for index in duplicates:
        budget.check()
        if type(index) is not int or index <= previous or index >= count:
            raise DefinitionSummaryError(
                "Duplicate definition summary is invalid; interpretation deferred"
            )
        previous = index
    for digest in digests:
        budget.check()
        index = locate(bytes.fromhex(digest))
        if index is None:
            yield digest, 0
            continue
        duplicate_index = bisect_left(duplicates, index)
        yield (
            digest,
            2
            if duplicate_index < len(duplicates)
            and duplicates[duplicate_index] == index
            else 1,
        )


def method_tier(method):
    roles = method.get("candidate_roles", ())
    return (
        4
        if any(role.startswith("source:") for role in roles)
        else 2
        if "network" in roles
        else 1
        if "transform" in roles
        else 0
    )


def method_key(method):
    return (
        method.get("artifact", ""),
        method.get("entry", ""),
        method["signature"],
        method.get("code_offset", 0),
    )


def candidate_order(methods, budget, diagnostics=None):
    definitions = defaultdict(list)
    neighbors = defaultdict(set)
    tiers = {}
    for index, method in enumerate(methods):
        budget.check()
        definitions[method["signature"]].append(index)
        tiers[index] = method_tier(method)
    edge_count = 0
    omitted_edges = 0
    for index, method in enumerate(methods):
        budget.check()
        for target in method.get("call_targets", ()):
            matches = definitions.get(target, ())
            if len(matches) == 1:
                other = matches[0]
                if edge_count >= min(MAX_NEIGHBOR_EDGES, budget.limits.max_references):
                    omitted_edges += 1
                    continue
                neighbors[index].add(other)
                neighbors[other].add(index)
                edge_count += 1
    if diagnostics is not None:
        diagnostics["neighbor_edges_omitted"] = omitted_edges
    pending = deque((index, 0) for index, tier in tiers.items() if tier in {4, 2})
    visited = {index for index, _ in pending}
    while pending:
        budget.check()
        index, depth = pending.popleft()
        if depth >= MAX_NEIGHBOR_DEPTH:
            continue
        for other in neighbors[index]:
            if other not in visited:
                visited.add(other)
                tiers[other] = max(tiers[other], 3)
                pending.append((other, depth + 1))
    groups = defaultdict(lambda: defaultdict(list))
    for index, method in enumerate(methods):
        budget.check()
        category = next(
            (
                role
                for role in method.get("candidate_roles", ())
                if role.startswith("source:")
            ),
            "other",
        )
        groups[tiers[index]][
            (category, method.get("artifact", ""), method.get("entry", ""))
        ].append(index)
    queues = {}
    for tier, buckets in groups.items():
        queues[tier] = deque(
            deque(
                sorted(
                    values,
                    key=lambda index: (
                        not bool(
                            methods[index].get(
                                "code_units", methods[index].get("instructions")
                            )
                        ),
                        methods[index].get("code_units", 0),
                        method_key(methods[index]),
                    ),
                )
            )
            for _, values in sorted(buckets.items())
        )
    while any(queues.values()):
        for tier in SELECTION_SCHEDULE:
            budget.check()
            buckets = queues.get(tier)
            if not buckets:
                continue
            bucket = buckets.popleft()
            yield bucket.popleft()
            if bucket:
                buckets.append(bucket)


class MethodSelection:
    def __init__(self, limits, budget, capacity=None):
        self.limits = limits
        self.budget = budget
        self.capacity = (
            capacity
            if capacity is not None
            else min(
                dex_ir.MAX_INDEXED_METHODS * MAX_CANDIDATE_FACTOR, limits.max_results
            )
        )
        self.items = {}
        self.heap = []
        self.size_bytes = 0
        self.considered = 0
        self.evicted = 0
        self.neighbor_truncations = 0
        self.definitions = DefinitionIndex(limits, budget)

    def add(self, method):
        self.budget.check()
        self.considered += 1
        self.definitions.add(definition_digest(method["signature"]))
        key = method_key(method)
        size = CANDIDATE_SLOT_OVERHEAD_BYTES + sum(
            sys.getsizeof(value)
            for value in (
                key,
                method,
                *method.keys(),
                *method.values(),
                *method.get("call_targets", ()),
                *method.get("candidate_roles", ()),
            )
        )
        quality = (
            method_tier(method),
            bool(method.get("code_units")),
            -method.get("code_units", 0),
            key,
        )
        if size > MAX_CANDIDATE_BYTES:
            self.evicted += 1
            return
        if key in self.items:
            return
        while self.items and (
            len(self.items) >= self.capacity
            or self.size_bytes + size > MAX_CANDIDATE_BYTES
        ):
            worst = self.heap[0]
            if quality <= worst[0]:
                self.evicted += 1
                return
            _, removed = heapq.heappop(self.heap)
            _, previous_size = self.items.pop(removed)
            self.size_bytes -= previous_size
            self.evicted += 1
        self.items[key] = (method, size)
        self.size_bytes += size
        heapq.heappush(self.heap, (quality, key))

    def select(self):
        methods = [value[0] for value in self.items.values()]
        selected = []
        omitted = 0
        selected_units = 0
        maximum = min(dex_ir.MAX_INDEXED_METHODS, self.limits.max_results)
        units = min(dex_ir.MAX_ARTIFACT_UNITS, self.limits.max_references)
        diagnostics = {}
        for index in candidate_order(methods, self.budget, diagnostics):
            method = methods[index]
            cost = method.get("code_units", 0)
            if (
                len(selected) >= maximum
                or cost > dex_ir.MAX_METHOD_UNITS
                or selected_units + cost > units
            ):
                omitted += 1
                continue
            selected.append(method)
            if self.definitions.counts[definition_digest(method["signature"])] > 1:
                method["ambiguous_definition"] = True
            selected_units += cost
        selected.sort(key=lambda method: method["definition_order"])
        return selected, {
            "definitions_considered": self.considered,
            "candidate_pool_retained": len(methods),
            "candidate_pool_omitted": self.evicted,
            "candidate_metadata_bytes": self.size_bytes,
            "selected_methods": len(selected),
            "selected_code_units": sum(item.get("code_units", 0) for item in selected),
            "body_budget_omitted": omitted,
            "neighbor_truncations": self.neighbor_truncations,
            **diagnostics,
            "policy": "Bounded source and network neighborhoods with category/DEX rotation and ordinary-method opportunities",
        }
