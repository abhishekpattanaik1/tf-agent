"""
blast_radius.py - deterministic dependency graph and blast radius from a Terraform plan JSON.

For every resource being destroyed or replaced, it answers "what else is affected?"
by walking the reverse dependency graph. No LLM involved, and no attribute VALUES are
read or returned: only addresses, types and the kind of edge.

Edges come from three places in `terraform show -json` output:
  * configuration   expression `references`, `depends_on`, count/for_each, module inputs
                    (var.*), module outputs (module.X.out), and provider configs: e.g. a
                    `databricks` provider whose `host` references the Azure workspace makes
                    EVERY databricks_* resource depend on that workspace.
  * prior_state     `depends_on` recorded by Terraform for existing resources. This also
                    covers references made through `local.*`, which the plan JSON's
                    configuration section does not include.

Nodes are config addresses (instance keys stripped): module.net["a"].azurerm_subnet.x[0]
becomes module.net.azurerm_subnet.x. Dependents outside Terraform (e.g. jobs created by
hand that use existing_cluster_id) are invisible here; the report says so.
"""
import re
from collections import defaultdict, deque

_KEY_RE = re.compile(r'\[(?:"(?:[^"\\]|\\.)*"|[^\]]*)\]')
_MODULE_PREFIX_RE = re.compile(r"^(module\.[^.]+\.)*")
_SKIP_HEADS = {"each", "count", "path", "terraform", "self", "local"}  # local.* is not in plan JSON

MAX_LISTED = 15


def strip_keys(address: str) -> str:
    """module.a["x"].aws_s3_bucket.b[0] -> module.a.aws_s3_bucket.b"""
    return _KEY_RE.sub("", address)


def is_data(node: str) -> bool:
    return _MODULE_PREFIX_RE.sub("", node).startswith("data.")


def node_type(node: str) -> str:
    rel = _MODULE_PREFIX_RE.sub("", node).split(".")
    return rel[1] if rel[0] == "data" and len(rel) > 1 else rel[0]


def _refs(obj):
    """All reference strings anywhere under an expressions object. Within one list, Terraform
    emits both `module.x.out` and `module.x` (or `aws_y.z.id` and `aws_y.z`); the shorter one is
    redundant, and resolving a bare `module.x` would wrongly pull in every output."""
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "references" and isinstance(v, list):
                refs = [r for r in v if isinstance(r, str)]
                out.extend(r for r in refs if not any(o != r and o.startswith(r + ".") for o in refs))
            else:
                out.extend(_refs(v))
    elif isinstance(obj, list):
        for v in obj:
            out.extend(_refs(v))
    return out


class Graph:
    def __init__(self):
        self.nodes = set()
        self.deps = defaultdict(dict)  # node -> {dependency: edge kind}
        self.sources = []

    def add_edge(self, node, dep, kind):
        if node != dep and dep not in self.deps[node]:
            self.deps[node][dep] = kind

    def dependents_index(self):
        rev = defaultdict(dict)
        for node, deps in self.deps.items():
            for dep, kind in deps.items():
                rev[dep].setdefault(node, kind)
        return rev


# --------------------------------------------------------------------------- configuration
def _index_modules(root_cfg):
    """prefix -> {cfg, parent, call}. Root prefix is ''; children look like 'module.net.'."""
    mods = {}

    def walk(cfg, prefix, parent, call):
        mods[prefix] = {"cfg": cfg or {}, "parent": parent, "call": call or {}}
        for name, child_call in (cfg or {}).get("module_calls", {}).items():
            walk(child_call.get("module", {}), f"{prefix}module.{name}.", prefix, child_call)

    walk(root_cfg, "", None, None)
    return mods


def _add_config_edges(g: Graph, configuration: dict):
    mods = _index_modules(configuration.get("root_module", {}))
    resources = {}  # node -> (prefix, resource cfg)
    for prefix, m in mods.items():
        for r in m["cfg"].get("resources", []):
            node = prefix + r["address"]
            resources[node] = (prefix, r)
            g.nodes.add(node)

    memo = {}

    def resolve(ref, prefix, stack=frozenset(), dep=False):
        """dep=True: a depends_on entry, where a bare `module.x` means every resource in it.
        Otherwise a bare `module.x` in an expression means the module's outputs."""
        key = (ref, prefix, dep)
        if key in memo:
            return memo[key]
        if key in stack:  # cycle through module outputs / vars
            return set()
        stack = stack | {key}
        parts = strip_keys(ref).split(".")
        head, out = parts[0], set()
        if head in _SKIP_HEADS or not head:
            pass
        elif head == "var":
            m = mods.get(prefix)
            if m and m["parent"] is not None and len(parts) > 1:
                for r in _refs(m["call"].get("expressions", {}).get(parts[1], {})):
                    out |= resolve(r, m["parent"], stack)
        elif head == "module" and len(parts) > 1:
            child = f"{prefix}module.{parts[1]}."
            cm = mods.get(child)
            if cm is not None:
                if len(parts) == 2 and dep:  # depends_on = [module.x]
                    out = {n for n in g.nodes if n.startswith(child)}
                else:
                    names = [parts[2]] if len(parts) > 2 else list(cm["cfg"].get("outputs", {}))
                    for name in names:
                        o = cm["cfg"].get("outputs", {}).get(name, {})
                        for r in _refs(o.get("expression", {})):
                            out |= resolve(r, child, stack)
                        for r in o.get("depends_on", []) or []:
                            out |= resolve(r, child, stack, dep=True)
        elif head == "data" and len(parts) > 2:
            out = {f"{prefix}data.{parts[1]}.{parts[2]}"}
        elif len(parts) > 1:
            out = {f"{prefix}{parts[0]}.{parts[1]}"}
        memo[key] = out
        return out

    # module-level count/for_each/depends_on apply to every resource inside (and below)
    module_deps = {}

    def deps_of_module(prefix):
        if prefix in module_deps:
            return module_deps[prefix]
        m = mods[prefix]
        found = set()
        if m["parent"] is not None:
            call = m["call"]
            refs = _refs(call.get("count_expression", {})) + _refs(call.get("for_each_expression", {}))
            for r in refs:
                found |= resolve(r, m["parent"])
            for r in call.get("depends_on", []) or []:
                found |= resolve(r, m["parent"], dep=True)
            found |= deps_of_module(m["parent"])
        module_deps[prefix] = found
        return found

    # provider configs: provider_config_key -> nodes the provider itself depends on
    provider_deps = {}
    for key, pc in configuration.get("provider_config", {}).items():
        mod_addr = pc.get("module_address", "")
        prefix = f"{mod_addr}." if mod_addr else ""
        found = set()
        for r in _refs(pc.get("expressions", {})):
            found |= resolve(r, prefix)
        provider_deps[key] = found

    for node, (prefix, r) in resources.items():
        refs = _refs(r.get("expressions", {})) + _refs(r.get("count_expression", {})) \
            + _refs(r.get("for_each_expression", {}))
        for ref in refs:
            for dep in resolve(ref, prefix):
                g.add_edge(node, dep, "reference")
        for ref in r.get("depends_on", []) or []:
            for dep in resolve(ref, prefix, dep=True):
                g.add_edge(node, dep, "depends_on")
        for dep in deps_of_module(prefix):
            g.add_edge(node, dep, "module dependency")
        for dep in provider_deps.get(r.get("provider_config_key"), ()):
            g.add_edge(node, dep, "provider config")


# --------------------------------------------------------------------------- prior state
def _state_resources(module):
    for r in (module or {}).get("resources", []):
        yield r
    for child in (module or {}).get("child_modules", []):
        yield from _state_resources(child)


def _add_state_edges(g: Graph, prior_state: dict):
    found = False
    for r in _state_resources(prior_state.get("values", {}).get("root_module")):
        node = strip_keys(r["address"])
        g.nodes.add(node)
        for dep in r.get("depends_on", []) or []:
            g.add_edge(node, strip_keys(dep), "state depends_on")
            found = True
    return found


def build_graph(plan: dict) -> Graph:
    g = Graph()
    if plan.get("configuration", {}).get("root_module"):
        _add_config_edges(g, plan["configuration"])
        g.sources.append("configuration")
    if plan.get("prior_state", {}).get("values", {}).get("root_module"):
        if _add_state_edges(g, plan["prior_state"]):
            g.sources.append("prior_state")
    for rc in plan.get("resource_changes", []):
        g.nodes.add(strip_keys(rc["address"]))
    return g


# --------------------------------------------------------------------------- blast radius
def _plan_actions(plan):
    from tf_risk_scan import classify_action  # local import: avoid a cycle
    acts = defaultdict(set)
    for rc in plan.get("resource_changes", []):
        k = classify_action(rc.get("change", {}).get("actions", []))
        if k != "noop":
            acts[strip_keys(rc["address"])].add(k)
    return acts


def dependents(g: Graph, rev, node):
    """BFS over dependents. Data sources are traversed but not reported, and do not
    count as a hop. Returns {dependent: (depth, edge kind of the first hop)}."""
    seen = {node: (0, None)}
    q = deque([node])
    while q:
        cur = q.popleft()
        depth, via = seen[cur]
        for nxt, kind in sorted(rev.get(cur, {}).items()):
            if nxt in seen:
                continue
            step = 0 if is_data(cur) and cur != node else 1
            seen[nxt] = (depth + step, via or kind)
            q.append(nxt)
    seen.pop(node)
    return {n: v for n, v in seen.items() if not is_data(n)}


def analyse(plan: dict, targets, is_critical=lambda t: False) -> dict:
    """targets: plan addresses (with instance keys) to compute blast radius for.
    Returns {"sources": [...], "by_address": {address: radius}}."""
    g = build_graph(plan)
    rev = g.dependents_index()
    acts = _plan_actions(plan)
    out = {}
    for address in targets:
        node = strip_keys(address)
        deps = dependents(g, rev, node)
        if not deps:
            out[address] = {"total": 0}
            continue
        ordered = sorted(deps, key=lambda n: (deps[n][0], not is_critical(node_type(n)), n))
        by_type = defaultdict(int)
        for n in deps:
            by_type[node_type(n)] += 1
        changing = [{"address": n, "action": "/".join(sorted(acts[n]))} for n in ordered if acts.get(n)]
        out[address] = {
            "total": len(deps),
            "direct": [{"address": n, "via": deps[n][1]} for n in ordered if deps[n][0] == 1][:MAX_LISTED],
            "indirect": [n for n in ordered if deps[n][0] > 1][:MAX_LISTED],
            "critical_dependents": sorted(n for n in deps if is_critical(node_type(n)))[:MAX_LISTED],
            "by_type": dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
            "also_changing": changing[:MAX_LISTED],
        }
    return {"sources": g.sources, "by_address": out}
