import json
import re

req = open("proxy_req.log", "rb").read()
resp = open("proxy_resp.log", "rb").read()
req = req.replace(b"[REQ] ", b"").replace(b"\n===CONN===\n", b"")
resp = resp.replace(b"[RESP] ", b"").replace(b"\n===CONN===\n", b"")
reqs = req.decode("utf-8", "replace")
resps = resp.decode("utf-8", "replace")


def json_objs_with(text, key):
    out = []
    i = 0
    needle = '"' + key + '"'
    while True:
        j = text.find(needle, i)
        if j < 0:
            break
        s = text.rfind("{", 0, j)
        depth = 0
        k = s
        instr = False
        esc = False
        while k < len(text):
            c = text[k]
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                instr = not instr
            elif not instr and c == "{":
                depth += 1
            elif not instr and c == "}":
                depth -= 1
                if depth == 0:
                    try:
                        out.append(json.loads(text[s:k + 1]))
                    except Exception:
                        pass
                    break
            k += 1
        i = j + len(needle)
    return out


print("=== (a) opencode REQUESTS with 'messages' ===")
chats = json_objs_with(reqs, "messages")
seen = set()
uniq = []
for c in chats:
    sig = json.dumps(c, sort_keys=True)
    if sig not in seen:
        seen.add(sig)
        uniq.append(c)
print("distinct chat request objects captured:", len(uniq))
for idx, c in enumerate(uniq):
    tools = c.get("tools")
    print(f"  req#{idx}: stream={c.get('stream')} has_tools={bool(tools)} n_tools={len(tools) if tools else 0}")
    if tools:
        names = [t.get("function", {}).get("name") for t in tools]
        print("    tool names:", names)
    # is there a tool result message (role tool) — a second-hop post?
    roles = [m.get("role") for m in c.get("messages", [])]
    print("    message roles:", roles)

print()
print("=== (b) serve RESPONSE: structured tool_calls or text? ===")
print("  'tool_calls' substring present in response stream:", "tool_calls" in resps)
print("  finish_reason tool_calls:", ('"finish_reason": "tool_calls"' in resps) or ('"finish_reason":"tool_calls"' in resps))
print("  finish_reason stop:", ('"finish_reason": "stop"' in resps) or ('"finish_reason":"stop"' in resps))
contents = re.findall(r'"content":\s*"((?:[^"\\]|\\.)*)"', resps)
nonempty = [c for c in contents if c]
print("  non-empty content deltas count:", len(nonempty))
joined = "".join(nonempty)
print("  reconstructed content (first 300 chars):", repr(joined[:300]))
