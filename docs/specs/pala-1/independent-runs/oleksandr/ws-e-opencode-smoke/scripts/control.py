import json
import urllib.request

KEY = "sk-***REDACTED***"
URL = "http://127.0.0.1:11436/v1/chat/completions"

# recover opencode's exact 10-tool array from the captured request
req = open("proxy_req.log", "rb").read()
req = req.replace(b"[REQ] ", b"").replace(b"\n===CONN===\n", b"")
text = req.decode("utf-8", "replace")


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


chats = json_objs_with(text, "messages")
tools = None
for c in chats:
    if c.get("tools"):
        tools = c["tools"]
        break
assert tools, "could not recover opencode tools from request log"
print("recovered opencode tools:", [t.get("function", {}).get("name") for t in tools])

msg = [{"role": "user", "content": "Create a file hello.txt with the line: smoke-run OK. Use the write tool."}]


def ask(tool_subset, label):
    body = {"model": "llama3.1:8b", "messages": msg, "tools": tool_subset, "stream": False}
    data = json.dumps(body).encode()
    r = urllib.request.Request(URL, data=data,
                              headers={"Authorization": "Bearer " + KEY, "Content-Type": "application/json"})
    d = json.loads(urllib.request.urlopen(r, timeout=180).read())
    m = d.get("choices", [{}])[0]
    msgo = m.get("message", {})
    print(f"--- {label} (n_tools={len(tool_subset)}) ---")
    print("  finish_reason:", m.get("finish_reason"))
    print("  has structured tool_calls:", bool(msgo.get("tool_calls")))
    if msgo.get("tool_calls"):
        print("  tool_calls:", json.dumps(msgo["tool_calls"])[:200])
    print("  content:", repr((msgo.get("content") or "")[:160]))


# full 10-tool opencode set
ask(tools, "A: full opencode toolset")
# trimmed to 3 basic tools (by name) if present
basic = [t for t in tools if t.get("function", {}).get("name") in ("write", "read", "bash")]
ask(basic, "B: trimmed 3 tools (write/read/bash)")
# single tool
single = [t for t in tools if t.get("function", {}).get("name") == "write"]
ask(single, "C: single tool (write)")
