import json
import urllib.request

KEY = "sk-***REDACTED***"
URL = "http://127.0.0.1:11436/v1/chat/completions"

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
exact = None
for c in chats:
    if c.get("tools"):
        exact = c
        break

# characterize opencode's system prompt (the suspected trigger)
sysmsgs = [m for m in exact["messages"] if m.get("role") == "system"]
syslen = sum(len(m.get("content", "")) for m in sysmsgs)
print("opencode request: n_tools=%d, n_messages=%d, system_prompt_chars=%d"
      % (len(exact["tools"]), len(exact["messages"]), syslen))
sc = (sysmsgs[0]["content"] if sysmsgs else "")
print("system prompt head:", repr(sc[:220]))

# replay VERBATIM (only force non-streaming for clean parse)
body = dict(exact)
body["stream"] = False
data = json.dumps(body).encode()
r = urllib.request.Request(URL, data=data,
                          headers={"Authorization": "Bearer " + KEY, "Content-Type": "application/json"})
d = json.loads(urllib.request.urlopen(r, timeout=180).read())
m = d.get("choices", [{}])[0]
msgo = m.get("message", {})
print("=== REPLAY of opencode's EXACT request (verbatim) ===")
print("  finish_reason:", m.get("finish_reason"))
print("  has structured tool_calls:", bool(msgo.get("tool_calls")))
print("  content:", repr((msgo.get("content") or "")[:220]))
