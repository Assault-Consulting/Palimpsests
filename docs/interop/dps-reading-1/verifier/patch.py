"""The case patches: set, insert, remove, copy/move (RFC 6902 add semantics at 'to'),
with a value, a value from vectors.json ('vector', a JSON pointer) or a document's
digest ('digest_of')."""
import copy as _copy

def _tokens(ptr):
    if ptr == "":
        return []
    assert ptr.startswith("/"), ptr
    return [t.replace("~1", "/").replace("~0", "~") for t in ptr[1:].split("/")]

def get(doc, ptr):
    cur = doc
    for t in _tokens(ptr):
        cur = cur[int(t)] if isinstance(cur, list) else cur[t]
    return cur

def _parent(doc, ptr):
    toks = _tokens(ptr)
    cur = doc
    for t in toks[:-1]:
        cur = cur[int(t)] if isinstance(cur, list) else cur[t]
    return cur, toks[-1]

def _set(doc, ptr, value):
    if ptr == "":
        return value
    par, last = _parent(doc, ptr)
    if isinstance(par, list):
        i = len(par) if last == "-" else int(last)
        if i == len(par):
            par.append(value)
        else:
            par[i] = value
    else:
        par[last] = value
    return doc

def _insert(doc, ptr, value):
    par, last = _parent(doc, ptr)
    if isinstance(par, list):
        i = len(par) if last == "-" else int(last)
        par.insert(i, value)
    else:
        par[last] = value
    return doc

def _remove(doc, ptr):
    par, last = _parent(doc, ptr)
    if isinstance(par, list):
        return par.pop(int(last))
    return par.pop(last)

def apply(doc, ops, vectors=None, digest_of=None):
    doc = _copy.deepcopy(doc)
    for op in ops:
        if "value" in op:
            val = _copy.deepcopy(op["value"])
        elif "vector" in op:
            val = _copy.deepcopy(get(vectors, op["vector"]))
        elif "digest_of" in op:
            val = digest_of(op["digest_of"])
        else:
            val = None
        if "set" in op:
            doc = _set(doc, op["set"], val)
        elif "insert" in op:
            doc = _insert(doc, op["insert"], val)
        elif "remove" in op:
            _remove(doc, op["remove"])
        elif "copy" in op:
            # replaces the value at 'to' (J03: 'two for attachment 0, none for attachment 1')
            doc = _set(doc, op["to"], _copy.deepcopy(get(doc, op["copy"])))
        elif "move" in op:
            v = _remove(doc, op["move"])
            doc = _insert(doc, op["to"], v)
        else:
            raise ValueError("unknown patch op %r" % op)
    return doc
