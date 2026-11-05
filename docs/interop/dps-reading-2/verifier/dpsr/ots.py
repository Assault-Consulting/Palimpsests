"""A strict reader and replay of an OpenTimestamps proof (.ots), written without any OpenTimestamps software.

What each rule rests on:
- operation tags sha256 0x08, append 0xf0, prepend 0xf1, and the Bitcoin attestation tag 0588960d73d71901:
  draft-fassbender-scitt-time-anchor-08, Table 4 and section 4.1 step 4.
- limits (shortest varints of at most nine bytes, argument and result of at most 4096 bytes, attestation
  payload of at most 8192, at most 256 nested timestamps, the same operation or attestation twice at one
  point refused, nothing after the proof, a height a report can carry): anchoring 0.2.0, "An OpenTimestamps
  proof as a timestamp", "The check".
- the byte-level grammar neither draft revision states (-08 sections 4.1 and 7.2.1, -03 sections 1.4 and 1.5:
  "OTS-DESERIALIZE, whose input format this profile does not specify"): the 31-byte magic, the version as a
  varint, the varint as unsigned LEB128, a length-prefixed argument, 0xff before each branch but the last
  of a fork, 0x00 before an attestation, an 8-byte attestation tag then a length-prefixed payload, and the
  pending tag 83dfe30d2ef90c8e. These are applied from knowledge of the OpenTimestamps format, checked
  against the bytes of draft -08 Appendix D.5 and the operation trace of Appendix D.4 (ambiguity log A01).
"""
import hashlib

MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
TAG_BITCOIN = bytes.fromhex("0588960d73d71901")
TAG_PENDING = bytes.fromhex("83dfe30d2ef90c8e")
OPS_UNARY = {0x08: ("sha256", 32), 0x02: ("sha1", 20), 0x03: ("ripemd160", 20), 0x67: ("keccak256", 32),
             0xf2: ("reverse", None), 0xf3: ("hexlify", None)}
OPS_BINARY = {0xf0: "append", 0xf1: "prepend"}
MAX_ARG = 4096
MAX_RESULT = 4096
MAX_PAYLOAD = 8192
MAX_DEPTH = 256
MAX_SAFE = 2 ** 53 - 1


class ProofError(ValueError):
    pass


def read_varint(b, i, where="varint"):
    """Unsigned LEB128, at most nine bytes, in its shortest form."""
    val = 0
    shift = 0
    n = 0
    while True:
        if i >= len(b):
            raise ProofError("%s truncated" % where)
        if n == 9:
            raise ProofError("%s longer than 9 bytes, over the limit of 9" % where)
        c = b[i]
        i += 1
        n += 1
        val |= (c & 0x7f) << shift
        shift += 7
        if not c & 0x80:
            break
    if n > 1 and c == 0:
        raise ProofError("%s not in its shortest form" % where)
    return val, i


class Node:
    __slots__ = ("ops", "atts")

    def __init__(self):
        self.ops = []   # (tag, name, arg, child Node)
        self.atts = []  # (tag8, payload)


class Reader:
    def __init__(self, data):
        self.b = data
        self.i = 0

    def byte(self):
        if self.i >= len(self.b):
            raise ProofError("proof truncated")
        c = self.b[self.i]
        self.i += 1
        return c

    def take(self, n):
        if self.i + n > len(self.b):
            raise ProofError("proof truncated")
        out = self.b[self.i:self.i + n]
        self.i += n
        return out

    def varbytes(self, limit, what):
        n, self.i = read_varint(self.b, self.i, what + " length")
        if n > limit:
            raise ProofError("%s of %d bytes, over the limit of %d" % (what, n, limit))
        return self.take(n)

    def timestamp(self, msg_len, depth):
        if depth > MAX_DEPTH:
            raise ProofError("timestamps nested deeper than 256")
        node = Node()
        tag = self.byte()
        while tag == 0xff:
            self.item(node, self.byte(), msg_len, depth)
            tag = self.byte()
        self.item(node, tag, msg_len, depth)
        return node

    def item(self, node, tag, msg_len, depth):
        if tag == 0x00:
            t8 = self.take(8)
            payload = self.varbytes(MAX_PAYLOAD, "attestation payload")
            if (t8, payload) in node.atts:
                raise ProofError("the same attestation twice at one point")
            node.atts.append((t8, payload))
            return
        if tag in OPS_BINARY:
            arg = self.varbytes(MAX_ARG, "argument")
            new_len = msg_len + len(arg)
            if new_len > MAX_RESULT:
                raise ProofError("%s result of %d bytes, over the limit of 4096" % (OPS_BINARY[tag], new_len))
            name = OPS_BINARY[tag]
        elif tag in OPS_UNARY:
            name, size = OPS_UNARY[tag]
            arg = b""
            if size is not None:
                new_len = size
            elif name == "reverse":
                new_len = msg_len
            else:
                new_len = msg_len * 2
                if new_len > MAX_RESULT:
                    raise ProofError("hexlify result of %d bytes, over the limit of 4096" % new_len)
        else:
            raise ProofError("unknown operation tag 0x%02x" % tag)
        for (t, _n, a, _c) in node.ops:
            if t == tag and a == arg:
                raise ProofError("the same operation twice at one point (%s)" % name)
        child = self.timestamp(new_len, depth + 1)
        node.ops.append((tag, name, arg, child))


def parse(data):
    """Returns (file_hash_op, file_digest, root Node). Raises ProofError with the reason."""
    if not data.startswith(MAGIC):
        raise ProofError("magic differs")
    r = Reader(data)
    r.i = len(MAGIC)
    version, r.i = read_varint(data, r.i, "version")
    if version != 1:
        raise ProofError("version %d, not 1" % version)
    op = r.byte()
    if op != 0x08:
        name = OPS_UNARY.get(op, ("0x%02x" % op,))[0]
        raise ProofError("file hash operation is %s, not sha256" % name)
    digest = r.take(32)
    root = r.timestamp(32, 1)
    if r.i != len(data):
        raise ProofError("%d bytes after the proof" % (len(data) - r.i))
    return "sha256", digest, root


def replay(root, start):
    """Walk every path; for each attestation return a dict with the digest reached (None when an operation
    on the path is not sha256, append or prepend) and the operations on the way."""
    out = []

    def walk(node, msg, path, unsupported):
        for (t8, payload) in node.atts:
            out.append({"tag": t8, "payload": payload, "digest": None if unsupported else msg,
                        "unsupported": list(unsupported), "path": list(path)})
        for (tag, name, arg, child) in node.ops:
            uns = list(unsupported)
            m = msg
            if not uns:
                if name == "sha256":
                    m = hashlib.sha256(msg).digest()
                elif name == "append":
                    m = msg + arg
                elif name == "prepend":
                    m = arg + msg
                else:
                    uns.append(name)
                    m = None
            path.append((name, arg))
            walk(child, m, path, uns)
            path.pop()

    walk(root, start, [], [])
    return out


def bitcoin_height(payload):
    """The height of a Bitcoin attestation: a varint in its shortest form, at most nine bytes, that a report
    can carry as an integer (at most 2^53 - 1), and nothing after it in the payload."""
    h, i = read_varint(payload, 0, "height varint")
    if i != len(payload):
        raise ProofError("bytes after the height in the attestation payload")
    if h > MAX_SAFE:
        raise ProofError("height %d is beyond what a report can carry (2^53 - 1)" % h)
    return h


def count_nodes(root):
    n = 0
    stack = [root]
    while stack:
        x = stack.pop()
        n += len(x.ops)
        stack.extend(c for (_t, _n, _a, c) in x.ops)
    return n
