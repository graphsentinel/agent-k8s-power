#!/usr/bin/env python3
"""Publication prep (G-7): replaces bearer tokens (JWTs) in evidence/ with `<jwt sha256:XXXXXXXXXXXX>`.

Only TokenRequest response bodies (I2-issue, V3a-mint: lab tokens for team-a/deployer, 600 s, long expired) contained
tokens. The 12-hex sha256 prefix keeps records comparable; the log lists every replaced token by file and prefix.
  lab/redact.py            # dry run
  lab/redact.py --apply
"""
import glob, hashlib, re, sys
RX = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
apply = "--apply" in sys.argv
total = 0
for f in sorted(glob.glob("evidence/**/*", recursive=True)):
    if not f.endswith((".jsonl", ".json", ".txt", ".log")):
        continue
    s = open(f, errors="replace").read()
    hits = RX.findall(s)
    if not hits:
        continue
    total += len(hits)
    for h in hits:
        print(f"{f}\tsha256:{hashlib.sha256(h.encode()).hexdigest()[:12]}")
    if apply:
        open(f, "w").write(RX.sub(lambda m: f"<jwt sha256:{hashlib.sha256(m.group(0).encode()).hexdigest()[:12]}>", s))
print(f"# {'replaced' if apply else 'would replace'} {total} tokens", file=sys.stderr)
