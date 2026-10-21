"""Compile actual captured memory replacements and check values/effect prefixes.

Usage: python tests/verify_mba_d810_memory.py CAPTURE.json ... --output REPORT.json
Captures use the review.json schema (functions/captures/profile/text). Historical
capture files are inputs and are never modified. Native effect-frame checking is
separate: this oracle exercises the emitted C arithmetic and observable accesses.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("captures", nargs="+", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cxx", default=os.environ.get("CXX"))
    args = parser.parse_args()
    compiler = args.cxx or "c++"
    functions = []
    inputs = []
    for capture in args.captures:
        raw = capture.read_bytes()
        inputs.append({"name": capture.name, "sha256": hashlib.sha256(raw).hexdigest()})
        for row in json.loads(raw)["functions"]:
            if row["name"] not in ("test_chained_add", "test_cst_simplification"):
                continue
            for profile, result in row["captures"].items():
                if profile not in ("normal", "deep"):
                    continue
                text = result["text"]
                if "mba_load" not in text:
                    raise RuntimeError("Required ordered-read replacement is absent")
                name = "captured_" + str(len(functions))
                text = text.replace("__fastcall", "").replace("unsigned __int32", "uint32_t")
                text = text.replace("__int64", "int64_t").replace("_DWORD", "uint32_t")
                text = re.sub(r"\b" + re.escape(row["name"]) + r"\b", name, text)
                text = re.sub(r"//[^\n]*", "", text)
                read_order = []
                store_order = []
                lines = []
                for line in text.splitlines():
                    read = re.fullmatch(r"\s*(mba_load\d+) = (?:\*a1|a1\[(\d+)\]);\s*", line)
                    store = re.fullmatch(r"\s*a1\[(\d+)\] = (.*);\s*", line)
                    if read:
                        index = int(read[2] or 0)
                        read_order.append(index)
                        line = f"  {read[1]} = observe_read(a1, {index});"
                    elif store:
                        index = int(store[1])
                        store_order.append(index)
                        line = f"  observe_store(a1, {index}, {store[2]});"
                    lines.append(line)
                expected_reads = 6 if row["name"] == "test_chained_add" else 7
                if len(read_order) != expected_reads:
                    raise RuntimeError("Original read multiplicity was not preserved")
                if store_order != ([] if expected_reads == 6 else [1, 2, 3, 4]):
                    raise RuntimeError("Original stores were not preserved")
                functions.append(
                    {
                        "name": name,
                        "kind": int(expected_reads == 7),
                        "source": "\n".join(lines),
                        "profile": profile,
                        "reads": read_order,
                        "stores": store_order,
                    }
                )
    if not functions:
        raise RuntimeError("No captured memory fixtures")
    source = r"""
#include <array>
#include <cstdint>
#include <vector>
#include <stdexcept>
#include <cstdio>
struct Event { bool store; unsigned index; uint32_t value;
 bool operator==(const Event &b) const { return store==b.store && index==b.index && value==b.value; }};
std::vector<Event> events;
int fault, observed;
void before() { if (observed++ == fault) throw 1; }
uint32_t observe_read(uint32_t *p, unsigned i) { before();events.push_back({false,i,p[i]});return p[i]; }
void observe_store(uint32_t *p,unsigned i,uint32_t v) { before();events.push_back({true,i,v});p[i]=v; }
uint64_t original(uint32_t *p, bool chain, const std::vector<unsigned> &reads) {
 if (!chain) {
  // Reads remain in the exact order independently checked by the SDK frame.
  for (unsigned i:reads) observe_read(p,i);
  return uint32_t(2u*p[1]+51u);
 }
 // Evaluate the original unsigned MBA circuit between its retained effects.
 uint32_t x=observe_read(p,reads[0]),y=observe_read(p,reads[1]);
 uint32_t v5=((x&1u)|0x222E69C2u)-((y&1u)|2u);observe_store(p,1,v5);
 x=observe_read(p,reads[2]);y=observe_read(p,reads[3]);
 uint32_t v4=((x&0x50211120u)^0x50295930u)+((y&0x50211120u)|0x83020001u);observe_store(p,2,v4);
 x=observe_read(p,reads[4]);y=observe_read(p,reads[5]);
 uint32_t v3=(((x&0x10500855u)|0x2009500u)+((~y&0x10500855u)|0x5204000u))^0x15482637u;observe_store(p,3,v3);
 x=observe_read(p,reads[6]);uint32_t v2=(((x+4u-(v3|4u))&0x7FFFFCu)>>2)|0xA29u;observe_store(p,4,v2);
 return uint32_t(v2+v3+v4+v5);
}
"""
    source += "\n".join(f["source"] for f in functions)
    source += "\nint main() { uint64_t random=0xA3564E27u; unsigned checks=0;\n"
    for f in functions:
        reads = ",".join(map(str, f["reads"]))
        source += f"""
 for (unsigned sample=0;sample<256;++sample) {{
  std::array<uint32_t,5> input;
  for (auto &v:input) {{random=random*6364136223846793005ull+1;v=uint32_t(random>>17);}}
  for (fault=-1;fault<12;++fault) {{
   auto a=input,b=input;uint64_t va=0,vb=0;bool fa=false,fb=false;
   events.clear();observed=0;try{{va=original(a.data(),{f["kind"]},{{{reads}}});}}catch(int){{fa=true;}}
   auto expected=events;events.clear();observed=0;try{{vb={f["name"]}(b.data());}}catch(int){{fb=true;}}
   if(fa!=fb || a!=b || expected!=events || (!fa && va!=vb)) {{
    std::fprintf(stderr,"Mismatch {f["name"]} sample=%u fault=%d\\n",sample,fault);return 1;}}
   ++checks;
  }}
 }}
"""
    source += 'std::printf("checks=%u\\n",checks);return 0;}\n'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=args.output.parent) as directory:
        directory = Path(directory)
        cpp, binary = directory / "oracle.cpp", directory / "oracle"
        cpp.write_text(source)
        subprocess.run(
            [
                compiler,
                "-std=c++17",
                "-O1",
                "-fsanitize=undefined",
                "-fno-sanitize-recover=undefined",
                str(cpp),
                "-o",
                str(binary),
            ],
            check=True,
        )
        result = subprocess.run([str(binary)], capture_output=True, text=True, check=True)
    report = {
        "inputs": inputs,
        "functions": len(functions),
        "ubsan": True,
        "oracle_source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "result": result.stdout.strip(),
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
