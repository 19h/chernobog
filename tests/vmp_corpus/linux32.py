"""Pinned-image Linux execution adapter for the host-side protector runner."""
import json
from pathlib import Path
import re
import uuid

from run_vmp_corpus import digest, execute


class Linux32:
    def __init__(self, root, output, image, context):
        self.output = output
        self.docker = ["docker", "--context", context]
        status, out, _ = execute(self.docker + ["image", "inspect", image, "--format", "{{.Id}} {{.Architecture}}"])
        fields = out.decode().split()
        if status["exit_code"] or len(fields) != 2 or not re.fullmatch(r"sha256:[0-9a-f]{64}", fields[0]):
            raise RuntimeError("Linux32 image inventory failed")
        self.image = fields[0]
        self.metadata = {"image_id": self.image, "container_architecture": fields[1],
                         "execution": "qemu-i386 user-mode translation in Linux container"}
        self.mounts = ["--mount", "type=bind,src=" + str(root / "tests") + ",dst=/source,readonly",
                       "--mount", "type=bind,src=" + str(output) + ",dst=/output"]
        (output / "guest-runs").mkdir()
        code = ("import hashlib,json,subprocess; from pathlib import Path; "
                "files=['/usr/bin/i686-linux-gnu-gcc','/usr/bin/i686-linux-gnu-ld','/usr/bin/qemu-i386',"
                "'/usr/i686-linux-gnu/lib/ld-linux.so.2','/usr/i686-linux-gnu/lib/libc.so.6']; "
                "print(json.dumps({'sha256':{Path(p).name:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in files},"
                "'packages':subprocess.check_output(['dpkg-query','-W','gcc-i686-linux-gnu','binutils-i686-linux-gnu',"
                "'libc6-dev-i386-cross','libc6-i386-cross','qemu-user','python3'],text=True).splitlines()}))")
        status, out, _ = self.execute(["python3", "-B", "-c", code])
        if status["exit_code"]:
            raise RuntimeError("Linux32 tool inventory failed")
        self.metadata.update(json.loads(out))

    def execute(self, arguments, timeout=60):
        name = "chernobog-vmp32-" + uuid.uuid4().hex
        result = execute(self.docker + ["run", "--rm", "--name", name, "--network", "none",
                         "--read-only", "--tmpfs", "/tmp:rw,nosuid,size=64m", "--cap-drop", "ALL",
                         "--security-opt", "no-new-privileges", *self.mounts, self.image, *arguments], timeout=timeout)
        if result[0]["exit_code"] or result[0]["timed_out"] or result[0]["output_exceeded"]:
            # A killed Docker client does not imply its container terminated.
            # Remove only the uniquely named container created by this call.
            execute(self.docker + ["rm", "-f", name], timeout=15)
        return result

    def run(self, binary, seed):
        token = binary.name + "-" + str(seed)
        report = "guest-runs/" + token + ".json"
        stdout = "guest-runs/" + token + ".txt"
        launcher, _, _ = self.execute(["python3", "-B", "/source/vmp_corpus/linux32_exec.py",
            "/output/" + binary.name, str(seed), "/output/" + report, "/output/" + stdout], timeout=30)
        if launcher["exit_code"] or launcher["timed_out"] or launcher["output_exceeded"]:
            raise RuntimeError("Linux32 guest observation failed")
        measurement = json.loads((self.output / report).read_text())
        if (not measurement["binary_unchanged"] or measurement["binary_sha256"] != digest(binary)
                or measurement["stdout_sha256"] != digest(self.output / stdout)
                or set(measurement["runtime_sha256"]) != {"qemu-i386", "ld-linux.so.2", "libc.so.6"}
                or any(self.metadata["sha256"][name] != value for name, value in measurement["runtime_sha256"].items())):
            raise RuntimeError("Linux32 guest artifact identity changed")
        measurement["launcher"] = launcher
        measurement["guest_report"] = report
        return measurement, (self.output / stdout).read_bytes(), b""
