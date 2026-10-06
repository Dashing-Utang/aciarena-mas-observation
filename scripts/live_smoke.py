"""Live API smoke with unchanged official CodeTask logic in an isolated process.

No model/Agent completion is mocked or rewritten. Only the official code
evaluation process is placed in fresh user/mount/network/PID namespaces.
"""

import argparse
import hashlib
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Trusted setup. Mounts are private; no project/home/credential mount is exposed.
MOUNT_SETUP = r"""
set -eu
sandbox_root=$1
mount --make-rprivate /
mount -t tmpfs -o size=128m,nosuid,nodev tmpfs "$sandbox_root"
mkdir -p "$sandbox_root/usr/bin" "$sandbox_root/usr/lib/python3.12" "$sandbox_root/usr/lib/x86_64-linux-gnu" "$sandbox_root/work" "$sandbox_root/tmp" "$sandbox_root/dev/shm"
touch "$sandbox_root/usr/bin/python3.12" "$sandbox_root/dev/null"
mount --bind /usr/bin/python3.12 "$sandbox_root/usr/bin/python3.12"
mount -o remount,bind,ro "$sandbox_root/usr/bin/python3.12"
mount --bind /usr/lib/python3.12 "$sandbox_root/usr/lib/python3.12"
mount -o remount,bind,ro "$sandbox_root/usr/lib/python3.12"
mount --bind /usr/lib/x86_64-linux-gnu "$sandbox_root/usr/lib/x86_64-linux-gnu"
mount -o remount,bind,ro "$sandbox_root/usr/lib/x86_64-linux-gnu"
ln -s usr/lib "$sandbox_root/lib"
mkdir "$sandbox_root/lib64"
ln -s /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 "$sandbox_root/lib64/ld-linux-x86-64.so.2"
mount --bind /dev/null "$sandbox_root/dev/null"
chmod 1777 "$sandbox_root/tmp" "$sandbox_root/dev/shm"
cd "$sandbox_root"
exec /usr/sbin/chroot "$sandbox_root" /usr/bin/python3.12 -I -c "$2"
"""

DRIVER = r"""
import ctypes, hashlib, json, os, resource, sys, types
libc=ctypes.CDLL(None, use_errno=True)
if libc.prctl(38, 1, 0, 0, 0) != 0:
    raise RuntimeError('Cannot set no_new_privs')
for capability in range(41):
    libc.prctl(24, capability, 0, 0, 0)
class Header(ctypes.Structure):
    _fields_=[('version',ctypes.c_uint),('pid',ctypes.c_int)]
class Data(ctypes.Structure):
    _fields_=[('effective',ctypes.c_uint),('permitted',ctypes.c_uint),('inheritable',ctypes.c_uint)]
header=Header(0x20080522,0)
data=(Data*2)()
if libc.capset(ctypes.byref(header),ctypes.byref(data)) != 0:
    raise RuntimeError('Cannot drop capabilities')
resource.setrlimit(resource.RLIMIT_AS,(512*1024*1024,512*1024*1024))
resource.setrlimit(resource.RLIMIT_FSIZE,(8*1024*1024,8*1024*1024))
resource.setrlimit(resource.RLIMIT_CPU,(65,65))
resource.setrlimit(resource.RLIMIT_NOFILE,(64,64))
os.chdir('/work')
isolation_checks={'readonly_system':bool(os.statvfs('/usr/lib/python3.12').f_flag & os.ST_RDONLY),
                  'host_home_absent':not os.path.exists('/home'),
                  'credential_env_absent':not any(('KEY' in k or 'TOKEN' in k or 'SECRET' in k) for k in os.environ)}
if not all(isolation_checks.values()):
    raise RuntimeError('Isolation checks failed')
payload=json.load(sys.stdin)
for name in ('aciarena','aciarena.evaluation','aciarena.evaluation.task','human_eval'):
    module=types.ModuleType(name)
    module.__path__=[]
    sys.modules[name]=module
utils=types.ModuleType('aciarena.utils')
utils.build_mas=None
utils.MASLogger=None
sys.modules['aciarena.utils']=utils
for name,source in payload['sources'].items():
    module=types.ModuleType(name)
    sys.modules[name]=module
    exec(compile(source,name,'exec'),module.__dict__)
CodeTask=sys.modules['aciarena.evaluation.task.code_task'].CodeTask
task=CodeTask(payload['query'],payload['ground_truth'])
task.answer={'response':payload['response']}
result=task.verify(timeout=payload['timeout'])
print(json.dumps({'result':result,'official_extracted_answer':task.last_extracted_answer,
                  'isolation_checks':isolation_checks,
                  'source_hashes':{name:hashlib.sha256(src.encode()).hexdigest() for name,src in payload['sources'].items()}}))
"""


def isolated_verify(task, timeout=60.0):
    from human_eval import execution
    from aciarena.evaluation.task import base_task, code_task
    sources = {
        "human_eval.execution": inspect.getsource(execution),
        "aciarena.evaluation.task.base_task": inspect.getsource(base_task),
        "aciarena.evaluation.task.code_task": inspect.getsource(code_task),
    }
    # Text extraction is passive; execute the original verify/extractor module
    # itself inside the isolated namespace, not a replacement scorer.
    task.last_raw_response = task.answer["response"]
    payload = dict(query=task.query, ground_truth=task.ground_truth,
                   response=task.last_raw_response, sources=sources, timeout=timeout)
    with tempfile.TemporaryDirectory(prefix="aciarena_eval_") as sandbox_root:
        command = ["/usr/bin/unshare", "--user", "--map-root-user", "--mount", "--net", "--pid", "--fork",
                   "/bin/bash", "-c", MOUNT_SETUP, "sandbox_setup", sandbox_root, DRIVER]
        result = subprocess.run(command, input=json.dumps(payload), text=True, capture_output=True,
                                timeout=timeout + 20, env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"}, close_fds=True)
    if result.returncode:
        raise RuntimeError("Isolated official evaluator failed: " + result.stderr[-1500:])
    outcome = json.loads(result.stdout.strip())
    for name, source in sources.items():
        if outcome["source_hashes"][name] != hashlib.sha256(source.encode()).hexdigest():
            raise RuntimeError("Official source fingerprint mismatch")
    task.last_extracted_answer = outcome["official_extracted_answer"]
    return outcome["result"]


def preflight():
    # Pure fixture proves the actual original evaluator works in the namespace.
    import benchmark  # dotenv is loaded before importing adapter modules.
    from aciarena.evaluation.task.code_task import CodeTask
    item = json.loads((ROOT / "aciarena/evaluation/datasets/aciarena_code.json").read_text())[0]
    task = CodeTask(item["problem"], item["answer"])
    task.answer = {"response": "```python\ndef separate_paren_groups(paren_string: str):\n    result, group, depth = [], '', 0\n    for ch in paren_string.replace(' ', ''):\n        group += ch\n        depth += 1 if ch == '(' else -1\n        if depth == 0:\n            result.append(group)\n            group = ''\n    return result\n```"}
    if isolated_verify(task, 5) != 1:
        raise RuntimeError("Isolated official evaluator preflight failed")


def main(mas, artifact_dir, preflight_only=False):
    os.chdir(ROOT)
    preflight()
    if preflight_only:
        print(json.dumps({"isolated_official_preflight": "PASS", "live_api_calls": 0}))
        return
    import benchmark
    from aciarena.evaluation.task.code_task import CodeTask
    args = SimpleNamespace(mas=mas, suite="hijacking", attack_mode="continuous", defense="none", task_domain="code",
                           max_workers=1, output_dir=str(Path(artifact_dir) / "console"),
                           malicious_agents=[{"metagpt": "engineer", "camel": "assistant", "cai": "codeagent"}[mas]],
                           task_ids="0", attack_names="SafetyCheckInstruction", repeat=1, trace=True,
                           trace_dir=str(Path(artifact_dir) / "traces"), run_tag="live_nano", model="gpt-5-nano", judge_model="gpt-5-nano",
                           offline_fixture=False, live_api=True, evaluation_isolation="unshare_user_mount_net_pid_readonly_system")
    with patch.object(CodeTask, "verify", isolated_verify):
        benchmark.main(args)
    print(json.dumps({"session_id": args.session_id, "live_api": True, "trace_dir": args.trace_dir}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mas", choices=("metagpt", "camel", "cai"), default="metagpt")
    parser.add_argument("--artifact_dir", default="logs/measurement_v1/live_nano")
    parser.add_argument("--preflight_only", action="store_true")
    options = parser.parse_args()
    try:
        main(options.mas, options.artifact_dir, options.preflight_only)
    except Exception as exc:
        from aciarena.observability.trace import sanitize
        print(json.dumps({'error_type':type(exc).__name__,'message':sanitize(str(exc))}))
        sys.exit(1)
