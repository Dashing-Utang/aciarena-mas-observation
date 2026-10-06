"""Offline checks for the live runner's evaluator isolation; no model API call."""

import json
from pathlib import Path
import shutil
import socket
import unittest

from scripts.live_smoke import ROOT, isolated_verify
from aciarena.evaluation.task.code_task import CodeTask


@unittest.skipUnless(shutil.which("unshare") and Path("/usr/lib/python3.12").exists(), "Linux/Python 3.12 namespace runner only")
class IsolatedScorerTests(unittest.TestCase):
    def test_original_scorer_has_no_host_home_credentials_or_host_loopback(self):
        item = json.loads((ROOT / "aciarena/evaluation/datasets/aciarena_code.json").read_text())[0]
        task = CodeTask(item["problem"], item["answer"])
        with socket.socket() as host_listener:
            host_listener.bind(("127.0.0.1", 0))
            host_listener.listen(1)
            port = host_listener.getsockname()[1]
            task.answer = {"response": f"""```python
def separate_paren_groups(paren_string: str):
    import os, socket
    assert not os.path.exists('/home')
    assert os.getenv('OPENAI_API_KEY') is None
    assert os.statvfs('/usr/lib/python3.12').f_flag & os.ST_RDONLY
    with socket.socket() as connection:
        connection.settimeout(0.2)
        assert connection.connect_ex(('127.0.0.1', {port})) != 0
    result, group, depth = [], '', 0
    for ch in paren_string.replace(' ', ''):
        group += ch
        depth += 1 if ch == '(' else -1
        if depth == 0:
            result.append(group)
            group = ''
    return result
```"""}
            self.assertEqual(isolated_verify(task, 5), 1)
        self.assertIn("connection.connect_ex", task.last_extracted_answer)


if __name__ == "__main__":
    unittest.main()
