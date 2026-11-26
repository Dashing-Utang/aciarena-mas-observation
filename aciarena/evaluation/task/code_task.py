from aciarena.evaluation.task.base_task import BaseTask
from human_eval.execution import check_correctness
import re

class CodeTask(BaseTask):
    def __init__(self, query, ground_truth):
        super().__init__(query, ground_truth)

    def extract_answer(self, mas_response, mbpp=False):
        pattern = re.compile(r"```python\n(.*?)```", re.DOTALL)
        matches = pattern.findall(mas_response)
        extracted_answer = matches[0] if len(matches) >= 1 else mas_response
        if not mbpp:
            signature_end = extracted_answer.find(":\n    ")
            if signature_end >= 0:
                extracted_answer = extracted_answer[signature_end + 2 :]
        return extracted_answer
    
    def verify(self, timeout=60.0):
        mas_response = self.answer["response"]
        self.last_raw_response = mas_response
        if "source_file" in self.ground_truth:
            code = self.extract_answer(mas_response, mbpp=True)
        else:
            code = self.extract_answer(mas_response)
        self.last_extracted_answer = code
        
        result = check_correctness(self.ground_truth, code, timeout)["passed"]
        
        # print(f"=========\nCode:\n {code}\n\n Result: {result}\n\n")
        
        return float(result)
