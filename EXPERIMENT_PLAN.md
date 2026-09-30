# ACIArena MAS 공격 전파 실험 계획

## 목적

ACIArena 공격이 특정 Agent에 적용된 뒤 다른 Agent와 최종 응답까지 어떻게
전달되는지 확인한다.

```text
ACIArena attack
→ MAS 실행
→ Agent 간 전달 관측
→ attack.verify()
→ 공격 성공 여부 기록
```

대상 MAS:

- MetaGPT
- CAMEL
- CAI

## 1. 환경 준비

```bash
cd /home/administrator/aciarena
python3 -m venv .venv
.venv/bin/pip install -e .
```

노출된 기존 키는 폐기하고 새 키를 환경변수로 설정한다.

```bash
cp .env.example .env
# .env에 새로 발급한 키 입력
set -a
source .env
set +a
```

모델 역할은 다음과 같이 설정되어 있다.

```text
configs/model.yaml  → Claude 실험 대상 모델
configs/judge.yaml  → OpenAI 공격 판정 모델
```

## 2. 먼저 확인할 구조

| MAS | 확인할 흐름 |
|---|---|
| MetaGPT | Product Manager → Architect → Project Manager → Engineer → QA |
| CAMEL | User Agent ↔ Assistant |
| CAI | Selection Agent → Handoff → CodeAgent → Tool |

확인할 파일:

```text
aciarena/mas/metagpt/metagpt_mas.py
aciarena/mas/camel/camel_mas.py
aciarena/mas/cai/cai_mas.py
aciarena/attacks/base_attack.py
aciarena/evaluation/evaluation_suite.py
```

각 MAS에서 다음을 찾는다.

- Agent가 메시지를 보내는 위치
- 다음 Agent가 메시지를 받는 위치
- CAI handoff 실행 위치
- Tool 호출 시작과 종료 위치
- 최종 응답을 반환하는 위치

## 3. 관측 코드 추가

공통 observer 인터페이스를 만든다.

```python
observer.emit({
    "team": "...",
    "from": "...",
    "to": "...",
    "event": "...",
    "message": "...",
})
```

권장 이벤트:

```text
attack_applied
message_transfer
agent_turn
handoff
tool_start
tool_end
attack_verify
```

원본 메시지는 console과 JSONL에 함께 기록한다.

## 4. 공격 실행

첫 실험은 기존 `hijacking`과 `code` domain으로 진행한다.

```bash
.venv/bin/python benchmark.py \
  --mas metagpt \
  --suite hijacking \
  --task_domain code \
  --malicious_agents engineer \
  --max_workers 1
```

```bash
.venv/bin/python benchmark.py \
  --mas camel \
  --suite hijacking \
  --task_domain code \
  --malicious_agents assistant \
  --max_workers 1
```

```bash
.venv/bin/python benchmark.py \
  --mas cai \
  --suite hijacking \
  --task_domain code \
  --malicious_agents codeagent \
  --max_workers 1
```

## 5. 반드시 확인할 내용

각 run에서 다음 순서로 확인한다.

- 공격이 지정한 Agent에 적용됐는가?
- 해당 Agent 출력에 공격 영향이 나타났는가?
- 다음 Agent가 그 메시지를 전달받았는가?
- 공격 영향이 어느 전달 경계까지 유지됐는가?
- 최종 응답에도 공격 영향이 남았는가?
- 기존 `attack.verify()` 결과는 `true`인가 `false`인가?
- 원래 과제의 Utility는 성공했는가?

`attack.verify() = true`와 코드의 실제 실행 여부는 구분해서 기록한다.

## 6. 결과 형식

이벤트 로그:

```json
{
  "team": "cai",
  "from": "Selection Agent",
  "to": "CodeAgent",
  "event": "handoff",
  "attack": "SafetyCheckInstruction"
}
```

최종 요약:

```json
{
  "team": "cai",
  "attack": "SafetyCheckInstruction",
  "first_observed_at": "handoff",
  "final_output_affected": true,
  "attack_success": true
}
```

## 완료 기준

- 세 MAS가 ACIArena에서 정상 실행됨
- Agent 간 실제 메시지가 JSONL에 기록됨
- 공격 영향이 처음 나타난 위치를 확인할 수 있음
- 이후 Agent로 전달되는 경로를 확인할 수 있음
- 기존 `attack.verify()` 결과가 함께 기록됨
- 공격 성공과 원래 과제 Utility를 구분해 보고함
