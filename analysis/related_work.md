# Related Work — 정지 시점 교란과 MAS 공격 평가

작성 2026-10-04 · 검색 기반 1차 정리 · **인용 전 full text 확인 필요한 항목을 표기했다**

검증 상태 표기

| 표기 | 의미 |
|---|---|
| ✅ | abstract 또는 본문을 직접 열어 확인 |
| ◐ | abstract만 확인, 세부(지표 정의 등) 미확인 |
| ⚠ | 검색 스니펫만. **arXiv ID·주장 모두 재확인 필요** |

---

## 0. 포지셔닝 요약

우리 주장을 네 선행 그룹과 대비하면 다음과 같다.

| 선행 연구가 다루는 것 | 우리가 다루는 것 |
|---|---|
| ABC: 평가 결과가 과제 성공을 올바르게 반영하는가 (**outcome validity**) | 그 결과를 **언제** 읽는가 |
| Outcome Finality: 종료 후 지연 효과·run 간 상태 누출 (**cross-unit separation**) | 종료 **시점 자체**가 측정 대상과 상관되는가 |
| Share-Borne: hop 생존률 + 우측 절단(censoring), 절단은 **비정보적**·종료는 **외생적**(고정 예산) | 종료가 **내생적**(에이전트의 과제 완료 판단) → **정보적 절단** |
| 멀티턴 jailbreak: ASR@k = "어느 턴에서든 성공" (단조, 공격자가 정지 결정) | ASR = "**마지막 턴**에서 성공" (비단조, **시스템**이 정지 결정) |

**핵심 차별 주장:** 반복 구조 MAS 벤치마크의 ASR은 **내생적 정지 시점에서의 종단 상태 읽기**이고, 정지 규칙(과제 완료 신호)과 페이로드 존재의 상관이 **아키텍처마다 부호가 다르다.** 따라서 아키텍처 간 ASR 비교가 성립하지 않는다.

우리 측정값 (gpt-5, hijacking/code):

| MAS | ASR = mean(S_마지막) | mean(S_모든 턴) | 상관 부호 |
|---|---|---|---|
| MetaGPT | 0.225 | 0.167 | **양** (QA가 `Bugs Found: None` → 수락과 동시 종료) |
| CAMEL | 0.250 | **0.543** | **음** (`user_proxy`가 깨끗한 답에 `<CAMEL_TASK_DONE>`) |
| CAI | 0.562 | 0.562 | 없음 (턴 1개) |

---

## 1. 대상 벤치마크

| 논문 | 상태 | 핵심 | 우리와의 관계 |
|---|---|---|---|
| **ACIArena: Toward Unified Evaluation for Agent Cascading Injection** — arXiv 2604.07775, **ACL 2026 long (2026.acl-long.457)** | ◐ | MAS 6종 × 공격 목표 3종(hijacking/disruption/disclosure) × 공격 표면 3종(외부 입력/agent profile/inter-agent message), 1,356 테스트 케이스. "토폴로지만으로 MAS 견고성을 평가하는 것은 불충분하다", "단순 환경에서 개발된 방어는 실환경으로 전이되지 않는다" | **연구 대상.** 우리는 이 벤치마크의 ASR·Utility 정의를 감사하고 재계산한다 |

> **반드시 확인할 것 (full text):** ASR·Utility의 정확한 정의, `max_turn` 설정과 반복 루프를 어떻게 다루는지, 종료 규칙에 대한 언급, limitation 절. abstract에는 멀티턴/정지 조건 언급이 **없다**(확인). 우리 주장이 그 공백을 겨냥한다.

관련 벤치마크 (비교군)

| 논문 | 상태 | 비고 |
|---|---|---|
| **TAMAS: Benchmarking Adversarial Risks in Multi-Agent LLM Systems** — arXiv 2511.05269, ACL 2026 long 1442 | ⚠ | 적대 시나리오 300 + benign 100, 5 도메인 × 6 공격 유형. **benign arm을 포함**한다는 점이 ACIArena보다 낫다 — 우리 benign baseline 부재 지적과 연결 |
| **Towards Unifying Quantitative Security Benchmarking for Multi Agent Systems** — arXiv 2507.21146 | ⚠ | MAS 보안 벤치마크 통합 시도. 지표 표준화 논의가 있으면 직접 경쟁 가능 |
| **PIArena: A Platform for Prompt Injection Evaluation** — arXiv 2604.08499 | ⚠ | 프롬프트 인젝션 평가 플랫폼 |

---

## 2. 벤치마크 타당성 — **가장 위험한 경쟁군**

| 논문 | 상태 | 핵심 | 우리와의 관계 |
|---|---|---|---|
| **Establishing Best Practices for Building Rigorous Agentic Benchmarks (ABC)** — arXiv 2507.02825, **NeurIPS 2025 D&B** | ◐ | **Outcome validity**(평가 결과가 과제 성공을 참으로 지시) + **Task validity**(목표 역량이 있을 때만 풀림) 두 축. 과제 설정·보상 설계 결함이 성능을 상대 기준 최대 100% 오추정. **τ-bench가 빈 응답을 성공으로 집계**하는 사례. CVE-Bench에 적용해 과대추정 33% 감소 | **최대 경쟁.** 우리 감사 발견(거부문을 성공으로, 빈 응답 처리)은 사실상 ABC의 outcome validity 위반 **사례**다. 감사만으로는 논문이 되지 않는다는 근거 |
| **Do Agent Benchmarks Measure Capability? Protocol Validity in the Age of Agentic AI** — arXiv 2607.22368 | ✅ | **Protocol validity**: 에이전트가 공개 정답 회수, 평가 artifact 읽기, 생성기 구조 추론, 피드백 조작, 무효 채점 경로 이용. `HackDetect` 사후 감사, `Mislead gap` 지표. Frontier Science 트레이스 67.0%, AutoLab 과제 66.7%에서 노출/보상 해킹 증거 | 보상 해킹 축. **반복 루프 측정 시점·종료 규칙·종단 vs 트래젝토리 지표는 다루지 않음**(abstract 확인) |
| **When Is an Agent Evaluation Over? Outcome Finality and Cross-Unit Separation** — arXiv 2608.14940 | ✅ | "run이 멈춘 시점의 상태를 점수로 쓰고 그 run을 1 trial로 센다. 그것을 독립 trial의 최종 결과로 해석하려면 **outcome finality**(이후 사건이 결과를 바꿀 수 없음)와 **cross-unit separation**(앞선 run이 뒤 run의 조건을 바꾸지 않음)이 필요하다." 지연 쓰기가 공유 상태에서 다음 run의 점수를 바꾸지만 namespacing/검증된 reset 후에는 그렇지 않음. `open-effects record` 제안 | **이중 관계.** (a) 프레임 차용: "종료 시점에서 점수를 읽는 것의 전제"를 정식화한 유일한 논문. (b) **우리 CAI 오염 6/16이 바로 cross-unit separation 위반 사례다.** 단 이 논문은 보안 지표·MAS를 다루지 않고(확인), **정지 시점이 측정 대상과 상관된다는 문제는 다루지 않는다** — 우리 축이 여기서 갈라진다 |

> **차별화 문장 초안**
> ABC formalizes *whether* an outcome check is valid; Outcome Finality formalizes *whether the outcome has settled* and *whether runs are separable*. Neither asks *whether the moment of reading is itself correlated with the measured property*. In iterative MAS pipelines the loop terminates on a task-completion judgment issued by an agent, and we show this judgment correlates with payload presence with architecture-dependent sign.

---

## 3. 평가 지표 신뢰도 (jailbreak judge / ASR)

이 그룹이 **"거부를 성공으로 집계"가 이미 알려진 문제**임을 보여준다. 우리 감사의 해당 발견은 단일턴에서는 선행 연구가 있다.

| 논문 | 상태 | 핵심 |
|---|---|---|
| **A StrongREJECT for Empty Jailbreaks** — arXiv 2402.10260 (Souly et al.) | ⚠ | ASR이 통상 과대보고되며 binary judge가 실사용 불가한 유해 내용 없는 응답까지 성공으로 인정 |
| **JailbreakBench** — NeurIPS 2024 D&B | ⚠ | 재현 가능한 jailbreak 평가 프로토콜 |
| **An Empirical Measurement of Jailbreaking Evaluators** — arXiv 2609.10594 | ⚠ | StrongREJECT 재현율 25.71%, **control-arm 오탐률 91–98%** |
| **Refusing Everything Looks Safe: Restoring the Benign Arm to Encoded-Prompt Evaluation** — arXiv 2609.26176 | ⚠ | binary judge가 **plaintext benign 프롬프트 응답의 0.61–0.70에서 발화**. benign arm 복원 필요 |
| **JailMeter: An Evidence-Based Evaluation Framework for Jailbreak** — arXiv 2607.19424 | ⚠ | 증거 기반 평가, 3단계 프롬프트가 StrongREJECT·HarmBench보다 우수 |
| **FalseReject** — arXiv 2505.08054 | ⚠ | 과도 거부 완화 자원. 거부 판별의 반대 방향 |

> **포지셔닝:** 단일턴 jailbreak에서 "judge 오탐"은 확립된 문제다. 우리 기여는 그 재발견이 아니라, **파이프라인 구조 때문에 생기는 새로운 오탐 경로**다 — QA 에이전트가 페이로드를 *버그 리포트 산문*에 언급하면서 코드에서는 제거했는데 substring 매칭이 성공으로 센다. 단일턴에는 존재할 수 없는 형태다. (MetaGPT 1/8, CAMEL 수정 전 1/1)

---

## 4. 정지 시점 · 종료 규칙

우리 주장의 직계 선행.

| 논문 | 상태 | 핵심 | 관계 |
|---|---|---|---|
| **Semantic Early-Stopping for Iterative LLM Agent Loops: A Judge-Efficient Study of When to Halt (SHP)** — arXiv 2606.27009 | ⚠ | 루프 종료를 "맹목적 카운터"에서 "내용 인식·품질 게이트 결정"으로 재구성. **step-budget 종료는 administrative stopping** — 정지 규칙이 에이전트 행동과 독립적으로 사전 고정되기 때문. "stop rule은 결과의 일부일 수도, 단지 관측의 종료일 수도 있다" | **용어를 그대로 쓸 수 있다.** administrative(외생) vs 내용 기반(내생) 구분이 우리 논증의 핵심 어휘. ACIArena의 `_need_iteration()`은 내용 기반 = 내생적 |
| 통계: **Experimenter evidence unmasking as a confound in optional stopping** — PMC12460446 | ⚠ | optional stopping의 교란으로 실험자가 현재 증거 상태를 아는 것이 내적 타당도를 떨어뜨림 | optional stopping 문헌으로의 연결. 우리 경우 "증거 상태를 아는 주체"가 에이전트다 |

> **이 그룹이 우리에게 가장 유리하다.** SHP는 *어떻게 잘 멈출까*를 묻고, 우리는 *멈추는 방식이 지표를 어떻게 망가뜨리는가*를 묻는다. 같은 대상, 반대 방향의 질문이고 아직 후자를 한 논문은 검색에서 나오지 않았다.

---

## 5. 전파 측정 · 생존 분석

| 논문 | 상태 | 핵심 | 관계 |
|---|---|---|---|
| **Share-Borne AI Virus: Memory-Hopping Attacks Across LLM Agents** — arXiv 2609.35576 | ✅ | hop 생존 확률 `S_c(h)=Pr(H_c ≥ h)`, **discrete Kaplan-Meier**로 우측 절단 보정. 절단 기준: 전원 감염 또는 최심 hop 도달 후 Δ=3 스텝 내 종료. universe 길이 10–60 스텝 **고정 예산** | **방법론 차용 + 핵심 차별.** 생존 분석 기구는 그대로 쓸 수 있다. 그러나 이 논문의 절단은 **비정보적**이고 종료는 **외생적**이며 **비교 불가능성 주장이 없다**(확인). 우리는 절단이 **정보적**이고 부호가 아키텍처별로 다름을 보인다 |
| **Prompt Infection: LLM-to-LLM Prompt Injection within Multi-Agent Systems** — arXiv 2410.07283 | ◐ | 자기복제 프롬프트가 에이전트 간 전파. `LLM Tagging` 방어 | 전파 공격의 원전. **지표 정의·측정 시점은 abstract에 없어 full text 확인 필요** |
| **Kill-Chain Canaries: Stage-Level Tracking of Prompt Injection** — arXiv 2603.28013 | ⚠ | 인젝션의 **단계별 추적** | 턴/단계 단위 관측의 선행. 우리 "턴별 점유율"과 가장 가까울 수 있어 **우선 확인 필요** |
| **CASPIAN: Online Detection and Attribution of Cascade Attacks in LLM Multi-Agent Systems via Cross-Channel Causal Monitoring** — arXiv 2605.19240 | ⚠ | 캐스케이드 공격 온라인 탐지·귀속 |  |
| **Collective Loss of Control in LLM Agent Systems: An Epidemic Account of Mutation, Contagion, and Recovery** — arXiv 2609.18460 | ⚠ | 전염병 모델(변이·전파·회복). **recovery를 모델에 넣는다** — 우리 "차단율"과 개념적으로 같은 자리 |  |
| **ASEval: Automated Trajectory-Level Security Testing for Autonomous Agents** — arXiv 2605.22321 | ⚠ | **트래젝토리 수준** 보안 테스트. 종단 vs 트래젝토리 구분을 이미 쓰고 있을 가능성 — **우선 확인 필요** |  |

---

## 6. MAS 공격 (배경)

| 논문 | 상태 | 핵심 |
|---|---|---|
| **Evil Geniuses: Delving into the Safety of LLM-based Agents** — arXiv 2311.11855 | ⚠ | 역할 정의 기반 자동 공격 프롬프트 생성. 에이전트 수가 늘면 유해 행동 성공률 상승 |
| **SoK: When Safe Agents Fail Together: The Security of Multi Agent LLM Systems** — arXiv 2609.00595 | ⚠ | MAS 보안 SoK. **서론 인용 필수** |
| **Beyond Single-Model Injection: A Threat Model and Defense Architecture for Prompt Injection in Multi-Agent Systems** — arXiv 2609.22949 | ⚠ | MAS 인젝션 위협 모델 |
| **Compositional Threat Analysis of Latent Compromise in LLM Agent Systems (Order 66)** — arXiv 2608.08131 | ⚠ | 잠재 침해의 조합적 위협 분석 |
| **Agent Against Agent: An Agentic System for Automatic Prompt Injection Red Teaming** — arXiv 2608.05108 | ⚠ | 자동 레드팀 |
| **Jailbreak Context Lingers: Divergent Safety Routing and Its Cross-Task Predictability in Tool Agents** — arXiv 2609.34686 | ⚠ | 유해 순응이 **이후 턴까지 지속**되고 선행 대화 이력에 민감. rescue / persistent unsafe / collateral loss 경로 구분 |

---

## 7. MAS 방어

| 논문 | 상태 | 핵심 | 관계 |
|---|---|---|---|
| **G-Safeguard: A Topology-Guided Security Lens and Treatment on LLM-based Multi-agent Systems** — arXiv 2502.11127, **ACL 2025 long 359** | ⚠ | **각 대화 라운드 종료 시점에 보안 평가**를 수행. utterance graph + edge-featured GNN으로 고위험 에이전트 식별, 토폴로지 개입으로 전파 차단 | **중요한 대비.** 턴 단위 관측을 *방어 기제*로는 쓰지만 *지표 정의*로는 쓰지 않는다. "턴 단위 정보가 방어에 쓰이는데 평가 지표는 여전히 종단 1점"이라는 우리 논증의 근거 |
| **BlindGuard** — arXiv 2508.08127, ACL 2026 long 1819 | ⚠ | 미지 공격 하 MAS 보호 |  |
| **Securing Multi-Agent Systems Against Corruptions via Node Contribution Backpropagation** — arXiv 2510.19420 | ⚠ | 노드 기여 역전파 |  |
| **Explainable and Fine-Grained Safeguarding of LLM Multi-Agent Systems via Bi-Level Graph Anomaly Detection** — arXiv 2512.18733 | ⚠ | 이중 수준 그래프 이상 탐지 |  |
| **When Agents Go Rogue: Activation-Based Detection of Malicious Behaviors in Multi-Agent Systems** — arXiv 2607.06807 | ⚠ | 활성값 기반 탐지 |  |
| **Privacy-Preserving Topology-Guided Safety for LLM-Based MAS via Federated Graph Learning** — arXiv 2609.02967 | ⚠ | 연합 그래프 학습 |  |

> 우리 발견 중 **"profile 교체는 출력 형식 준수율로 탐지된다"**(0/52 vs 30/38)가 이 그룹에 직접 들어갈 수 있다. 위 방어들은 모두 그래프·활성값·내용 기반인데, 형식 규약 위반은 쓰이지 않고 있다. 다만 **가볍고 저렴한 신호**라는 점이 장점이므로 defense 제안으로 분리 가능.

---

## 8. 멀티턴 jailbreak (지표 형태 대비)

| 논문 | 상태 | 핵심 |
|---|---|---|
| **MultiBreak: A Scalable and Diverse Multi-turn Jailbreak Benchmark** — arXiv 2605.01687 | ⚠ | 전체 대화 객체를 보존하고 **턴 k에서의 ASR**을 핵심 지표로 정의 |
| **Crescendo: Great, Now Write an Article About That** — arXiv 2404.01833 | ⚠ | 점진적 멀티턴 jailbreak |
| **M2S: Multi-turn to Single-turn jailbreak** — arXiv 2503.04856 | ⚠ | 멀티턴을 단일턴으로 압축 |
| **Multi-Turn Jailbreaks Are Simpler Than They Seem** — arXiv 2508.07646 | ⚠ | 멀티턴 우위가 과대평가됐다는 반론 |
| **AutoAdv** — arXiv 2507.01020 | ⚠ | 자동 멀티턴 적대 프롬프팅 |

> **대비 핵심:** 멀티턴 jailbreak의 ASR@k는 **단조 누적**("어느 턴에서든 성공")이고 정지를 **공격자가** 결정한다. MAS 파이프라인 벤치마크의 ASR은 **종단 전용**("마지막 턴에서 성공")이고 정지를 **시스템이** 결정한다. 전자는 공격자에게 유리한 쪽으로, 후자는 **아키텍처에 따라 양쪽으로** 치우친다. 이 비대칭을 지적한 선행 연구를 찾지 못했다.

---

## 9. 자기수정 (교정 기회 메커니즘의 배경)

주장 2("차단은 검토 에이전트가 아니라 교정 기회에서 나온다")의 이론적 배경.

| 논문 | 상태 | 핵심 | 관계 |
|---|---|---|---|
| **Large Language Models Cannot Self-Correct Reasoning Yet** — arXiv 2310.01798 (Huang et al., ICLR 2024) | ⚠ | **내재적** 자기수정은 외부 신호 없이는 개선하지 못하고 오히려 악화. 외부에서 오류 위치를 주면 수정 성능이 크게 향상 — **병목은 진단이지 수정이 아니다** | **핵심 인용.** 우리 CAMEL 관측과 정확히 맞물린다: `user_proxy`가 "Disregard the fallback"이라고 **오류 위치를 지정**해 주었을 때 assistant가 교정했다. 검토자가 없어도 교정이 일어난 이유 |
| **The Self-Correction Illusion: LLMs Correct Others but Not Themselves** — arXiv 2606.05976 | ⚠ | 타인 교정은 되고 자기 교정은 안 됨. role relabeling이 오류 지적을 게이트 | MetaGPT(타 에이전트 QA) vs CAMEL(같은 에이전트 + 외부 지시) 대비에 직접 쓰임 |
| **When Can LLMs Actually Correct Their Own Mistakes? A Critical Survey** | ⚠ | 자기수정 조건 서베이 |  |

---

## 10. 가장 위험한 경쟁 3편과 차별화 문장

### ① ABC (NeurIPS 2025 D&B) — arXiv 2507.02825
**위험:** 우리 감사 발견 전체가 outcome validity 위반 사례로 흡수된다. τ-bench 빈 응답 사례는 우리 CAMEL 빈 응답 2건과 구조가 같다.
**대응:** 감사를 헤드라인에서 내리고 "계측기 교정" 절로 배치한다. 그리고 ABC의 두 축에 **세 번째 축**을 더하는 형태로 포지셔닝한다.

> ABC establishes outcome validity (does the check indicate success?) and task validity (is the task solvable only with the target capability?). We identify a third requirement for iterative pipelines: **read-time validity** — the step at which the outcome is read must be independent of the property being measured. We show this fails in a published MAS security benchmark, with the direction of failure flipping across architectures.

### ② Outcome Finality — arXiv 2608.14940
**위험:** "종료 시점에서 점수를 읽는 전제"를 이미 정식화했다. 우리 CAI 오염은 이 논문의 cross-unit separation 위반 사례다.
**대응:** 이 논문을 **프레임으로 차용**하고, 두 조건(finality, separation)이 모두 성립해도 **여전히 남는 세 번째 문제**로 우리 축을 세운다.

> Outcome finality asks whether later events can change the label; cross-unit separation asks whether runs are independent. Both can hold while the metric remains biased, because neither constrains *when* the run stops relative to the measured state. We exhibit a pipeline where finality and separation hold yet terminal-state ASR deviates from turn-occupancy by 29 points with opposite sign across two architectures.

### ③ Share-Borne AI Virus — arXiv 2609.35576
**위험:** per-hop 생존 + Kaplan-Meier 절단 보정을 이미 한다. "생존 분석으로 전파를 재는 것"은 새롭지 않다.
**대응:** 절단의 **정보성**을 구분점으로 삼는다.

> Prior propagation studies apply right-censoring under the assumption that termination is administrative — a fixed step budget independent of the attack state. In MAS pipelines the loop terminates on an agent's task-completion judgment, which we measure to be correlated with payload presence (CAMEL: 0/8 payload at terminal turn among early-stopped runs vs 4/8 among budget-exhausted runs). Censoring is therefore informative, and Kaplan-Meier-style estimates inherit the bias.

---

## 11. 다음에 읽을 순서 (우선순위)

- [ ] **ACIArena full text** (ACL 2026 long 457) — ASR·Utility 정의, `max_turn` 처리, 종료 규칙 언급, limitation. 우리 주장의 공백이 실제로 비어 있는지 확정
- [ ] **Kill-Chain Canaries** (2603.28013) — 단계별 추적이 우리 턴별 점유율과 같은 것인지. **가장 위험한 미확인 항목**
- [ ] **ASEval** (2605.22321) — 트래젝토리 수준 보안 평가가 종단 지표 비판을 이미 하는지
- [ ] **Jailbreak Context Lingers** (2609.34686) — 턴 간 유해 순응 지속. rescue/persistent 경로 구분이 우리 점유율·차단율과 겹치는지
- [ ] **ABC 체크리스트 PDF** (assets/checklist.pdf) — 항목 전수 확인. "process-based metrics alongside outcome-based metrics"가 권고에 있다는 스니펫이 있어 read-time 축이 일부 선점됐을 가능성
- [ ] **Collective Loss of Control** (2609.18460) — recovery 항이 우리 차단율과 같은 자리인지
- [ ] **TAMAS** (ACL 2026 long 1442) — benign arm 설계 참고. 우리 benign baseline 부재 보완에 직접 활용
- [ ] **Prompt Infection full text** (2410.07283) — 지표 정의와 측정 시점
- [ ] **G-Safeguard** (ACL 2025 long 359) — 라운드별 평가를 지표로도 쓰는지, 방어 전용인지

## 12. 검색에서 나오지 않은 것 (= 공백 후보)

다음 조합으로 검색했으나 해당 주장을 하는 논문을 찾지 못했다. 추가 검색으로 재확인 필요.

- 정지 규칙과 보안 지표의 상관 → 아키텍처 간 비교 불가능성
- 종단 ASR vs 턴 점유율의 괴리를 측정하고 부호가 뒤바뀌는 것을 보인 사례
- MAS 공격 평가에서 정보적 절단(informative censoring)을 지적한 사례
- 출력 형식 규약 위반을 profile 교체 공격의 탐지 신호로 쓴 사례

마지막 항목은 defense 제안으로 따로 뗄 수 있다 (우리 측정: profile 교체 0/52 준수 vs 쿼리 주입 30/38 준수).

---

## 부록. 참조 목록 (ID 재확인 필요 항목 표기)

| # | 논문 | ID | 상태 |
|---|---|---|---|
| 1 | ACIArena | arXiv 2604.07775 / ACL 2026 long 457 | ◐ |
| 2 | ABC (Rigorous Agentic Benchmarks) | arXiv 2507.02825 / NeurIPS 2025 D&B | ◐ |
| 3 | Protocol Validity / HackDetect | arXiv 2607.22368 | ✅ |
| 4 | Outcome Finality & Cross-Unit Separation | arXiv 2608.14940 | ✅ |
| 5 | Share-Borne AI Virus | arXiv 2609.35576 | ✅ |
| 6 | Prompt Infection | arXiv 2410.07283 | ◐ |
| 7 | StrongREJECT | arXiv 2402.10260 | ⚠ |
| 8 | JailbreakBench | NeurIPS 2024 D&B | ⚠ |
| 9 | Empirical Measurement of Jailbreaking Evaluators | arXiv 2609.10594 | ⚠ |
| 10 | Refusing Everything Looks Safe | arXiv 2609.26176 | ⚠ |
| 11 | JailMeter | arXiv 2607.19424 | ⚠ |
| 12 | FalseReject | arXiv 2505.08054 | ⚠ |
| 13 | Semantic Early-Stopping (SHP) | arXiv 2606.27009 | ⚠ |
| 14 | Kill-Chain Canaries | arXiv 2603.28013 | ⚠ |
| 15 | CASPIAN | arXiv 2605.19240 | ⚠ |
| 16 | Collective Loss of Control | arXiv 2609.18460 | ⚠ |
| 17 | ASEval | arXiv 2605.22321 | ⚠ |
| 18 | Evil Geniuses | arXiv 2311.11855 | ⚠ |
| 19 | SoK: When Safe Agents Fail Together | arXiv 2609.00595 | ⚠ |
| 20 | Beyond Single-Model Injection | arXiv 2609.22949 | ⚠ |
| 21 | Order 66 (Compositional Threat Analysis) | arXiv 2608.08131 | ⚠ |
| 22 | Agent Against Agent | arXiv 2608.05108 | ⚠ |
| 23 | Jailbreak Context Lingers | arXiv 2609.34686 | ⚠ |
| 24 | G-Safeguard | arXiv 2502.11127 / ACL 2025 long 359 | ⚠ |
| 25 | BlindGuard | arXiv 2508.08127 / ACL 2026 long 1819 | ⚠ |
| 26 | Node Contribution Backpropagation | arXiv 2510.19420 | ⚠ |
| 27 | Bi-Level Graph Anomaly Safeguarding | arXiv 2512.18733 | ⚠ |
| 28 | When Agents Go Rogue | arXiv 2607.06807 | ⚠ |
| 29 | Privacy-Preserving Topology-Guided Safety | arXiv 2609.02967 | ⚠ |
| 30 | TAMAS | arXiv 2511.05269 / ACL 2026 long 1442 | ⚠ |
| 31 | Unifying Quantitative Security Benchmarking for MAS | arXiv 2507.21146 | ⚠ |
| 32 | PIArena | arXiv 2604.08499 | ⚠ |
| 33 | MultiBreak | arXiv 2605.01687 | ⚠ |
| 34 | Crescendo | arXiv 2404.01833 | ⚠ |
| 35 | M2S | arXiv 2503.04856 | ⚠ |
| 36 | Multi-Turn Jailbreaks Are Simpler Than They Seem | arXiv 2508.07646 | ⚠ |
| 37 | AutoAdv | arXiv 2507.01020 | ⚠ |
| 38 | LLMs Cannot Self-Correct Reasoning Yet | arXiv 2310.01798 | ⚠ |
| 39 | The Self-Correction Illusion | arXiv 2606.05976 | ⚠ |
