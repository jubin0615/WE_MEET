# 자체 규칙팩

`vibescan/*.yml`은 이번 프로젝트에서 작성한 Semgrep 규칙이다. 외부 레지스트리 규칙을 복사·다운로드하지 않는다. YAML의 JSON 표기법으로 저장해 메타데이터를 표준 라이브러리로도 읽을 수 있다.

규칙에는 `metadata.cwe`, `metadata.vibescan`의 `category`(VS-01~10), `limitations_ko`(지원 범위와 수동 확인 사항), `title_ko`, `remediation_ko`, `severity`, `confidence`를 반드시 넣는다. 새 규칙은 이 디렉터리에 파일과 같은 이름의 취약/안전 테스트를 추가하면 적용된다. `fix_example`은 선택 사항이며 실행 가능한 자동 수정으로 취급하지 않는다. 원시 코드·메타변수의 값은 보고서에 복사하지 않는다.

`python -m bench.check_rules`는 규칙마다 `semgrep --test --strict`를 실행한다. 모든 규칙에 `ruleid`와 `ok` 표본이 있어야 하고, 파싱·실행 오류나 빠진 검사도 실패 처리한다. Windows에서 Semgrep 1.185의 병렬 테스트가 설정 파일을 동시에 교체하는 문제를 피하도록 규칙별로 순서대로 실행한다. 앱 검사에서는 전체 규칙을 한 번에 실행한다.

직접 추적한 입력→싱크는 Likely, API·설정·가드 부재 추정은 Potential이다. 여러 패턴이 겹친다는 이유만으로 Confirmed나 Likely로 승격하지 않는다. Semgrep CE의 함수 내부 분석과 제한된 프레임워크 패턴만 제공하며 파일·함수 간 흐름을 보장하지 않는다.

웹 OWASP 코드는 규칙의 CWE를 2025판 공식 매핑의 역색인에서 찾아 부여한다. 목록에 없는 CWE는 OWASP를 비워 두고 카탈로그의 `unmapped_cwes`에 근거를 남긴다. LLM·에이전트 항목은 `metadata.vibescan.owasp_ai`에 별도로 기록한다. 규칙 ID는 지문과 과거 스캔 비교에 사용한다.

[OWASP Top 10:2025](https://top10.owasp.org/2025/) · [Semgrep 규칙 테스트](https://semgrep.dev/docs/writing-rules/testing-rules)
