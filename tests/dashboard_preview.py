"""Deterministic demo results and an offline HTML preview of the shipped UI.

Run from the repository: python tests/dashboard_preview.py --output /tmp/vibescan-demo
The generated fixture is test data; it never reads or scans a user's repositories.
"""
import argparse
import copy
import json
from pathlib import Path


def samples():
    titles = [
        ("Critical", "SQL 문자열 결합으로 사용자 입력이 쿼리에 포함됨", "app/api/search.py", 42, "VS-05", "CWE-89"),
        ("High", "관리자 API에서 권한 검사 없이 사용자 정보 조회", "app/api/admin.py", 87, "VS-02", "CWE-862"),
        ("High", "파일 다운로드 경로에 외부 입력을 그대로 사용", "app/api/download.py", 31, "VS-05", "CWE-22"),
        ("Medium", "세션 쿠키의 Secure 속성이 설정되지 않음", "config/session.py", 18, "VS-06", "CWE-614"),
        ("Medium", "허용 출처가 제한되지 않은 교차 출처 요청", "app/middleware/cors.py", 24, "VS-06", "CWE-942"),
        ("Low", "오류 응답에 내부 경로가 포함될 수 있음", "app/errors.py", 56, "VS-06", "CWE-209"),
        ("Low", "쿠키 만료 시간이 명시되지 않음", "config/cookies.py", 12, "VS-06", "CWE-613"),
        ("Info", "로그인 경로의 요청 제한 정책 수동 확인 필요", "app/api/auth.py", 103, "VS-08", "CWE-307"),
        ("Info", "업로드 파일 검사 정책 수동 확인 필요", "app/api/uploads.py", 64, "VS-08", "CWE-770"),
        ("Info", "민감한 기능의 감사 로그 확인 필요", "app/services/audit.py", 28, "VS-06", "CWE-778"),
        ("Info", "운영 환경의 HTTPS 적용 여부 확인 필요", "config/server.py", 9, "VS-06", "CWE-319"),
        ("Info", "백업 데이터 접근 제어 수동 확인 필요", "app/services/backup.py", 72, "VS-02", "CWE-284"),
    ]
    findings = []
    catalogs = Path(__file__).resolve().parents[1] / "rules/catalog"
    web = json.loads((catalogs / "owasp-top10-2025.yml").read_text(encoding="utf8"))["items"]
    owasp_codes = {cwe: item["code"] for item in web for cwe in item["cwes"]}
    for index, (severity, title, file, line, category, cwe) in enumerate(titles):
        findings.append(dict(
            id=f"F-{index + 1:03}", title=title, severity=severity, confidence="Likely",
            status="open", change="new" if index == 0 else "existing", introduced_in="a1b2c3d4",
            original_severity=severity, location=dict(file=file, line=line),
            cwe=cwe, owasp=owasp_codes.get(cwe, ""), category=category,
            evidence='query = "SELECT * FROM notes WHERE title = \'" + title + "\'"\nrows = db.execute(query)',
            how_found=["정적 규칙 탐지", "사용자 입력에서 쿼리 실행까지의 흐름 확인"],
            impact_ko="사용자가 입력한 값이 SQL 구문의 일부로 합쳐집니다. 공격자가 쿼리 구조를 바꾸면 허용되지 않은 데이터를 조회할 수 있습니다.",
            remediation_ko="문자열 결합을 제거하고 데이터베이스 드라이버의 매개변수 바인딩을 사용하세요. 입력값은 쿼리와 분리해서 전달해야 합니다.",
            fix_diff='--- a/app/api/search.py\n+++ b/app/api/search.py\n-query = "SELECT * FROM notes WHERE title = \'" + title + "\'"\n-rows = db.execute(query)\n+query = "SELECT * FROM notes WHERE title = ?"\n+rows = db.execute(query, (title,))',
            fix_note="실제 코드 문맥에서 검토 필요", triage_reason="요청 입력이 SQL 실행 함수로 전달됩니다.",
        ))
    for index, status in enumerate(["dismissed", "dismissed", "fixed", "fixed", "fixed"], 13):
        finding = copy.deepcopy(findings[0])
        finding.update(id=f"F-{index:03}", status=status, change="fixed" if status == "fixed" else "existing",
                       title="기존 발견 검토 " + str(index))
        findings.append(finding)
    findings[0]["rule_id"] = "demo-sql"
    findings.append(dict(findings[0], id="F-018", change="existing",
                         location=dict(file="app/api/archive.py", line=59)))
    for finding in findings[1:-1]:
        # Only the SQL fixture has a code-level explanation and suggested diff.
        finding.update(impact_ko="", remediation_ko="", evidence="", fix_diff="", triage_reason="")
    summary = {level: sum(f["severity"] == level and f["status"] == "open" for f in findings)
               for level in ["Critical", "High", "Medium", "Low", "Info"]}
    common = dict(
        repo=dict(name="vulnapp", path="C:/demo/vulnapp", branch="main"), commit="a1b2c3d4e5f6",
        baseline_commit="8f20c6a12345", risk_score=100, findings=findings, summary=summary,
        delta=dict(new=1, fixed=3), dismissed_count=2, analysis_note="모델 점검 계획 적용 · 한국어 상세 검토 12/12건",
        profile=dict(framework="Flask", routes=8, auth="세션 인증", limitations=["정적 검사 결과이며 안전을 보증하지 않습니다.", "실제 실행 환경과 권한 정책은 수동 확인이 필요합니다."]),
        report_md="# VibeScan 데모 보고서\n\n실제 진단 결과가 아닌 화면 검증용 데이터입니다.",
        trigger="git-hook", scan_type="full",
    )
    scans = []
    for i, score in enumerate([66, 75, 61, 84, 67, 73, 60, 100]):
        scan = copy.deepcopy(common)
        scan.update(scan_id=f"demo-{i}", scanned_at=f"2026-11-{13+i:02}T01:30:00Z", risk_score=score)
        if i < 7:
            scan["commit"] = f"c0ffee{i:06}"
        scans.append(scan)
    clean = copy.deepcopy(common)
    clean.update(scan_id="clean", repo=dict(name="portfolio", path="C:/demo/portfolio", branch="main"),
                 scanned_at="2026-11-20T00:00:00Z", findings=[], risk_score=0,
                 summary={key: 0 for key in summary}, delta=dict(new=0, fixed=0), analysis_note="로컬 규칙으로 작성",
                 dismissed_count=0, trigger="manual", baseline_commit=None)
    failed = copy.deepcopy(common)
    failed.update(scan_id="ai-failed", repo=dict(name="legacy-api", path="C:/demo/legacy", branch="develop"),
                  scanned_at="2026-11-19T00:00:00Z", analysis_note="모델 분석 확인 실패 · 로컬 규칙 결과 유지")
    for scan in scans + [clean, failed]:
        for field, filename, key in (("coverage", "vibescan-top10", "category"),
                                     ("owasp_coverage", "owasp-top10-2025", "owasp")):
            rows = json.loads((catalogs / (filename + ".yml")).read_text(encoding="utf8"))["items"]
            scan[field] = []
            for row in rows:
                ids = [f["id"] for f in scan["findings"] if f[key] == row["code"] and f["status"] == "open"]
                scan[field].append(dict(code=row["code"], name=row.get("name_ko", row["name"]),
                                        status="취약 후보" if ids else "부분 점검", execution="partial",
                                        findings=ids, reason="화면 검증용 표본", url=row.get("url")))
    return sorted(scans + [clean, failed], key=lambda scan: scan["scanned_at"], reverse=True)


def build(output, web):
    output.mkdir(parents=True, exist_ok=True)
    scans = samples()
    for scan in scans:
        folder = output / "results" / scan["scan_id"]
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "scan_result.json").write_text(json.dumps(scan, ensure_ascii=False, indent=2), encoding="utf-8")
    (output / "empty-results").mkdir(exist_ok=True)
    fixture = """
const demoScans = SCANS;
const previewEmpty = new URLSearchParams(location.search).has("empty");
let demoRepos = previewEmpty ? [] : [{path:"C:/demo/vulnapp",name:"vulnapp",hook:true},{path:"C:/demo/portfolio",name:"portfolio",hook:false},{path:"C:/demo/new-project",name:"new-project",hook:null}];
try { localStorage.setItem("vibescan-project", "C:/demo/vulnapp"); } catch {}
window.fetch = async (url, options={}) => {
  let data;
  if (url === "/api/repos") {
    if (options.method === "POST") { const body=JSON.parse(options.body); const repo={path:body.path,name:body.path.split(/[\\/]/).pop(),hook:false,commit:"demo",branch:"main"};demoRepos.push(repo);data=repo; }
    else data={repos:demoRepos};
  } else if (url === "/api/scans") data={scans:previewEmpty?[]:demoScans,results_path:"C:/demo/results"};
  else if (url.startsWith("/api/scans/")) data=demoScans.find(s=>s.scan_id===url.split("/").pop());
  else if (url === "/api/scan") data={state:"idle",stages:["코드 수집","정찰","점검 계획","정적 검사","검토·보고서"]};
  else if (url === "/api/latest") data={scan_id:previewEmpty?null:"demo-7"};
  else if (url === "/api/auth") data={state:"ready",message:"ChatGPT 연결됨 · 화면 검증용",login:{state:"idle"}};
  else if (url === "/api/settings") data={background_llm:false};
  else data={};
  return {ok:true,json:async()=>data};
};
"""
    fixture = fixture.replace("SCANS", json.dumps(scans, ensure_ascii=False).replace("</", "<\\/"))
    html = (web / "index.html").read_text(encoding="utf-8")
    html = html.replace("</head>", "<script>" + fixture + "</script></head>")
    css = (web / "dashboard.css").read_text(encoding="utf-8")
    font_uri = (web / "fonts/PretendardVariable.woff2").resolve().as_uri()
    css = css.replace("/assets/fonts/PretendardVariable.woff2", font_uri)
    html = html.replace('<link rel="stylesheet" href="/assets/dashboard.css">', "<style>" + css + "</style>")
    html = html.replace('<script defer src="/assets/dashboard.js"></script>', "")
    html = html.replace("</body>", "<script>" + (web / "dashboard.js").read_text(encoding="utf-8") + "</script></body>")
    (output / "preview.html").write_text(html, encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build(args.output, Path(__file__).resolve().parents[1] / "vibescan/web")
    print(args.output.resolve() / "preview.html")
