"use strict";
// Constants and storage. The URL hash is exclusively the loopback access ticket.
const $ = id => document.getElementById(id);
const levels = ["Critical", "High", "Medium", "Low", "Info"];
const severityLabels = {Critical: "치명", High: "높음", Medium: "보통", Low: "낮음", Info: "정보"};
const confidenceLabels = {Confirmed: "확인됨", Likely: "가능성 높음", Potential: "잠재적"};
const statuses = {open: "열림", dismissed: "오탐 후보", fixed: "해결됨"};
const issueHints = {
  limit: "ChatGPT 사용량 한도에 도달했습니다. ChatGPT 설정의 사용량에서 이 앱의 한도를 확인하세요.",
  plan: "ChatGPT Plus/Pro 구독과 구독 사용 승인이 필요합니다.",
  login: "설정에서 ChatGPT에 다시 연결하세요.",
  register: "먼저 터미널에서 python -m vibescan.register 로 이 PC를 등록하세요.",
  error: "모델 분석 일부를 완료하지 못했습니다.",
};
function stored(storage, key, fallback = "") {
  try { return globalThis[storage].getItem(key) || fallback; } catch { return fallback; }
}
function remember(storage, key, value) {
  try { globalThis[storage].setItem(key, value); } catch { /* Persistence is optional. */ }
}
const token = location.hash.slice(1) || stored("sessionStorage", "vibescan-token");
if (location.hash) {
  remember("sessionStorage", "vibescan-token", token);
  history.replaceState(null, "", location.pathname + (location.search || ""));
}

// State
let result = null, scanList = [], repoList = [], stages = [];
let selectedProject = stored("localStorage", "vibescan-project");
let scanMode = stored("localStorage", "vibescan-mode", "local") === "ai" ? "ai" : "local";
let taskGroups = [], activeSection = "findings";
const sectionNames = {findings: "지금 확인할 것", later: "다음에 확인할 것", fixed: "이번 검사에서 해결됨", dismissed: "오탐 후보", coverage: "검사 범위"};
let latestSeen, detailVersion = 0, refreshVersion = 0, jobVersion = 0;
let scanning = false, connecting = false, hookPending = false, backgroundPending = false;
let pollTimer = null, authTimer = null, toastTimer = null, loginRequested = false, auth = null;
let activeDrawer = null, returnFocus = null, lastJob = "";
let retryAction = null, resultsPath = "", latestPollFailed = false;
const jobIssues = new Map(), notifiedScans = new Set();

// DOM and API
function node(tag, text = "", className = "") {
  const item = document.createElement(tag);
  item.textContent = text;
  if (className) item.className = className;
  return item;
}
function badge(level) {
  const known = levels.includes(level) ? level : "Info";
  return node("span", severityLabels[known], "badge " + known);
}
function findingStatus(f) { return f.change === "fixed" ? "fixed" : (f.status || "open"); }
function locationText(f) { return (f.location?.file || f.location?.endpoint || "위치 미확인") + (f.location?.line ? ":" + f.location.line : ""); }
function dateText(value) { return new Date(value).toLocaleString("ko-KR", {month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit"}); }
function message(text, error = false, retry = null) {
  clearTimeout(toastTimer);
  $("message").textContent = text;
  $("toast").hidden = !text;
  $("toast").classList.toggle("error", error);
  retryAction = retry;
  $("retry").hidden = !retry;
  if (text && !error) toastTimer = setTimeout(() => { $("toast").hidden = true; }, 6000);
}
async function api(path, body) {
  const response = await fetch(path, {method: body === undefined ? "GET" : "POST",
    headers: {"X-VibeScan-Token": token, "Content-Type": "application/json"},
    body: body === undefined ? undefined : JSON.stringify(body), cache: "no-store"});
  if (!response.ok) {
    if (response.status === 403) throw new Error("접속 권한이 만료되었습니다. 터미널에 표시된 대시보드 주소로 다시 여세요.");
    const data = await response.json().catch(() => ({}));
    throw new Error(typeof data.detail === "string" ? data.detail : "요청을 처리할 수 없습니다. 입력과 파일 상태를 확인하세요.");
  }
  return response.json();
}
async function copyText(text, success) {
  try { await navigator.clipboard.writeText(text); message(success); }
  catch { message("복사 권한이 없습니다. 텍스트를 선택해 복사하세요.", true); }
}
function selectedRepo() { return repoList.find(repo => repo.path === selectedProject); }
function projectScans(path = selectedProject) { return scanList.filter(scan => scan.repo.path === path); }
function projects() {
  const combined = new Map(repoList.map(repo => [repo.path, {...repo, connected: true}]));
  for (const scan of scanList) {
    if (!combined.has(scan.repo.path)) combined.set(scan.repo.path, {...scan.repo, connected: false, hook: null});
  }
  return [...combined.values()];
}

// Project selection: project, history and visible result always move together.
function renderProjects() {
  const items = projects();
  const select = $("projects");
  const counts = new Map();
  for (const project of items) counts.set(project.name, (counts.get(project.name) || 0) + 1);
  select.replaceChildren(...items.map(project => {
    const label = counts.get(project.name) > 1 ? project.name + " · " + project.path : project.name;
    const option = node("option", label + (project.connected ? "" : " · 결과만"));
    option.value = project.path;
    option.title = project.path;
    return option;
  }));
  if (!items.length) select.append(node("option", "프로젝트 없음"));
  select.disabled = !items.length;
  select.value = selectedProject;
}
function renderHistory(preferred) {
  const scans = projectScans();
  $("scan-select").replaceChildren(...scans.map(scan => {
    const trigger = scan.trigger === "git-hook" || scan.trigger === "watcher" ? "자동" : "수동";
    const option = node("option", `${(scan.commit || "커밋 없음").slice(0, 7)} · ${dateText(scan.scanned_at)} · ${scan.risk_score}점 · ${trigger}`);
    option.value = scan.scan_id;
    return option;
  }));
  if (!scans.length) {
    const option = node("option", "스캔 기록 없음"); option.value = "";
    $("scan-select").append(option);
  }
  $("scan-select").value = scans.some(scan => scan.scan_id === preferred) ? preferred : scans[0]?.scan_id || "";
  $("scan-select").disabled = !scans.length;
}
function resetFilters() {
  $("vs-filter").value = ""; $("owasp-filter").value = "";
  $("search").value = "";
}
function emptyState() {
  const project = projects().find(p => p.path === selectedProject);
  $("result").hidden = true; $("empty").hidden = false;
  $("download").disabled = true; $("analysis-badge").hidden = true;
  $("repo-name").textContent = project?.name || "진단 대시보드";
  $("repo-name").title = project?.path || "";
  $("repo-meta").textContent = project ? "아직 스캔 기록이 없습니다" : "프로젝트를 연결해 시작하세요";
  $("empty-description").textContent = project ? "연결이 완료됐습니다. 첫 스캔을 실행해 발견한 문제와 수정 방법을 확인하세요." : "코드에서 발견한 문제와 근거, 수정 방법을 한곳에 모읍니다.";
  renderOnboarding();
}
function renderOnboarding() {
  for (const [id, done, number] of [
    ["step-project", Boolean(selectedRepo()), "01"], ["step-scan", projectScans().length > 0, "02"], ["step-auth", auth?.state === "ready", "03"]]) {
    $(id).textContent = done ? "✓ 완료" : number; $(id).classList.toggle("complete", done);
  }
  $("onboard-scan").disabled = scanning || !selectedRepo();
}
async function chooseProject(path, preferred = null) {
  if (!projects().some(project => project.path === path)) return;
  const changed = path !== selectedProject;
  selectedProject = path;
  remember("localStorage", "vibescan-project", path);
  ++detailVersion;
  if (changed) { closeDrawer(); result = null; resetFilters(); }
  renderProjects(); renderHistory(preferred); busy(scanning);
  if ($("scan-select").value) await selectScan();
  else { result = null; emptyState(); }
}
async function selectScan() {
  const id = $("scan-select").value, path = selectedProject, version = ++detailVersion;
  if (!id) { result = null; emptyState(); return; }
  // Old results must not remain actionable while their replacement is loading.
  $("download").disabled = true;
  $("result").hidden = true;
  $("result").setAttribute("aria-busy", "true");
  try {
    const data = await api("/api/scans/" + encodeURIComponent(id));
    if (version !== detailVersion || path !== selectedProject) return;
    if (data.repo.path !== path || data.scan_id !== id) throw new Error("프로젝트와 스캔 결과가 일치하지 않습니다.");
    closeDrawer();
    result = data; render();
  } catch (error) {
    if (version === detailVersion) {
      result = null; emptyState();
      $("repo-meta").textContent = "결과를 불러오지 못했습니다";
      message(error.message, true, selectScan);
    }
  } finally { if (version === detailVersion) $("result").setAttribute("aria-busy", "false"); }
}
async function refresh(preferred = null) {
  const version = ++refreshVersion;
  try {
    const data = await api("/api/scans");
    if (version !== refreshVersion) return;
    const oldId = $("scan-select").value;
    scanList = data.scans || []; resultsPath = data.results_path || "";
    $("results-path").textContent = resultsPath;
    const items = projects();
    if (!items.some(p => p.path === selectedProject)) {
      selectedProject = items[0]?.path || "";
      remember("localStorage", "vibescan-project", selectedProject);
      result = null; resetFilters();
    }
    renderProjects();
    const preferredScan = projectScans().find(scan => scan.scan_id === preferred);
    renderHistory(preferredScan?.scan_id || oldId);
    busy(scanning);
    if ($("scan-select").value) {
      if (result?.scan_id !== $("scan-select").value || result?.repo.path !== selectedProject) await selectScan();
    } else { ++detailVersion; result = null; emptyState(); }
    if (data.unavailable) message(`읽을 수 없는 결과 폴더 ${data.unavailable}개를 제외했습니다. 파일 형식과 권한을 확인하세요.`, true, refresh);
  } catch (error) { if (version === refreshVersion) message(error.message, true, refresh); }
}
async function loadRepos() {
  const data = await api("/api/repos");
  repoList = data.repos || [];
  renderProjects(); busy(scanning);
}

// Result rendering
function riskGrade(findings) {
  const highest = levels.find(level => findings.some(f => findingStatus(f) === "open" && f.severity === level));
  return {label: ({Critical: "심각", High: "위험", Medium: "주의", Low: "낮음", Info: "낮음"})[highest] || "발견 없음", level: highest || "Info"};
}
function freshRisks(scan) { return scan.findings.filter(f => f.change === "new" && findingStatus(f) === "open" && ["Critical", "High"].includes(f.severity)); }
function groupFindings(findings) {
  const groups = new Map();
  for (const f of findings) {
    const dismissed = findingStatus(f) === "dismissed";
    const key = JSON.stringify([dismissed, f.rule_id || [f.category || "", f.title]]);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(f);
  }
  return [...groups.values()].map(items => {
    const open = items.filter(f => findingStatus(f) === "open");
    const active = open.length ? open : items;
    const level = levels.find(level => active.some(f => f.severity === level)) || "Info";
    const status = open.length ? "open" : findingStatus(items[0]);
    const section = status === "open" ? (["Critical", "High"].includes(level) ? "findings" : "later") : status;
    const locations = [...new Set(active.map(locationText))];
    return {items, open, locations, level, section, fresh: open.some(f => f.change === "new"),
      title: active.find(f => f.severity === level)?.title || active[0].title};
  }).sort((a, b) => Number(b.fresh) - Number(a.fresh) || levels.indexOf(a.level) - levels.indexOf(b.level)
    || b.locations.length - a.locations.length);
}

function fixPrompt(group, scan) {
  // Report prose, snippets and diffs can contain literal credentials. Export only locators and identifiers.
  const files = [...new Set(group.open.filter(f => f.location?.file).map(locationText))];
  const cwes = [...new Set(group.open.map(f => f.cwe).filter(value => /^CWE-\d+$/i.test(value)))];
  return [`프로젝트 ${scan.repo.name} · ${scan.repo.branch || "브랜치 미확인"} · ${(scan.commit || "").slice(0, 12)}`,
    `보안 진단에서 ${severityLabels[group.level]} 등급으로 분류한 위치를 검토해 주세요. ${cwes.join(", ")}`,
    ...(files.length ? files : ["보고서에 파일 위치가 기록되지 않았습니다."]), "각 위치의 코드와 사용처를 확인하고, 문제가 확인되면 기존 동작을 유지하면서 수정해 주세요.",
    "비밀값은 출력하지 말고, 변경한 파일과 검증 결과를 알려 주세요."].join("\n");
}

function locationDetail(f) {
  const detail = node("details", "", "location-detail");
  detail.append(node("summary", [locationText(f), severityLabels[f.severity], statuses[findingStatus(f)]].filter(Boolean).join(" · ")));
  detail.addEventListener("toggle", () => {
    if (!detail.open || detail.children.length > 1) return;
    detail.append(node("p", f.impact_ko || "영향 설명 없음"), node("h4", "근거 코드"), node("pre", f.evidence || "기록 없음"),
      node("h4", "수정 방법"), node("p", f.remediation_ko || "수정 방법 없음"));
    if (f.rule_id === "vs-client-only-auth") {
      for (const step of f.trace || []) detail.append(node("p", '화면 호출 근거 · ' + step.file + ':' + step.line));
    }
    if (f.fix_diff) {
      const fix = node("details"), copy = node("button", "수정안 복사", "secondary");
      copy.addEventListener("click", () => copyText(f.fix_diff, "수정안을 복사했습니다."));
      fix.append(node("summary", "수정 코드 보기"), node("pre", f.fix_diff), node("p", "동작 검증 전 제안 · " + (f.fix_note || "적용 전 검토하세요.")), copy);
      detail.append(fix);
    }
    const decision = node("details");
    const adjustment = f.original_severity && f.original_severity !== f.severity
      ? `심각도 조정 ${severityLabels[f.original_severity]} → ${severityLabels[f.severity]}` : "";
    decision.append(node("summary", "판정 정보"), node("p", [f.rule_id, f.category, f.cwe, f.owasp, ...(f.owasp_ai || []),
      confidenceLabels[f.confidence], adjustment, ...(f.how_found || []), f.triage_reason,
      f.introduced_in && "처음 발견 " + f.introduced_in.slice(0, 12)].filter(Boolean).join(" · ") || "기록 없음"));
    detail.append(decision);
  });
  return detail;
}

function taskCard(group) {
  const card = node("article", "", "task-card " + group.level);
  const tags = node("div", "", "task-tags");
  tags.append(badge(group.level));
  for (const code of new Set(group.items.map(f => f.owasp).filter(Boolean))) {
    const url = result.owasp_coverage?.find(row => row.code === code)?.url;
    const linked = /^https:\/\/top10\.owasp\.org\/2025\/A\d{2}_2025-[A-Za-z_]+\/$/.test(url || "");
    const tag = node(linked ? "a" : "span", code, "new-tag");
    if (linked) { tag.href = url; tag.target = "_blank"; tag.rel = "noopener noreferrer"; }
    tags.append(tag);
  }
  if (group.fresh) tags.append(node("span", "새로 발견", "new-tag"));
  const heading = node("h3", group.title);
  heading.append(node("small", group.locations.length + "곳"));
  const locations = group.locations.slice(0, 3).join(" · ") + (group.locations.length > 3 ? ` · 외 ${group.locations.length - 3}곳` : "");
  card.append(tags, heading);
  const impact = group.items.find(f => f.title === group.title && f.severity === group.level)?.impact_ko;
  if (impact) card.append(node("p", impact));
  card.append(node("p", locations, "task-path"));
  if (group.open.length) {
    const copy = node("button", "수정 요청 프롬프트 복사", "primary");
    const manual = node("textarea");
    manual.readOnly = true; manual.hidden = true; manual.setAttribute("aria-label", "직접 복사할 프롬프트");
    const prompt = fixPrompt(group, result);
    copy.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(prompt); message("프롬프트를 복사했습니다. AI 코딩 도구에 붙여넣으세요."); }
      catch { manual.hidden = false; manual.value = prompt; manual.focus(); manual.select(); }
    });
    card.append(copy, manual);
  }
  const detail = node("details", "", "task-detail");
  detail.setAttribute("name", "active-task");
  detail.append(node("summary", "위치별 근거와 수정 방법"));
  detail.addEventListener("toggle", () => {
    if (!detail.open || detail.children.length > 1) return;
    const items = [...group.open, ...group.items.filter(f => findingStatus(f) !== "open")];
    const entries = items.slice(0, 3).map(locationDetail);
    detail.append(...entries);
    entries[0].open = true;
    if (items.length > entries.length) {
      const more = node("details", "", "location-detail");
      more.append(node("summary", `나머지 ${items.length - entries.length}건 보기`));
      more.addEventListener("toggle", () => {
        if (more.open && more.children.length === 1) more.append(...items.slice(3).map(locationDetail));
      });
      detail.append(more);
    }
  });
  card.append(detail);
  return card;
}

function filterFindings() {
  const query = $("search").value.trim().toLocaleLowerCase();
  const vs = $("vs-filter").value, owasp = $("owasp-filter").value;
  const matches = groupFindings(result.findings.filter(f =>
    (!vs || f.category === vs) && (!owasp || f.owasp === owasp) &&
    (!query || [f.title, f.cwe, f.location?.file].join(" ").toLocaleLowerCase().includes(query))));
  const counts = new Map();
  for (const group of matches) counts.set(group.section, (counts.get(group.section) || 0) + 1);
  for (const section of Object.keys(sectionNames)) {
    const button = $("jump-" + section);
    button.setAttribute("aria-pressed", String(section === activeSection));
    button.hidden = section !== "findings" && section !== "coverage" && section !== activeSection && !counts.has(section);
  }
  const coverage = activeSection === "coverage";
  $("findings-label").textContent = sectionNames[activeSection];
  $("resolution").hidden = activeSection !== "findings";
  $("coverage-section").hidden = !coverage;
  $("finding-search").hidden = coverage;
  $("finding-filters").hidden = coverage || !result.coverage?.some(c => c.code);
  $("findings").hidden = coverage;
  const groups = matches.filter(g => g.section === activeSection);
  $("findings").replaceChildren(...groups.map(taskCard));
  if (!coverage && !groups.length) {
    const text = (query || vs || owasp) ? "검색 조건에 맞는 항목이 없습니다." : "열린 치명·높음 항목이 없습니다.";
    $("findings").append(node("p", text, "quiet-state"));
  }
}
function renderClassification() {
  const rows = $("classification-view").value === "owasp" ? result.owasp_coverage : result.coverage;
  const items = (rows || []).filter(row => row.code);
  $("classification").hidden = !items.length;
  $("classification-rows").replaceChildren(...items.map(row => {
    const li = node("li");
    li.append(node("strong", row.code), node("span", row.name),
      node("small", row.status + (row.findings?.length ? " · " + row.findings.length + "건" : "")));
    li.title = row.reason;
    return li;
  }));
}

function filterOptions(id, rows) {
  const select = $(id), selected = select.value;
  const options = [["", "전체"], ...(rows || []).filter(row => row.code).map(row => [row.code, row.code + " " + row.name])];
  select.replaceChildren(...options.map(([code, name]) => {
    const option = node("option", name);
    option.value = code;
    return option;
  }));
  select.value = options.some(([code]) => code === selected) ? selected : "";
}

function renderCoverage() {
  const checks = [...(result.coverage || []), ...(result.source_checks || [])];
  const completed = checks.filter(c => c.execution === "completed").length;
  const inapplicable = checks.filter(c => c.execution === "not_applicable").length;
  const pending = checks.length - completed - inapplicable;
  $("coverage-summary").textContent = checks.length
    ? [`검사 범위 · ${checks.length}개 점검 중 ${completed}개 완료`,
       inapplicable && `해당 없음(추정) ${inapplicable}개`, pending && `미완료·수동 확인 ${pending}개`].filter(Boolean).join(" · ")
    : "검사 범위 기록 없음";
  const execution = {completed: "✓ 자동 점검 범위 검사 완료", partial: "◐ 부분 점검 · 수동 확인 포함", manual: "◐ 수동 확인 필요 · 미검사", unsupported: "✕ 지원 소스 없음 · 미검사"};
  $("coverage").replaceChildren(...checks.map(c => node("li", `${c.name} — ${c.status || execution[c.execution] || "✕ 검사 여부 미확인"}. ${c.reason || ""}`)));
  const profile = result.profile || {};
  $("limitations").replaceChildren(...(profile.limitations || []).map(text => node("li", text)));
  $("profile").textContent = `${profile.framework || "프레임워크 미확인"} · 라우트 ${profile.routes || 0}개 · ${profile.auth || "인증 방식 미확인"}`;
}
function analysisState(d) {
  const note = d.analysis_note || "", issue = jobIssues.get(d.scan_id);
  if (issue || /실패|미완료|한도|중단|오류|모델.*못|분석.*못|검토.*못/.test(note))
    return {label: "AI 분석 일부 실패 ⓘ", className: "warning", hint: [note, issueHints[issue] || issueHints.error].filter(Boolean).join(" · ")};
  if (/모델|ChatGPT|AI/.test(note) && !/미사용|사용하지|없음|오프라인/.test(note))
    return {label: "AI 분석 포함", className: "", hint: note};
  return {label: "로컬 검사만", className: "local", hint: note || "모델 분석 기록 없음"};
}
function render() {
  const d = result, grade = riskGrade(d.findings), analysis = analysisState(d);
  $("repo-name").textContent = d.repo.name; $("repo-name").title = d.repo.path;
  $("repo-meta").textContent = `${d.repo.branch || "브랜치 미확인"} · ${(d.commit || "커밋 없음").slice(0, 7)} · ${dateText(d.scanned_at)}`;
  $("analysis-badge").textContent = analysis.label; $("analysis-badge").className = "analysis-badge " + analysis.className;
  $("analysis-badge").title = analysis.hint; $("analysis-badge").hidden = false;
  $("risk-grade").textContent = grade.label; $("risk").textContent = d.risk_score;
  $("risk-grade").className = "badge " + grade.level;
  taskGroups = groupFindings(d.findings);
  const urgent = taskGroups.filter(g => g.section === "findings").length;
  const later = taskGroups.filter(g => g.section === "later").length;
  const fixed = taskGroups.filter(g => g.section === "fixed");
  const done = fixed.filter(g => ["Critical", "High"].includes(g.level)).length;
  const fresh = taskGroups.filter(g => g.fresh).length;
  $("verdict-title").textContent = urgent ? `배포 전에 ${urgent}가지를 먼저 확인하세요.`
    : later ? `우선순위가 낮은 ${later}가지를 확인하세요.` : "자동 점검에서 열린 문제가 없습니다.";
  const notes = d.baseline_commit ? [fresh && `새로 발견한 문제 ${fresh}가지`, fixed.length && `해결된 문제 ${fixed.length}가지`]
    : ["이 브랜치의 현재 커밋과 비교할 이전 검사 결과가 없습니다."];
  const incomplete = [...(d.coverage || []), ...(d.source_checks || [])].filter(c => !["completed", "not_applicable"].includes(c.execution)).length;
  if (incomplete) notes.push(`직접 확인할 점검 항목 ${incomplete}개`);
  $("delta").textContent = notes.filter(Boolean).join(" · ") || "지난 검사와 비교해 새로 발견되거나 해결된 문제가 없습니다.";
  $("resolution").textContent = urgent + done ? `치명·높음 ${urgent + done}가지 중 ${done}가지 해결` : "";
  const latest = projectScans()[0];
  $("history-notice").hidden = !latest || latest.scan_id === d.scan_id;
  activeSection = "findings";
  filterOptions("vs-filter", d.coverage);
  filterOptions("owasp-filter", d.owasp_coverage);
  renderClassification(); filterFindings(); renderCoverage();
  $("empty").hidden = true; $("result").hidden = false; $("download").disabled = false;
  renderOnboarding();
}

// Keep keyboard focus inside settings until it closes.
function setPageInert(value) {
  $("workspace").inert = value;
  $("app-nav").inert = value;
}
function openDrawer(id) {
  if (activeDrawer === id) return;
  const origin = document.activeElement;
  closeDrawer(false); returnFocus = origin; activeDrawer = id;
  $(id).hidden = false;
  $("settings-backdrop").hidden = id !== "settings";
  setPageInert(true); $(id).focus();
}
function closeDrawer(restore = true) {
  if (!activeDrawer) return;
  $(activeDrawer).hidden = true; activeDrawer = null;
  $("settings-backdrop").hidden = true;
  setPageInert(false);
  if (restore && returnFocus?.isConnected) returnFocus.focus();
  returnFocus = null;
}
function showProjectDialog() {
  closeDrawer(); $("connected-next").hidden = true; $("connect-form").hidden = false;
  $("project-dialog").showModal(); $("repo-path").focus();
}
// Scan, login and background watchers
function busy(running) {
  scanning = running;
  const repo = selectedRepo(), ready = auth?.state === "ready";
  $("connect").disabled = running || connecting; $("repo-path").disabled = running || connecting;
  $("scan").disabled = running || !repo; $("scan-menu-toggle").disabled = running || !repo;
  $("scan").textContent = scanMode === "ai" && ready ? "↗ 지금 스캔 · AI" : "↗ 지금 스캔";
  $("scan").title = repo ? (scanMode === "ai" && ready ? "AI 심층 분석" : "빠른 검사 · 로컬") : "프로젝트를 연결하면 스캔할 수 있습니다";
  $("mode-ai").disabled = !ready || running; $("mode-local").disabled = running;
  $("connect-ai").hidden = ready; $("mode-local").setAttribute("aria-pressed", String(scanMode === "local"));
  $("mode-ai").setAttribute("aria-pressed", String(scanMode === "ai"));
  $("watch-project").textContent = repo?.name || "연결된 프로젝트를 선택하세요";
  $("hook-toggle").checked = !!repo?.hook;
  $("hook-toggle").disabled = running || hookPending || !repo || repo.hook === null;
  $("hook-note").textContent = !repo ? "결과만 있는 프로젝트는 먼저 연결하세요." : repo.hook === null ? "이 PC에서 커밋하지 않는 프로젝트 · 자동 감시를 지원하지 않습니다." : "이 프로젝트에 커밋하면 자동으로 검사하고 결과를 업데이트합니다.";
  $("background-llm").disabled = running || backgroundPending || (!ready && !$("background-llm").checked);
  $("notification-note").textContent = !("Notification" in globalThis) ? "이 브라우저는 데스크톱 알림을 지원하지 않습니다." :
    Notification.permission === "denied" ? "알림이 차단됐습니다. 브라우저 설정에서 허용하세요." :
    Notification.permission === "granted" ? "새로운 치명·높음 위험을 데스크톱 알림으로 알려드립니다." : "자동 스캔을 켤 때 새 위험 알림 권한을 요청합니다.";
  renderOnboarding();
}
function renderProgress(title, state) {
  $("progress").hidden = !state; $("scan-controls").hidden = !!state;
  if (!state) return;
  $("progress-title").textContent = title;
  $("progress-steps").replaceChildren(...stages.map((name, index) => {
    const item = node("li", name, index < state.stage ? "done" : index === state.stage ? "current" : "");
    if (index === state.stage) item.setAttribute("aria-current", "step");
    return item;
  }));
  $("activity").replaceChildren(...(state.log || []).slice(-8).map(text => node("li", text)));
}
function alertNewRisks(scan) {
  const fresh = freshRisks(scan);
  if (notifiedScans.has(scan.scan_id)) return false;
  if (!fresh.length) {
    const solved = groupFindings(scan.findings).filter(g => g.section === "fixed").length;
    if (!solved) return false;
    notifiedScans.add(scan.scan_id);
    message(`${scan.repo?.name || "프로젝트"} · 이번 검사에서 ${solved}가지가 해결됐습니다.`);
    return true;
  }
  notifiedScans.add(scan.scan_id);
  const text = `${scan.repo?.name || "프로젝트"} · 커밋 ${(scan.commit || "").slice(0, 7)}에서 새 치명·높음 ${fresh.length}건: ${fresh[0].title}`;
  message(text);
  if ("Notification" in globalThis && Notification.permission === "granted") {
    try { new Notification("meet vibescan · 새 위험 발견", {body: text}); } catch { /* Toast remains available. */ }
  }
  return true;
}
async function pollJob() {
  clearTimeout(pollTimer);
  const version = ++jobVersion;
  try {
    const job = await api("/api/scan");
    if (version !== jobVersion) return;
    stages = job.stages || stages;
    busy(job.state === "running");
    renderProgress(`${job.repo || ""} · ${job.offline ? "빠른 검사" : "AI 심층 분석"}`, scanning ? job : job.hook || null);
    if (scanning) { pollTimer = setTimeout(pollJob, 1000); return; }
    const signature = [job.state, job.scan_id, job.message].join("|");
    if (signature === lastJob) return;
    lastJob = signature;
    if (job.state === "completed") {
      if (job.issue) jobIssues.set(job.scan_id, job.issue);
      await refresh(job.scan_id);
      if (job.issue) { message(`스캔 완료 · 정적 검사 결과는 저장되었습니다. ${issueHints[job.issue] || issueHints.error} ${job.message || ""}`, true); await loadAuth(); }
      else message("스캔 완료 · " + (job.message || "결과를 저장했습니다."));
    } else if (job.state === "failed") message(job.message, true);
  } catch (error) {
    if (version !== jobVersion) return;
    message(error.message, true, pollJob);
    if (scanning) pollTimer = setTimeout(pollJob, 3000);
  }
}
async function startScan(mode = scanMode) {
  const repo = selectedRepo();
  if (!repo || scanning) return;
  if (mode === "ai" && auth?.state !== "ready") { openDrawer("settings"); message("AI 심층 분석을 사용하려면 ChatGPT를 연결하세요."); return; }
  scanMode = mode; remember("localStorage", "vibescan-mode", mode);
  closeScanMenu(); ++jobVersion; clearTimeout(pollTimer); busy(true);
  try { await api("/api/scan", {path: repo.path, offline: mode !== "ai"}); lastJob = ""; await pollJob(); }
  catch (error) { message(error.message, true); await pollJob(); }
}
async function loadAuth() {
  clearTimeout(authTimer);
  try {
    auth = await api("/api/auth");
    const running = auth.login?.state === "running";
    $("auth-label").textContent = running ? "ChatGPT 연결 중" : auth.state === "ready" ? "ChatGPT 연결됨" : "ChatGPT 연결 필요";
    $("account-state").textContent = running ? auth.login.message : auth.login?.state === "failed" && auth.state !== "ready" ? auth.login.message + " · " + auth.message : auth.message;
    $("login").hidden = auth.state === "register"; $("login").disabled = running;
    $("login").textContent = auth.state === "ready" ? "다시 로그인" : "ChatGPT로 로그인";
    $("logout").hidden = !["ready", "plan"].includes(auth.state); $("logout").disabled = running;
    $("register-hint").hidden = auth.state !== "register";
    $("account-state").hidden = auth.state === "register" && !running;  // the notice below already says it
    if (running && loginRequested && auth.login.url) { location.assign(auth.login.url); return; }
    if (running) authTimer = setTimeout(loadAuth, loginRequested ? 300 : 1500);
  } catch (error) {
    auth = null; $("auth-label").textContent = "ChatGPT 상태 확인 실패";
    $("account-state").textContent = error.message; message(error.message, true, loadAuth);
  }
  busy(scanning);
}
async function pollLatest() {
  try {
    const job = await api("/api/scan");
    stages = job.stages || stages;
    if (job.state === "running" && !scanning) await pollJob();
    else if (!scanning) renderProgress(job.hook ? `커밋 ${(job.hook.commit || "").slice(0, 7)} 자동 스캔 · ${job.hook.repo}` : "", job.hook || null);
    const {scan_id: id} = await api("/api/latest");
    if (id && latestSeen !== undefined && id !== latestSeen && !scanning && !scanList.some(s => s.scan_id === id)) {
      await refresh(id);  // New results in another project never change the current selection.
      const arrived = await api("/api/scans/" + encodeURIComponent(id));
      alertNewRisks(arrived);
    }
    latestSeen = id; latestPollFailed = false;
  } catch (error) {
    if (!latestPollFailed) message(error.message, true, refresh);
    latestPollFailed = true;
  }
  setTimeout(pollLatest, 3000);
}
function closeScanMenu() { $("scan-menu").hidden = true; $("scan-menu-toggle").setAttribute("aria-expanded", "false"); }

// Events
$("connect-form").addEventListener("submit", async event => {
  event.preventDefault(); if (connecting || scanning) return;
  connecting = true; busy(scanning);
  if (/^(https?:\/\/|git@)/.test($("repo-path").value.trim())) message("GitHub에서 프로젝트를 복제하는 중입니다. 저장소 크기에 따라 몇 분 걸릴 수 있습니다.");
  try {
    const repo = await api("/api/repos", {path: $("repo-path").value.trim()});
    await loadRepos(); await chooseProject(repo.path);
    $("connect-form").hidden = true; $("connected-next").hidden = false;
    $("connected-name").textContent = repo.name + " 연결 완료";
    $("first-scan").focus(); message("프로젝트를 연결했습니다. 첫 스캔을 실행하세요.");
  } catch (error) { message(error.message, true); }
  finally { connecting = false; busy(scanning); }
});
$("first-scan").addEventListener("click", () => { $("project-dialog").close(); startScan("local"); });
for (const id of ["add-project", "onboard-add"]) $(id).addEventListener("click", showProjectDialog);
$("close-project").addEventListener("click", () => $("project-dialog").close());
for (const id of ["settings-open", "auth-chip", "connect-ai", "onboard-auth"]) $(id).addEventListener("click", () => { closeScanMenu(); openDrawer("settings"); });
$("close-settings").addEventListener("click", () => closeDrawer());
$("settings-backdrop").addEventListener("click", () => closeDrawer());
$("copy-path").addEventListener("click", () => copyText(resultsPath, "결과 폴더 경로를 복사했습니다."));
$("scan").addEventListener("click", () => startScan(scanMode === "ai" && auth?.state !== "ready" ? "local" : scanMode));
$("onboard-scan").addEventListener("click", () => startScan("local"));
$("scan-menu-toggle").addEventListener("click", () => {
  const show = $("scan-menu").hidden; $("scan-menu").hidden = !show;
  $("scan-menu-toggle").setAttribute("aria-expanded", String(show));
  if (show) $("mode-local").focus();
});
$("mode-local").addEventListener("click", () => startScan("local"));
$("mode-ai").addEventListener("click", () => startScan("ai"));
$("scan-select").addEventListener("change", () => { resetFilters(); selectScan(); });
$("classification-view").addEventListener("change", renderClassification);
for (const id of ["vs-filter", "owasp-filter"]) $(id).addEventListener("change", filterFindings);
$("search").addEventListener("input", filterFindings);
for (const section of Object.keys(sectionNames)) {
  $("jump-" + section).addEventListener("click", () => {
    activeSection = section;
    filterFindings();
    const heading = $("findings-label");
    heading.style.scrollMarginTop = ($("app-nav").offsetHeight + 12) + "px";
    heading.focus({preventScroll: true});
    heading.scrollIntoView({block: "start"});
  });
}
$("projects").addEventListener("change", () => chooseProject($("projects").value));
$("latest-scan").addEventListener("click", () => {
  renderHistory(); resetFilters(); selectScan();
});
$("dismiss-toast").addEventListener("click", () => { $("toast").hidden = true; });
$("retry").addEventListener("click", () => { const action = retryAction; message(""); if (action) action(); });
$("login").addEventListener("click", async () => {
  $("login").disabled = true;
  try { await api("/api/login", {}); loginRequested = true; }
  catch (error) { message(error.message, true); }
  await loadAuth();
});
$("logout").addEventListener("click", async () => {
  $("logout").disabled = true;
  try { await api("/api/logout", {}); } catch (error) { message(error.message, true); }
  await loadAuth();
});
$("hook-toggle").addEventListener("change", async () => {
  const repo = selectedRepo(); if (!repo || repo.hook === null || hookPending) return;
  const wanted = $("hook-toggle").checked;
  // Request synchronously inside the user's click, before network awaits lose activation.
  let permission = Promise.resolve();
  if (wanted && "Notification" in globalThis && Notification.permission === "default") {
    try { permission = Promise.resolve(Notification.requestPermission()).catch(() => {}); } catch { /* No notification support. */ }
  }
  hookPending = true; busy(scanning);
  try {
    await api("/api/hook", {path: repo.path, enabled: wanted});
    await loadRepos(); message(wanted ? "커밋 후 자동 스캔을 켰습니다." : "커밋 후 자동 스캔을 껐습니다.");
  } catch (error) { message(error.message, true); }
  finally { hookPending = false; busy(scanning); }
  await permission; busy(scanning);
});
$("background-llm").addEventListener("change", async () => {
  const wanted = $("background-llm").checked;
  backgroundPending = true; busy(scanning);
  try {
    const saved = await api("/api/settings", {background_llm: wanted});
    $("background-llm").checked = saved.background_llm;
    message(saved.background_llm ? "자동 스캔에서 새 치명·높음 발견을 AI로 검토합니다. 구독 사용량이 차감됩니다." : "자동 스캔은 로컬 검사만 사용합니다.");
  } catch (error) { $("background-llm").checked = !wanted; message(error.message, true); }
  finally { backgroundPending = false; busy(scanning); }
});
$("download").addEventListener("click", () => {
  if (!result || result.repo.path !== selectedProject) return;
  const url = URL.createObjectURL(new Blob([result.report_md], {type: "text/markdown;charset=utf-8"}));
  const link = node("a"); link.href = url; link.download = `vibescan-${result.scan_id}.md`;
  link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
});
document.addEventListener("click", event => { if (!$("scan-controls").contains(event.target)) closeScanMenu(); });
document.addEventListener("keydown", event => {
  if (activeDrawer) {
    if (event.key === "Escape") { event.preventDefault(); closeDrawer(); return; }
    if (event.key === "Tab") {
      const focusable = [...$(activeDrawer).querySelectorAll('button:not([disabled]), input:not([disabled]), select:not([disabled]), summary, [tabindex="0"]')].filter(el => !el.hidden && el.getClientRects().length);
      const first = focusable[0], last = focusable[focusable.length - 1];
      if (!first) { event.preventDefault(); $(activeDrawer).focus(); }
      else if (event.shiftKey && (document.activeElement === first || document.activeElement === $(activeDrawer))) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && (document.activeElement === last || document.activeElement === $(activeDrawer))) { event.preventDefault(); first.focus(); }
    }
    return;
  }
  if (event.key === "Escape" && !$("scan-menu").hidden) { closeScanMenu(); $("scan-menu-toggle").focus(); return; }
  if ($("project-dialog").open || event.ctrlKey || event.metaKey || event.altKey || /INPUT|TEXTAREA|SELECT/.test(event.target.tagName) || event.target.isContentEditable) return;
  if (event.key === "/" && result && activeSection !== "coverage") { event.preventDefault(); $("search").focus(); }
});
async function initialize() {
  const settings = api("/api/settings").then(saved => { $("background-llm").checked = saved.background_llm; }).catch(error => message(error.message, true));
  await Promise.all([loadRepos().catch(error => message(error.message, true, loadRepos)), loadAuth(), settings]);
  await refresh(); await pollJob(); pollLatest();
}
initialize();

