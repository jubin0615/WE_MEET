// Behavioral tests against the shipped HTML + JS, without a browser dependency.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const html = fs.readFileSync(path.join(__dirname, "../vibescan/web/index.html"), "utf8");
const source = fs.readFileSync(path.join(__dirname, "../vibescan/web/dashboard.js"), "utf8");

function harness({blockedStorage = false, hash = ""} = {}) {
  const elements = new Map();
  let document;
  class Element {
    constructor(tag = "div") {
      this.tagName = tag.toUpperCase(); this.children = []; this.handlers = {};
      this.value = ""; this._text = ""; this.dataset = {}; this.style = {};
      this.attributes = {}; this.hidden = false; this.disabled = false; this.isConnected = true;
    }
    set textContent(text) { this._text = String(text); this.children = []; }
    get textContent() { return this._text + this.children.map(c => c.textContent).join(""); }
    set innerHTML(_) { throw new Error("Untrusted HTML must never be parsed"); }
    append(...children) { this.children.push(...children); }
    replaceChildren(...children) { this._text = ""; this.children = children; }
    addEventListener(type, callback) { this.handlers[type] = callback; }
    setAttribute(name, value) { this.attributes[name] = String(value); }
    getAttribute(name) { return this.attributes[name]; }
    get classList() {
      const self = this;
      return {
        contains(name) { return (self.className || "").split(" ").includes(name); },
        toggle(name, force) {
          const names = new Set((self.className || "").split(" ").filter(Boolean));
          if (force === undefined) force = !names.has(name);
          force ? names.add(name) : names.delete(name);
          self.className = [...names].join(" ");
        },
        add(name) { this.toggle(name, true); },
        remove(name) { this.toggle(name, false); },
      };
    }
    querySelectorAll(selector) {
      const all = this.children.flatMap(c => [c, ...c.querySelectorAll("*")]);
      if (selector === "*") return all;
      if (selector.startsWith(".")) return all.filter(c => c.classList.contains(selector.slice(1)));
      const attr = selector.match(/^\[data-(\w+)="([^"]*)"\]$/);
      if (attr) return all.filter(c => c.dataset[attr[1]] === attr[2]);
      if (selector === "button") return all.filter(c => c.tagName === "BUTTON");
      return all.filter(c => ["BUTTON", "INPUT", "SELECT", "SUMMARY"].includes(c.tagName) && !c.disabled);
    }
    querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
    focus() { document.activeElement = this; }
    select() { this.selected = true; }
    click() { this.focus(); return this.handlers.click?.({target: this, preventDefault() {}}); }
    contains(target) { return this === target || this.querySelectorAll("*").includes(target); }
    showModal() { this.open = true; } close() { this.open = false; }
    scrollIntoView() {} getClientRects() { return this.hidden ? [] : [{}]; }
  }
  for (const match of html.matchAll(/<([a-z0-9]+)\b([^>]*\bid="([^"]+)"[^>]*)>/gi)) {
    assert(!elements.has(match[3]), "Duplicate HTML id " + match[3]);
    const element = new Element(match[1]); element.id = match[3];
    element.hidden = /\bhidden\b/.test(match[2]); element.disabled = /\bdisabled\b/.test(match[2]);
    elements.set(match[3], element);
  }
  const get = id => {
    if (elements.has(id)) return elements.get(id);
    for (const el of elements.values()) {
      const found = el.querySelectorAll("*").find(c => c.id === id);
      if (found) return found;
    }
    throw new Error("Missing HTML element: " + id);
  };
  const sidebar = new Element("aside"), body = new Element("body");
  document = {getElementById: get, body, documentElement: new Element("html"), activeElement: body,
    createElement: tag => new Element(tag), createElementNS: (_, tag) => new Element(tag),
    querySelector: selector => selector === ".sidebar" ? sidebar : null, handlers: {},
    addEventListener(type, fn) { this.handlers[type] = fn; }};
  for (const id of ["settings"]) { const content = new Element(); content.className = "drawer-body"; get(id).append(content); }
  const storage = new Map([["vibescan-token", "test-ticket"]]), requests = [], notices = [], copies = [], downloads = [], replaced = [];
  const store = {getItem(key) { if (blockedStorage) throw Error("blocked"); return storage.get(key); },
    setItem(key, value) { if (blockedStorage) throw Error("blocked"); storage.set(key, value); }};
  const context = vm.createContext({document, location: {hash, pathname: "/", search: "", assign: url => replaced.push(url)},
    history: {replaceState: (...args) => replaced.push(args)}, localStorage: store, sessionStorage: store,
    fetch: () => new Promise(() => {}), clearTimeout() {}, setTimeout() {},
    navigator: {clipboard: {writeText: async value => copies.push(value)}},
    URL: {createObjectURL: blob => { downloads.push(blob); return "blob:test"; }, revokeObjectURL() {}}, Blob,
    Notification: class { static permission = "granted"; constructor(_, opts) { notices.push(opts.body); } }});
  vm.runInContext(source, context);
  const run = code => vm.runInContext(code, context);
  const seed = data => { context.seed = data; run("result = seed; selectedProject = seed.repo.path; render();"); };
  const respond = handler => {
    context.fetch = async (url, options) => { requests.push({url, options}); return {ok: true, json: async () => handler(url, options)}; };
  };
  return {context, get, run, seed, respond, requests, notices, copies, downloads, storage, document, replaced};
}
const finding = (id, severity = "High", extra = {}) => ({
  id, title: "문제 " + id, severity, confidence: "Likely", status: "open", change: "existing",
  location: {file: "app.py", line: 12}, cwe: "CWE-89", category: "VS-05", owasp: "A05:2025", evidence: "execute(query)",
  how_found: ["정적 규칙"], impact_ko: "입력값이 쿼리 구조를 바꿉니다.", remediation_ko: "매개변수 바인딩을 사용하세요.",
  fix_diff: "--- a/app.py\n+++ b/app.py\n-query\n+safe_query", ...extra,
});
const sample = (id = "scan-a", repo = "C:/a", findings = []) => {
  const summary = {Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0};
  findings.filter(f => f.status === "open" && f.change !== "fixed").forEach(f => summary[f.severity]++);
  return {scan_id: id, repo: {name: repo.split("/").pop(), path: repo, branch: "main"},
    commit: "abcdef1234", scanned_at: "2026-11-20T00:00:00Z", risk_score: 40, findings, summary,
    delta: {new: 1, fixed: 1}, baseline_commit: "previous", analysis_note: "로컬 규칙으로 작성",
    profile: {routes: 2, limitations: ["자동 검사는 안전 보증이 아닙니다."]}, coverage: [], report_md: "# 보고서"};
};
async function main() {
  const h = harness(), {get, run} = h;
  const filtered = sample("filters", "C:/a", [finding("sql", "High", {rule_id: "mixed"}),
    finding("path", "High", {rule_id: "mixed", owasp: "A01:2025", location: {file: "path.js", line: 5}})]);
  filtered.coverage = [{code: "VS-05", name: "주입", status: "취약 후보", findings: ["sql", "path"]}];
  filtered.owasp_coverage = [{code: "A05:2025", name: "인젝션", url: "https://top10.owasp.org/2025/A05_2025-Injection/",
    status: "취약 후보", findings: ["sql"]}, {code: "A01:2025", name: "접근 통제", status: "취약 후보", findings: ["path"]}];
  h.seed(filtered);
  assert.match(get("classification-rows").textContent, /VS-05.*2건/);
  get("classification-view").value = "owasp";
  get("classification-view").handlers.change();
  assert.match(get("classification-rows").textContent, /A01:2025/);
  get("vs-filter").value = "VS-05"; get("owasp-filter").value = "A05:2025";
  get("owasp-filter").handlers.change();
  assert.match(get("findings").textContent, /app.py/);
  assert.doesNotMatch(get("findings").textContent, /path.js/);
  assert.equal(get("findings").querySelectorAll("*").find(e => e.tagName === "A").href, filtered.owasp_coverage[0].url);
  get("vs-filter").value = "VS-01"; get("vs-filter").handlers.change();
  assert.match(get("findings").textContent, /검색 조건/);
  run("resetFilters()");
  const data = sample("scan-a", "C:/a", [
    finding("critical", "Critical", {status: "dismissed"}),
    finding("fixed", "High", {change: "fixed"}),
    finding("medium", "Medium"),
    finding("new", "High", {change: "new"}),
    finding("info", "Info"),
  ]);
  data.source_checks = [{id: "dependencies", name: "의존성 보안 공지", execution: "partial", reason: "고정 버전 2건 대조"}];
  h.seed(data);
  assert.equal(get("risk-grade").textContent, "위험"); // dismissed Critical is excluded
  assert.equal(get("findings").children.length, 1);
  assert.match(get("verdict-title").textContent, /1가지/);
  assert.match(get("resolution").textContent, /2가지 중 1가지/);
  assert.equal(get("coverage-section").hidden, true);
  assert.equal(get("jump-findings").getAttribute("aria-pressed"), "true");
  for (const [section, size] of [["later", 2], ["fixed", 1], ["dismissed", 1], ["coverage", 0]]) {
    const jump = get("jump-" + section);
    assert.equal(jump.hidden, false);
    await jump.click();
    assert.equal(get("findings").children.length, size);
    assert.equal(get("findings").hidden, section === "coverage");
    assert.equal(get("coverage-section").hidden, section !== "coverage");
    assert.equal(jump.getAttribute("aria-pressed"), "true");
    assert.equal(h.document.activeElement, get("findings-label"));
  }
  await get("jump-findings").click();
  assert.match(get("coverage").textContent, /의존성 보안 공지.*고정 버전 2건 대조/);
  assert.equal(h.document.activeElement, get("findings-label"));
  get("search").value = "missing"; run("filterFindings()");
  assert.equal(get("jump-later").hidden, true);
  assert.match(get("findings").textContent, /검색 조건/);
  assert.equal(get("coverage-section").hidden, true);
  run("resetFilters()");
  h.seed({...sample("clean"), baseline_commit: null});
  assert.match(get("verdict-title").textContent, /열린 문제가 없습니다/);
  assert.match(get("delta").textContent, /비교할 이전 검사 결과가 없습니다/);
  h.seed(sample("later", "C:/a", [finding("m", "Medium")]));
  assert.match(get("verdict-title").textContent, /우선순위가 낮은 1가지/);

  const hostile = finding("hostile", "High", {rule_id: "secret", title: "<img onerror=alert(1)>",
    evidence: "private literal", remediation_ko: "private literal", fix_diff: "+private literal",
    original_severity: "Critical", change: "new"});
  h.seed(sample("mixed", "C:/a", [hostile, finding("older", "Low", {rule_id: "secret",location:{file:"b.py",line:2}}),
    finding("closed", "Critical", {rule_id:"secret", change:"fixed", location:{file:"old.py",line:1}})]));
  const card = get("findings").children[0];
  assert.match(card.textContent, /2곳/);
  assert.equal(get("jump-fixed").hidden, true);
  const copy = card.querySelector("button");
  await copy.click();
  assert.match(h.copies[0], /app.py:12/); assert.match(h.copies[0], /b.py:2/);
  assert.doesNotMatch(h.copies[0], /private literal|onerror|old.py/);
  const clipboard = h.context.navigator.clipboard;
  h.context.navigator.clipboard = null;
  await copy.click();
  const manual = h.document.activeElement;
  assert.equal(manual.tagName, "TEXTAREA"); assert.equal(manual.hidden, false);
  assert.equal(manual.value, h.copies[0]); assert.equal(manual.selected, true);
  h.context.navigator.clipboard = clipboard;
  const detail = card.querySelector(".task-detail");
  detail.open = true; detail.handlers.toggle();
  const loc = detail.querySelector(".location-detail"); loc.handlers.toggle();
  assert.match(loc.textContent, /private literal/);
  assert.match(loc.textContent, /치명 → 높음/);
  assert.match(loc.textContent, /가능성 높음/);
  await loc.querySelector("button").click(); assert.equal(h.copies[1], hostile.fix_diff);
  const legacy = finding("legacy");
  h.seed(sample("legacy", "C:/a", [legacy, {...legacy, id:"other", location:{file:"other.py", line:2}}]));
  assert.equal(get("findings").children.length, 1);
  console.log("Grouped tasks, partial resolution, legacy reports, inline evidence and prompt privacy: OK");

  const a1 = sample("a1"), a2 = {...sample("a2"), scanned_at: "2026-11-21T00:00:00Z", trigger: "git-hook"};
  const b = sample("b1", "C:/b");
  h.context.scans = [a2, b, a1];
  run('scanList = scans; repoList = [{path:"C:/a", name:"a", hook:true}, {path:"C:/empty",name:"empty",hook:null}]; selectedProject="C:/a";');
  h.respond(url => ({a1, a2, b1: b}[url.split("/").pop()]));
  await run('chooseProject("C:/a")');
  assert.equal(get("scan-select").children.length, 2);
  assert.match(get("scan-select").children[0].textContent, /자동/);
  assert.equal(get("projects").children.length, 3);
  await run('chooseProject("C:/b")');
  assert.equal(get("repo-name").textContent, "b"); assert.equal(get("scan").disabled, true);
  assert.equal(get("scan-select").children.length, 1);
  assert.equal(h.storage.get("vibescan-project"), "C:/b");
  await run('chooseProject("C:/empty")');
  assert.equal(get("empty").hidden, false); assert.equal(get("result").hidden, true);
  assert.equal(get("scan").disabled, false); assert.equal(get("hook-toggle").disabled, true);
  console.log("Connected + result-only project union, scoped history, persistent selection and empty state: OK");

  // Out-of-order network replies cannot show A's scan below B's heading.
  const race = harness(); race.context.rows = [a1, b];
  race.run('scanList=rows; repoList=[]; selectedProject="C:/a";');
  const pending = {};
  race.context.fetch = url => new Promise(resolve => { pending[url] = data => resolve({ok:true,json:async () => data}); });
  const first = race.run('chooseProject("C:/a")');
  const second = race.run('chooseProject("C:/b")');
  pending["/api/scans/b1"](b); await second;
  pending["/api/scans/a1"](a1); await first;
  assert.equal(race.get("repo-name").textContent, "b");
  assert.equal(race.run("result.repo.path"), "C:/b");
  console.log("Stale scan response ignored after project switch: OK");

  await run('chooseProject("C:/a", "a1")');
  assert.equal(get("history-notice").hidden, false);
  run('repoList.push({name:"a",path:"D:/a",hook:false}); renderProjects()');
  assert.match(get("projects").textContent, /D:\/a/);
  assert.match(get("projects").textContent, /C:\/a/);
  h.context.fresh = sample("alert", "C:/a", [finding("f", "High", {change: "new"})]);
  assert.equal(run("alertNewRisks(fresh)"), true); assert.equal(run("alertNewRisks(fresh)"), false);
  assert.equal(h.notices.length, 1); assert.match(h.notices[0], /치명·높음/);
  console.log("Historical selection and deduplicated new-risk notification: OK");

  const scan = harness(), saved = sample("saved", "C:/a", [finding("f")]);
  scan.context.saved = saved;
  scan.run('selectedProject="C:/a"; repoList=[{path:"C:/a",name:"a",hook:false}]; stages=["수집","정찰","계획","검사","검토"];');
  let running = true;
  scan.respond((url, options) => {
    if (url === "/api/scan") return running ? {state:"running",repo:"C:/a",offline:true,stage:2,log:["검사 중"]} : {state:"completed",repo:"C:/a",scan_id:"saved",issue:"limit",message:"사용량 초과"};
    if (url === "/api/scans") return {scans:[saved],results_path:"C:/out"};
    if (url === "/api/auth") return {state:"ready",message:"연결됨",login:{state:"idle"}};
    return saved;
  });
  await scan.run('startScan("local")');
  assert.deepEqual(JSON.parse(scan.requests[0].options.body), {path:"C:/a",offline:true});
  assert.equal(scan.requests[0].options.headers["X-VibeScan-Token"], "test-ticket");
  assert.equal(scan.get("progress").hidden, false);
  assert.equal(scan.get("progress-steps").children[2].className, "current");
  running = false; await scan.run("pollJob()");
  assert.equal(scan.get("result").hidden, false); assert.equal(scan.get("scan").disabled, false);
  assert.match(scan.get("message").textContent, /정적 검사 결과는 저장/);
  assert.match(scan.get("analysis-badge").textContent, /일부 실패/);
  assert.match(scan.get("analysis-badge").title, /한도/);
  await scan.get("download").click(); assert.equal(await scan.downloads[0].text(), "# 보고서");
  scan.respond(url => url === "/api/auth" ? {state:"register",message:"등록 필요",login:{state:"idle"}} : {});
  await scan.run("loadAuth()");
  assert.equal(scan.get("login").hidden, true); assert.equal(scan.get("register-hint").hidden, false); assert.equal(scan.get("account-state").hidden, true);
  assert.equal(scan.get("mode-ai").disabled, true);
  console.log("Explicit offline POST, progress, AI failure recovery, report download and auth gating: OK");

  const poll = harness();
  poll.respond(url => url === "/api/scan" ? {state:"idle"} : {scan_id:null});
  await poll.run("pollLatest()");
  const arrivals = []; poll.context.arrivals = arrivals;
  poll.run("refresh = async id => arrivals.push(id)");
  poll.respond(url => url === "/api/scan" ? {state:"idle"} : url === "/api/latest" ? {scan_id:"first"} : sample("first"));
  await poll.run("pollLatest()"); assert.deepEqual(arrivals, ["first"]);
  const blocked = harness({blockedStorage:true,hash:"#fresh-ticket"});
  assert.equal(blocked.run("token"), "fresh-ticket");
  assert.equal(blocked.replaced[0][2], "/");
  assert.equal((html.match(/aria-live=/g) || []).length, 1);
  assert.doesNotMatch(source, /\.innerHTML\s*=/);
  console.log("First hook result, unavailable storage, ticket hash isolation, single live region: OK");
}
main().catch(error => { console.error(error); process.exitCode = 1; });

