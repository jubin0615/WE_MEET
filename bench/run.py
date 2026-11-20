"""Ground-truth benchmark; fixtures are committed to a temporary repo, never executed."""

import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from scanner.ingest import snapshot
from scanner.static import inspect


def run():
    base = Path(__file__).resolve().parent
    truth = json.loads((base / 'ground_truth.yml').read_text(encoding='utf-8'))
    started = time.monotonic()
    with tempfile.TemporaryDirectory() as temp:
        repo = Path(temp) / 'probe'
        shutil.copytree(base / 'probe', repo)
        (repo / 'dotenv.fixture').rename(repo / '.env')
        for args in (['init', '-q'], ['add', '.'], ['-c', 'user.name=Benchmark', '-c',
                     'user.email=benchmark@example.invalid', '-c', 'commit.gpgsign=false', 'commit', '-qm', 'fixture']):
            subprocess.run(['git', '-C', str(repo), *args], check=True, capture_output=True)
        source = Path(temp) / 'snapshot'
        source.mkdir()
        _, _, files = snapshot(repo, source)
        findings = inspect(source, files)
    detected = {(f.location.file, f.location.line, code) for f in findings for code in f.kisa}
    rows = []
    for item in truth:
        rows.append({**item, 'detected': (item['file'], item['line'], item['kisa']) in detected})
    tp = sum(r['expect'] == 'vulnerable' and r['detected'] for r in rows)
    fp = sum(r['expect'] == 'safe' and r['detected'] for r in rows)
    positive = sum(r['expect'] == 'vulnerable' for r in rows)
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / positive
    text = ['# 진단 벤치마크', '', '계획서의 35개 패턴을 재구성한 합성 표본입니다. 원본 실험 레포와 동일하지 않습니다.',
            '코드는 실행하지 않으며 안전 표본은 각 후보 패턴에 대한 회귀 검사입니다. 실제 앱의 정밀도를 뜻하지 않습니다.', '',
            f'- 탐지: {tp}/{positive} · 안전 표본 오탐: {fp}/{len(rows)-positive}',
            f'- 표본 정밀도: {precision:.3f} · 재현율: {recall:.3f} · F1: {2*precision*recall/(precision+recall) if precision+recall else 0:.3f}',
            f'- 시간: {time.monotonic()-started:.2f}초 · 모델 호출: 0', '',
            '| 표본 | 분류 | 기대 | 탐지 |', '|---|---|---|---|']
    text.extend(f"| {r['id']} | {r['kisa']} | {r['expect']} | {r['detected']} |" for r in rows)
    text += ['', '## 분류별 표본 지표', '', '| 분류 | 탐지/취약 | 안전 표본 오탐 | 정밀도 | 재현율 |', '|---|---|---|---|---|']
    for code in sorted({r['kisa'] for r in rows}):
        group = [r for r in rows if r['kisa'] == code]
        positives = sum(r['expect'] == 'vulnerable' for r in group)
        found = sum(r['expect'] == 'vulnerable' and r['detected'] for r in group)
        false = sum(r['expect'] == 'safe' and r['detected'] for r in group)
        p = f'{found/(found+false):.3f}' if found+false else '미산정'
        r = f'{found/positives:.3f}' if positives else '미산정'
        text.append(f'| {code} | {found}/{positives} | {false} | {p} | {r} |')
    text += ['', 'P35는 고정된 Flask 버전을 내장 보안 공지와 대조하는 표본입니다.']
    (base / 'report.md').write_text('\n'.join(text) + '\n', encoding='utf-8')
    print(f'probe={tp}/{positive}, false_positives={fp}, precision={precision:.3f}, recall={recall:.3f}')
    missed = [r['id'] for r in rows if r['expect'] == 'vulnerable' and not r['detected']]
    print('missed:', ', '.join(missed))
    assert not missed and fp == 0, 'Detection benchmark regressed from the checked-in baseline'
    return rows


if __name__ == '__main__':
    run()
