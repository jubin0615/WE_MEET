"""Check every bundled rule and its positive/negative fixture; fail on runner errors."""

import json
import os
import shutil
import subprocess
from pathlib import Path

from scanner.owasp import catalog, classify


def main():
    root = Path(__file__).resolve().parents[1] / 'rules/vibescan'
    configs = sorted(root.glob('*.yml'))
    assert configs, 'No bundled rules'
    categories = {item["code"] for item in catalog("vibescan-top10")["items"]}
    unmapped = catalog("owasp-top10-2025")["unmapped_cwes"]
    for config in configs:
        rules = json.loads(config.read_text(encoding='utf-8'))['rules']
        fixtures = [p for p in root.glob(config.stem + '.*') if p.suffix in ('.py', '.js', '.html', '.java', '.php', '.rb', '.go')]
        assert fixtures, f'Missing tests: {config.name}'
        content = '\n'.join(p.read_text(encoding='utf-8') for p in fixtures)
        for rule in rules:
            meta = rule['metadata']
            detail = meta['vibescan']
            assert detail['category'] in categories and detail['limitations_ko'].strip(), config.name
            assert all(detail.get(k) for k in ('title_ko', 'remediation_ko', 'severity', 'confidence')), config.name
            assert classify(meta['cwe']) or meta['cwe'] in unmapped, config.name
            assert 'ruleid: ' + rule['id'] in content and 'ok: ' + rule['id'] in content
        # Windows Semgrep 1.185's parallel test runner races on its settings file.
        result = subprocess.run([shutil.which('semgrep') or 'semgrep', '--test', '--strict', '--config', str(config),
                                 *map(str, fixtures), '--json', '--metrics=off', '--disable-version-check'],
                                capture_output=True, timeout=120, env={**os.environ, 'PYTHONUTF8': '1'})
        data = json.loads(result.stdout)
        checks = [c for r in data['results'].values() for c in r['checks'].values()]
        assert (result.returncode == 0 and not data['config_with_errors'] and not data['config_missing_tests']
                and len(checks) == len(rules) and all(c['passed'] for c in checks)), config.name
        print(f'{config.stem}: OK', flush=True)
    print(f'{len(configs)} rule files passed')


if __name__ == '__main__':
    main()
