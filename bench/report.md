# 진단 벤치마크

계획서의 35개 패턴을 재구성한 합성 표본입니다. 원본 실험 레포와 동일하지 않습니다.
코드는 실행하지 않으며 안전 표본은 각 후보 패턴에 대한 회귀 검사입니다. 실제 앱의 정밀도를 뜻하지 않습니다.

- 탐지: 35/35 · 안전 표본 오탐: 0/22
- 표본 정밀도: 1.000 · 재현율: 1.000 · F1: 1.000
- 시간: 4.87초 · 모델 호출: 0

| 표본 | VS | OWASP | 기대 | 탐지 |
|---|---|---|---|---|
| P01 | VS-06 | A04:2025 | vulnerable | True |
| P02 | VS-06 | A02:2025 | vulnerable | True |
| P03 | VS-01 | A07:2025 | vulnerable | True |
| P04 | VS-01 | A07:2025 | vulnerable | True |
| P05 | VS-01 | A07:2025 | vulnerable | True |
| P06 | VS-05 | A05:2025 | vulnerable | True |
| P07 | VS-05 | A05:2025 | vulnerable | True |
| P08 | VS-05 | A05:2025 | vulnerable | True |
| P09 | VS-05 | A05:2025 | vulnerable | True |
| P10 | VS-05 | A05:2025 | vulnerable | True |
| P11 | VS-05 | A05:2025 | vulnerable | True |
| P12 | VS-05 | A05:2025 | vulnerable | True |
| P13 | VS-05 | A05:2025 | vulnerable | True |
| P14 | VS-05 | A01:2025 | vulnerable | True |
| P15 | VS-05 | A01:2025 | vulnerable | True |
| P16 | VS-05 | A05:2025 | vulnerable | True |
| P17 | VS-05 | A08:2025 | vulnerable | True |
| P18 | VS-02 | A04:2025 | vulnerable | True |
| P19 | VS-05 | A06:2025 | vulnerable | True |
| P20 | VS-02 | A01:2025 | vulnerable | True |
| P21 | VS-02 | A01:2025 | vulnerable | True |
| P22 | VS-06 | A02:2025 | vulnerable | True |
| P23 | VS-06 | A02:2025 | vulnerable | True |
| P24 | VS-05 | A05:2025 | vulnerable | True |
| P25 | VS-05 | A05:2025 | vulnerable | True |
| P26 | VS-01 | A07:2025 | vulnerable | True |
| P27 | VS-01 | A07:2025 | vulnerable | True |
| P28 | VS-05 | A05:2025 | vulnerable | True |
| P29 | VS-05 | A05:2025 | vulnerable | True |
| P30 | VS-05 | A05:2025 | vulnerable | True |
| P31 | VS-05 | A05:2025 | vulnerable | True |
| P32 | VS-05 | A05:2025 | vulnerable | True |
| P33 | VS-01 | A07:2025 | vulnerable | True |
| P34 | VS-01 | A01:2025 | vulnerable | True |
| P35 | VS-04 | A03:2025 | vulnerable | True |
| S01 | VS-05 | A05:2025 | safe | False |
| S02 | VS-05 | A05:2025 | safe | False |
| S03 | VS-05 | A05:2025 | safe | False |
| S04 | VS-05 | A01:2025 | safe | False |
| S05 | VS-05 | A01:2025 | safe | False |
| S06 | VS-05 | A08:2025 | safe | False |
| S07 | VS-02 | A04:2025 | safe | False |
| S08 | VS-05 | A06:2025 | safe | False |
| S09 | VS-06 | A02:2025 | safe | False |
| S10 | VS-06 | A02:2025 | safe | False |
| S11 | VS-02 | A01:2025 | safe | False |
| S12 | VS-02 | A01:2025 | safe | False |
| S13 | VS-01 | A07:2025 | safe | False |
| S14 | VS-06 | A04:2025 | safe | False |
| S15 | VS-06 | A02:2025 | safe | False |
| S16 | VS-05 | A05:2025 | safe | False |
| S17 | VS-05 | A05:2025 | safe | False |
| S18 | VS-05 | A05:2025 | safe | False |
| S19 | VS-05 | A05:2025 | safe | False |
| S20 | VS-05 | A05:2025 | safe | False |
| S21 | VS-01 | A07:2025 | safe | False |
| S22 | VS-05 | A05:2025 | safe | False |

## 분류별 표본 지표

| 분류 | 탐지/취약 | 안전 표본 오탐 | 정밀도 | 재현율 |
|---|---|---|---|---|
| VS-01 | 7/7 | 0 | 1.000 | 1.000 |
| VS-02 | 3/3 | 0 | 1.000 | 1.000 |
| VS-04 | 1/1 | 0 | 1.000 | 1.000 |
| VS-05 | 20/20 | 0 | 1.000 | 1.000 |
| VS-06 | 4/4 | 0 | 1.000 | 1.000 |
| A01:2025 | 5/5 | 0 | 1.000 | 1.000 |
| A02:2025 | 3/3 | 0 | 1.000 | 1.000 |
| A03:2025 | 1/1 | 0 | 1.000 | 1.000 |
| A04:2025 | 2/2 | 0 | 1.000 | 1.000 |
| A05:2025 | 16/16 | 0 | 1.000 | 1.000 |
| A06:2025 | 1/1 | 0 | 1.000 | 1.000 |
| A07:2025 | 6/6 | 0 | 1.000 | 1.000 |
| A08:2025 | 1/1 | 0 | 1.000 | 1.000 |

P35는 고정된 Flask 버전을 내장 보안 공지와 대조하는 표본입니다.
