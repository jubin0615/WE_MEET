# 진단 벤치마크

계획서의 35개 패턴을 재구성한 합성 표본입니다. 원본 실험 레포와 동일하지 않습니다.
코드는 실행하지 않으며 안전 표본은 각 후보 패턴에 대한 회귀 검사입니다. 실제 앱의 정밀도를 뜻하지 않습니다.

- 탐지: 35/35 · 안전 표본 오탐: 0/22
- 표본 정밀도: 1.000 · 재현율: 1.000 · F1: 1.000
- 시간: 3.45초 · 모델 호출: 0

| 표본 | 분류 | 기대 | 탐지 |
|---|---|---|---|
| P01 | CI-16 | vulnerable | True |
| P02 | V-02 | vulnerable | True |
| P03 | CI-05 | vulnerable | True |
| P04 | CI-05 | vulnerable | True |
| P05 | CI-05 | vulnerable | True |
| P06 | CI-02 | vulnerable | True |
| P07 | CI-02 | vulnerable | True |
| P08 | CI-02 | vulnerable | True |
| P09 | CI-02 | vulnerable | True |
| P10 | CI-01 | vulnerable | True |
| P11 | CI-06 | vulnerable | True |
| P12 | CI-01 | vulnerable | True |
| P13 | CI-01 | vulnerable | True |
| P14 | CI-15 | vulnerable | True |
| P15 | CI-08 | vulnerable | True |
| P16 | CI-01 | vulnerable | True |
| P17 | CI-01 | vulnerable | True |
| P18 | CI-16 | vulnerable | True |
| P19 | CI-14 | vulnerable | True |
| P20 | CI-19 | vulnerable | True |
| P21 | CI-11 | vulnerable | True |
| P22 | CI-18 | vulnerable | True |
| P23 | CI-04 | vulnerable | True |
| P24 | CI-06 | vulnerable | True |
| P25 | CI-06 | vulnerable | True |
| P26 | CI-05 | vulnerable | True |
| P27 | CI-05 | vulnerable | True |
| P28 | CI-02 | vulnerable | True |
| P29 | CI-06 | vulnerable | True |
| P30 | CI-01 | vulnerable | True |
| P31 | CI-06 | vulnerable | True |
| P32 | CI-06 | vulnerable | True |
| P33 | CI-05 | vulnerable | True |
| P34 | V-01 | vulnerable | True |
| P35 | V-03 | vulnerable | True |
| S01 | CI-02 | safe | False |
| S02 | CI-06 | safe | False |
| S03 | CI-01 | safe | False |
| S04 | CI-15 | safe | False |
| S05 | CI-08 | safe | False |
| S06 | CI-01 | safe | False |
| S07 | CI-16 | safe | False |
| S08 | CI-14 | safe | False |
| S09 | CI-18 | safe | False |
| S10 | CI-04 | safe | False |
| S11 | CI-19 | safe | False |
| S12 | CI-11 | safe | False |
| S13 | CI-05 | safe | False |
| S14 | CI-16 | safe | False |
| S15 | V-02 | safe | False |
| S16 | CI-02 | safe | False |
| S17 | CI-06 | safe | False |
| S18 | CI-01 | safe | False |
| S19 | CI-06 | safe | False |
| S20 | CI-06 | safe | False |
| S21 | CI-05 | safe | False |
| S22 | CI-06 | safe | False |

## 분류별 표본 지표

| 분류 | 탐지/취약 | 안전 표본 오탐 | 정밀도 | 재현율 |
|---|---|---|---|---|
| CI-01 | 6/6 | 0 | 1.000 | 1.000 |
| CI-02 | 5/5 | 0 | 1.000 | 1.000 |
| CI-04 | 1/1 | 0 | 1.000 | 1.000 |
| CI-05 | 6/6 | 0 | 1.000 | 1.000 |
| CI-06 | 6/6 | 0 | 1.000 | 1.000 |
| CI-08 | 1/1 | 0 | 1.000 | 1.000 |
| CI-11 | 1/1 | 0 | 1.000 | 1.000 |
| CI-14 | 1/1 | 0 | 1.000 | 1.000 |
| CI-15 | 1/1 | 0 | 1.000 | 1.000 |
| CI-16 | 2/2 | 0 | 1.000 | 1.000 |
| CI-18 | 1/1 | 0 | 1.000 | 1.000 |
| CI-19 | 1/1 | 0 | 1.000 | 1.000 |
| V-01 | 1/1 | 0 | 1.000 | 1.000 |
| V-02 | 1/1 | 0 | 1.000 | 1.000 |
| V-03 | 1/1 | 0 | 1.000 | 1.000 |

P35는 고정된 Flask 버전을 내장 보안 공지와 대조하는 표본입니다.
