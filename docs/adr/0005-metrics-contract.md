# 0005. メトリクスの契約: 発見ごとの系列と、段階ごとの件数

- Date: 2026-10-27
- Status: Accepted

## Context

段階と注釈は、既存の Grafana（kube-prometheus）で見る。即時のアラートも、Prometheus の
PrometheusRule で鳴らす。どちらも fleet-infra 側の作業単位が書くので、集計役のメトリクスは
その作業単位との **契約** になる。ダッシュボードとアラートが、このメトリクスだけで書けなければならない。

見たいものは次のとおりである。

- 段階ごとの件数の推移
- イメージごとの一覧（脆弱性・段階・注釈）
- 注釈と理由、期限切れの注釈
- 即時のアラート: 注釈も対応もない、新しい、修正版のある Critical

系列の数に気をつける必要がある。2026-10-27 の本番の発見（ADR 0002 の単位）は 6,740 あり、
そのうち Critical は 57、High は 453 である。すべてを 1 発見 1 系列で出すと、段階や注釈が
変わるたびに系列が入れ替わることも合わせて、Prometheus の負担になる。

## Decision

### 系列の分け方

- **発見ごとの系列**（`vuln_tracker_finding`）は、重大度が設定した集合（既定 `CRITICAL,HIGH`）に
  入る発見だけに出す。今の本番で 500 系列ほどになる
- **段階ごとの件数**（`vuln_tracker_findings`）は、すべての重大度について、イメージの粒度で出す
- 動いている場所は発見とは別の系列にし、ラベルで結ぶ
- 人が読む文（理由・脆弱性の題名）はラベルにしない

### 共通のラベル

| ラベル | 値 |
|---|---|
| `image` | `<registry>/<repository>`。Trivy の正規化した名前（例 `ghcr.io/yuanying/hshelf`、`index.docker.io/library/nginx`）。fleet-infra の VEX のファイルの path と同じ |
| `tag` | 動いている版のタグ |
| `digest` | 動いている版の digest（`sha256:…`） |
| `severity` | `CRITICAL`・`HIGH`・`MEDIUM`・`LOW`・`UNKNOWN`（VulnerabilityReport のまま） |
| `stage` | `in-git`・`fixed-in-release`・`fixed-upstream`・`fixed-in-main`・`unfixed`・`unscannable`・`pending`（ADR 0002） |
| `fixable` | 修正版があれば `true`、`fixedVersion` が空なら `false` |
| `vex_state` | 注釈の state（`upstream`・`not-exploitable`・`in-progress`・`investigating`・`fixed`）、注釈が無ければ `none`（ADR 0004） |
| `vex_expired` | 注釈の見直す期限が切れていれば `true`、それ以外（注釈なしを含む）は `false` |

### 系列

| 名前 | 種類 | ラベル | 値 |
|---|---|---|---|
| `vuln_tracker_finding` | gauge | 共通のすべて、`vulnerability_id`、`package`、`installed_version`、`fixed_version`、`vex_status`、`vex_review_by` | その脆弱性をそのイメージで **初めて見た時刻**（unix 秒） |
| `vuln_tracker_findings` | gauge | `image`・`tag`・`digest`・`severity`・`stage`・`fixable`・`vex_state`・`vex_expired` | 発見の件数 |
| `vuln_tracker_image_info` | gauge | `image`・`tag`・`digest`・`self_built`（`true`/`false`）・`source`（ソースの URL、分からなければ空）・`revision`（ラベルの revision、無ければ空） | 1 |
| `vuln_tracker_image_workload_info` | gauge | `image`・`tag`・`digest`・`namespace`・`kind`・`name`・`container` | 1 |
| `vuln_tracker_candidate_info` | gauge | `image`・`digest`（動いている版）・`candidate`（`main`・`release`・`upstream`・`git`）・`candidate_tag`・`candidate_digest`・`revision`・`result`（`scanned`・`failed`・`pending`） | 最後にスキャンした時刻（unix 秒）。まだなら 0 |
| `vuln_tracker_image_renovate_pr_info` | gauge | `image`・`url` | 1 |
| `vuln_tracker_scans_total` | counter | `result`（`success`・`failure`） | スキャンの本数 |
| `vuln_tracker_scan_duration_seconds` | histogram | | 1 本のスキャンの所要時間 |
| `vuln_tracker_sync_timestamp_seconds` | gauge | `target`（`fleet-infra`・`k8s-manifests-fraction`・`registry`） | 最後に読めた時刻 |
| `vuln_tracker_sync_errors_total` | counter | `target`（上に `vex` を加える） | 読めなかった回数。VEX は捨てた文書と statement の数 |
| `vuln_tracker_digest_sent_timestamp_seconds` | gauge | | 最後に週次ダイジェストを送れた時刻 |

`vuln_tracker_finding` の `package` は VulnerabilityReport の `resource`（パッケージの名前）である。
`vuln_tracker_finding` に `self_built` と `source` は持たせない。要るときは `image`・`digest` で
`vuln_tracker_image_info` と結ぶ。

### 「新しい」の定義

**初めて見た時刻** は、`image` × `vulnerability_id` の組を本番で最初に見た時刻である。タグや digest、
パッケージには依らない。版を上げても残った脆弱性は、新しくはならない。

- 状態の ConfigMap（ADR 0006）に持ち、再起動しても失わない
- 本番からその組が消えて 30 日たったら忘れる。レポートの取り直しや、一時的に版を戻したことで
  「新しい」に戻らないようにするためである
- 集計役を初めて動かしたときは、その時点のすべての組が同じ時刻になる。最初の 1 回だけは、
  それを「新しい」と扱わないよう、ConfigMap が空のときに見た組は時刻 0（unix epoch）にする

「新しい」の窓の長さはアラートのルールの側で決める（下の例では 7 日）。

### 即時のアラート

「注釈も対応もない、新しい、修正版のある Critical」は、次で書ける。

- `vuln_tracker_finding` のうち `severity="CRITICAL"`・`fixable="true"`・`vex_state="none"`・
  `stage` が `unfixed`・`fixed-upstream`・`unscannable`・`pending` のいずれか
  （`fixed-upstream` は「上流は直したが fleet-infra は未着手」なので、対応なしに数える）
- かつ `time() - vuln_tracker_finding < 7 * 86400`
- `image` ごとに `count` でまとめる

PrometheusRule は fleet-infra 側で書く。式の例（7 日の窓）を契約の確認のために残す。

```promql
count by (image) (
  (time() - vuln_tracker_finding{severity="CRITICAL", fixable="true", vex_state="none",
                                 stage=~"unfixed|fixed-upstream|unscannable|pending"})
  < 7 * 86400
)
```

### ダッシュボード

| 見たいもの | 使う系列 |
|---|---|
| 段階ごとの件数の推移 | `sum by (stage) (vuln_tracker_findings)`。重大度・注釈で絞れる |
| イメージごとの一覧 | `vuln_tracker_finding` を表にする。動いている場所は `vuln_tracker_image_workload_info` と `image`・`digest` で結ぶ |
| 注釈と理由 | `vex_state`・`vex_review_by`。理由は `image` から作る fleet-infra の VEX のファイルへのリンク |
| 期限切れ | `vex_expired="true"` |
| 対応先不明 | `vuln_tracker_image_info{source=""}` |
| 候補の様子 | `vuln_tracker_candidate_info` |

## Consequences

- 発見ごとの系列は Critical と High だけなので、Medium 以下の個々の脆弱性はダッシュボードで
  一覧できない。件数は見える。必要なら設定で重大度の集合を広げる
- 段階や注釈が変わると、`vuln_tracker_finding` と `vuln_tracker_findings` の系列が入れ替わる。
  段階の推移は件数の系列で見る
- 値に初めて見た時刻を入れるので、発見ごとの系列は値で「いくつあるか」を数えられない。数えるときは
  `count` を使う
- 初回の起動時に見たものを時刻 0 にするので、導入した直後にアラートが一斉に鳴ることは無い。
  その代わり、導入時点で既にある「注釈も対応もない」ものは即時には鳴らず、週次ダイジェストと
  ダッシュボードで拾う
- ラベルの名前と値はこの ADR が契約である。変えるときは fleet-infra のダッシュボードと
  PrometheusRule を同時に直す

## 関連 ADR

- [[0002-remediation-stages]]
- [[0004-applying-openvex-annotations]]
- [[0006-weekly-digest-and-durable-state]]
