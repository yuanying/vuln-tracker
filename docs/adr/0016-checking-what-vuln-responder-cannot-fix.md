# 0016. vuln-responder が直せない自作のソースを、github-writer.json と archived で見つける

- Date: 2026-11-17
- Status: Accepted

## Context

vuln-responder（fraction-agents の係）は、自作のイメージのソースのリポジトリに PR を出して直す（ADR 0009・0011）。
vuln-responder の GitHub App（`fraction-vuln-responder`）のインストール先は持ち主の All repositories なので、
App の資格の上では持ち主のどのリポジトリにも書ける。vuln-responder が実際に書けるのは、fleet-infra の
`apps/fraction-agents/prod/vuln-responder/github-writer.json` の `repositories` に絞ったリポジトリだけである。
書ける一覧は、この 1 か所に手で書いてある。

自作のイメージを増やしたとき、この一覧への入れ忘れが起きる。入れ忘れたリポジトリへの依頼は、
vuln-responder が PR を出せずに終わるので、気づくのが遅れる。アーカイブ済みのリポジトリも同じく、PR を出せない。

集計役は、本番で動く自作のイメージのソースのリポジトリを、イメージのラベル `org.opencontainers.image.source` と
`security/image-sources.yaml` から知っている（ADR 0002、`vuln_tracker_image_info` の `self_built`・`source`）。
そのため、漏れは集計役の側で見つけられる。

## Decision

### 何を「書ける」とみなすか

- fleet-infra の github-writer.json を、**vuln-responder が書ける一覧** として読む。installation は All repositories なので、
  書ける範囲を決めているのはこの一覧だけであり、集計役はこれを読めば足りる
- responder の App の installation は読まない。読む必要が無いうえ、読むにはその App の鍵が要る。鍵を集計役に渡すことは、
  書ける資格を書き手の係だけに閉じ込める fraction-agents の隔離（fraction-agents の ADR 0027）を壊し、
  集計役の資格は読み取りだけ（ADR 0007）という決定にも反する
- 読むのは `repositories` の各要素の `owner` と `name` だけで、ほかのキーは無視する。名前の大文字小文字は区別しない

### 設定

| フラグ | 既定 | 意味 |
|---|---|---|
| `--responder-writer-config` | `""` | `--fleet-infra` のリポジトリの中の github-writer.json の path。空なら検査しない。本番は `apps/fraction-agents/prod/vuln-responder/github-writer.json` |

- fleet-infra の定期読み（VEX・`security/image-sources.yaml` と同じ、`--git-interval` ごと）で読む。GitHub の tarball からは
  マニフェストと VEX 文書のほかに、この path のファイルだけを残す
- ファイルが無い・JSON として読めない・`repositories` が無い・要素に `owner` か `name` が無いときは、前に読めた一覧を保ち、
  ログに出して `vuln_tracker_sync_errors_total{target="vex"}` に数える（`security/image-sources.yaml` と同じ扱い）。
  一度も読めていなければ、`not-writable` は出さない

### 検査

対象は、本番で動いている自作のイメージ（`vuln_tracker_image_info` の `self_built="true"`）のソースのリポジトリである。
発見の有無は問わない。リポジトリごとに次を調べる。

| reason | 条件 |
|---|---|
| `not-writable` | github-writer.json に無い |
| `archived` | GitHub でアーカイブ済み。集計役の App（ADR 0013）で `GET /repos/{owner}/{repo}` の `archived` を読む |

- 当てはまる reason ごとに `vuln_tracker_responder_coverage_gap{source_repository="owner/name",reason}` を 1 で出す（ADR 0005 の追記）。
  両方なら 2 系列、漏れが無ければ系列を出さない。漏れが直れば次の評価で系列が消える。フラグが空なら何も出さない
- archived の読みは、リポジトリごとに 1 時間に 1 回までにする。間隔は、読めたかどうかを問わず最後に試した時刻から数える。
  読めなかったとき（404・権限が無い・GitHub の障害）も 1 時間は試し直さず、前に読めた値を保ち、
  `vuln_tracker_sync_errors_total{target="repositories"}` に数える。すべて読めた回は
  `vuln_tracker_sync_timestamp_seconds{target="repositories"}` を進める。一度も読めていないリポジトリはアーカイブされていないとみなす
- 本番から消えたソースのリポジトリの読みは忘れる

### アラート

PrometheusRule は fleet-infra の側で書く（`vuln_tracker_responder_coverage_gap == 1` が 1 時間続いたら、
`source_repository` ごとに warning）。

### 依頼

漏れたリポジトリへの依頼は止めない。依頼の条件と振る舞い（ADR 0009・0011）は変えない。

### rate limit

archived の読みは、読めても読めなくても、ソースのリポジトリの数だけ 1 時間に 1 回である。ADR 0014 の見積もり（ソースのリポジトリ 13）に
1 時間 13 回を足して 273 回以下、上限（1 時間 5,000 回）の 6% ほどに収まる（ADR 0014 の追記）。

## Consequences

- 自作のイメージを増やして github-writer.json に入れ忘れると、1 時間ほどでアラートが鳴る
- installation を All repositories から選んだリポジトリに戻すと、github-writer.json にあっても書けないリポジトリが生じ、
  集計役はそれを見つけられない。戻すときはこの ADR を直す
- github-writer.json の path が変われば、fleet-infra のフラグも直す。path を誤ると、読めないエラーが増え続ける
  （一度も読めていなければ `not-writable` は出ない）
- アーカイブしたリポジトリのイメージを本番で動かし続ける限り、`archived` は鳴り続ける。イメージを置き換えるか、ルールの側で除く

## 関連 ADR

- [[0002-remediation-stages]]
- [[0005-metrics-contract]]
- [[0007-read-only-credentials]]
- [[0009-requesting-triage-from-vuln-responder]]
- [[0013-a-dedicated-github-app]]
- [[0014-two-axes-of-remediation-and-linked-pull-requests]]
