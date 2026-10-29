# 0015. JSON の API の契約: `GET /api/findings`

- Date: 2026-10-29
- Status: Accepted

## Context

集計役の出口はメトリクス（ADR 0005）と週次ダイジェスト（ADR 0006）だけで、どちらも pi（coding agent）の
ツールからは読めない。Prometheus は gated の内側にあり、claude の ServiceAccount は通れない。
発見ごとの 2 軸の状態と結び付いた PR（ADR 0014）は、ラベルにすると系列が増えすぎる。

release-lag は同じ目的で、JSON の API を gated の Ingress の内側に出し、pi の codemode のツールから読んでいる
（release-lag の ADR 0004）。

この API は、fleet-infra（Ingress・authz）と dotfiles（pi のツール）との **契約** である。

## Decision

### 設定

| 項目 | 値 |
|---|---|
| フラグ | `--api-bind-address`（既定 `:8082`。`0` なら出さない） |
| コンテナのポート | `api`（8082）。`metrics`（8080）・`probes`（8081）は今のまま |
| Service `vuln-tracker` のポート | `api`（8082 → targetPort `api`） |
| 認証 | 持たない。前に立つ gated の Ingress が `github:yuanying` と `system:serviceaccount:fraction-agents:claude` だけを通す（fleet-infra の作業） |

API はリーダー選出の有無にかかわらずすべてのレプリカで出す。リーダーでないレプリカは評価をしないので 503 を返す
（既定はレプリカ 1、リーダー選出なし。ADR 0001）。

### `GET /api/findings`

- クエリは無い。`--detail-severities`（既定 `CRITICAL,HIGH`）の重大度の発見をすべて返す
- 200、`Content-Type: application/json`。中身は最後の評価（1 分ごと）のもの
- 起動の直後、リポジトリとレジストリを 1 回読み終える前は、どの発見も `pending` にしか見えないので、
  503 と、キー `error` に理由の文を 1 つ持つ JSON を返す
- それ以外のパスは 404、`GET` 以外は 405
- 発見の並びは、イメージの名前と digest の順、その中は VulnerabilityReport の順である。呼び出し側は並びに頼らない

### 本文

キーは camelCase。値の無いものは `null`、配列は空でも `[]`。**呼び出し側は未知のキーを無視する**。
キーを足すのは自由だが、下のキーの名前と意味は変えない。変えるときはこの ADR を改め、呼び出し側と合わせる。

最上位:

| キー | 型 | 意味 |
|---|---|---|
| `generatedAt` | 時刻（RFC 3339、UTC） | その評価の時刻 |
| `severities` | 文字列の配列 | 返す重大度（`CRITICAL`・`HIGH`・`MEDIUM`・`LOW`・`UNKNOWN` の順） |
| `findings` | 発見の配列 | 下記 |

発見（ADR 0002 の「本番で動いている版 × 脆弱性 × パッケージ」）:

| キー | 型 | 意味 |
|---|---|---|
| `image` | 文字列 | `<registry>/<repository>`。メトリクスの `image` と同じ |
| `tag`・`digest` | 文字列 | 動いている版 |
| `vulnerabilityID`・`severity`・`package`・`installedVersion` | 文字列 | VulnerabilityReport のまま |
| `fixedVersion` | 文字列 | Trivy の修正版。無ければ `""` |
| `fixable` | 真偽 | `fixedVersion` があるか（追加のキー） |
| `selfBuilt` | 真偽 | 自作のイメージか（ADR 0002） |
| `sourceRepository` | 文字列か `null` | 自作のイメージのソースのリポジトリ（`owner/name`） |
| `stage` | 文字列 | ADR 0002 の段階そのもの。メトリクスのラベル `stage` と同じ値 |
| `source.state` | 文字列 | ソース側（ADR 0014）: `unaddressed`・`pr-open`・`merged`・`released`・`not-applicable`・`unknown` |
| `source.pullRequests` | PR の配列 | ソース側に結び付いた PR |
| `manifest.state` | 文字列 | マニフェスト側（ADR 0014）: `no-fix`・`unaddressed`・`pr-open`・`merged`・`unknown` |
| `manifest.repository` | 文字列か `null` | その版を書いているマニフェストのリポジトリ（`owner/name`） |
| `manifest.pullRequests` | PR の配列 | マニフェスト側に結び付いた PR |
| `vex.state` | 文字列 | メトリクスの `vex_state` と同じ値。注釈が無ければ `none` |
| `vex.status` | 文字列か `null` | OpenVEX の status |
| `vex.reviewBy` | 文字列か `null` | `review-by`（YYYY-MM-DD） |
| `vex.document` | 文字列か `null` | VEX のファイルへのリンク（`--vex-base-url` に fleet-infra の中の path を足したもの） |
| `vex.reason` | 文字列か `null` | 注釈の理由（`impact_statement` か `action_statement`。追加のキー） |
| `vex.expired` | 真偽 | `review-by` が切れているか（追加のキー） |
| `vex.pullRequests` | PR の配列 | VEX だけを変える、結び付いた PR（ADR 0014。追加のキー） |
| `workloads` | 配列 | 動いている場所。要素は `namespace`・`kind`・`name`・`container` |
| `firstSeenAt` | 時刻か `null` | その脆弱性をそのイメージで初めて見た時刻。導入時からあったもの（メトリクスの値が 0）は `null` |

PR（`pullRequests` の要素）:

| キー | 型 | 意味 |
|---|---|---|
| `url` | 文字列 | PR の URL |
| `repository` | 文字列 | `owner/name` |
| `number` | 整数 | PR の番号 |
| `title` | 文字列 | PR のタイトル |
| `state` | 文字列 | `open`・`merged`・`closed`（マージせずに閉じた） |
| `author` | 文字列 | 作者の login |
| `link` | 文字列 | 結び付けた理由: `vuln-responder`・`renovate`・`mentions-id`（ADR 0014） |

## Consequences

- pi のツールは、この 1 本の呼び出しで発見ごとの段階・2 軸・PR・注釈を読める。refresh の API は無い
  （集計役の読みの間隔は ADR 0002・0014 のまま）
- 本文には `--detail-severities` の発見しか出ない。今の本番で 500 件ほどになる
- private のリポジトリの名前・PR のタイトルが本文に入る。gated の authz で読める人を絞ることが前提である

## 関連 ADR

- [[0001-a-resident-tracker-for-remediation-stages]]
- [[0002-remediation-stages]]
- [[0005-metrics-contract]]
- [[0014-two-axes-of-remediation-and-linked-pull-requests]]
