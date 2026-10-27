# 0004. OpenVEX の注釈を、Trivy と同じ規則で発見に重ねる

- Date: 2026-10-27
- Status: Proposed

## Context

なぜ対応していないかの注釈は、fleet-infra の `security/vex/<registry>/<repository>.openvex.json` に
OpenVEX 0.2.0 で置かれる（fleet-infra ADR 0001、`security/vex/README.md`）。集計役はこれを読み、
ダッシュボードと週次ダイジェストに状態・理由・見直す期限を出し、注釈のある発見を即時のアラートから
外す。

注釈の約束は fleet-infra の README が正であり、集計役はそれに従う側である。

## Decision

### 読み方

fleet-infra の既定ブランチから `security/vex/` の下の `*.openvex.json` をすべて読む
（読む間隔は ADR 0002）。1 つの文書が読めない・形が約束と違うときは、その文書だけを捨てて
エラーを数え（ADR 0005）、他の文書は使う。読めなかった文書の注釈は「注釈なし」に戻るので、
即時のアラートの側に倒れる。

### 照合

README の「照合の規則」に従い、`github.com/openvex/go-vex` の照合を使う。Trivy も同じ
ライブラリを使っているので、Trivy CLI に `--vex` で渡したときと結果がずれない。

1. 発見の動いている版から、イメージの purl
   `pkg:oci/<repository の最後の要素>@<digest>?repository_url=<registry>/<repository>` を作る。
   registry と repository は VulnerabilityReport の `report.registry.server` と
   `report.artifact.repository`、digest は `report.artifact.digest` である
2. statement の脆弱性の名前（か別名）が発見の脆弱性の ID と一致し、product がイメージの purl に
   当たれば効く
3. statement に subcomponent があれば、発見のパッケージの purl（レポートの `packagePURL`）にも
   当たる必要がある
4. 複数の statement が当たれば、`timestamp` の新しい方を取る

注釈は本番で動いている版の発見にだけ当てる。候補の版には当てない（段階は候補のスキャンの結果
そのものから決める）。

### 発見に付けるもの

| 項目 | 出どころ |
|---|---|
| 注釈の state | `status_notes` の `state`（`upstream`・`not-exploitable`・`in-progress`・`investigating`・`fixed`）。当たる statement が無ければ `none` |
| 注釈の status | OpenVEX の `status` |
| 見直す期限 | `status_notes` の `review-by` |
| 期限切れ | 見直す期限の日が、集計役のタイムゾーン（既定 `Asia/Tokyo`）の今日より前なら期限切れ |
| 理由 | `impact_statement` か `action_statement`。メトリクスには出さず、ダイジェストにだけ出す |

`status_notes` が約束の形でない（`state` が無い、`review-by` が日付でない）statement は、
当たっても注釈として使わず、エラーとして数える。

### 段階との関係

注釈は段階を変えない。段階は「どこまで直ったか」を、注釈は「人がどう判断したか」を表し、
両方を並べて出す。たとえば `fixed-upstream` かつ注釈 `upstream` の発見は、注釈が書かれた後に
上流が直したことを示しており、注釈を見直すきっかけになる。

## Consequences

- 注釈の照合が Trivy と同じになるので、fleet-infra の `scripts/check-vex.sh` を通った注釈が
  集計役で当たらない、ということが起きにくい
- 理由の文はメトリクスのラベルにしない（長く、変わりやすく、系列を増やす）。ダッシュボードでは、
  発見から fleet-infra の VEX のファイルへのリンクで理由を見せる。ファイルの path はイメージの
  名前から決まる（`security/vex/<registry>/<repository>.openvex.json`）ので、リンクはラベルだけで作れる
- 1 つの版だけの注釈（digest 指定）は、版を上げると当たらなくなり「注釈なし」に戻る。
  これは fleet-infra ADR 0001 が意図した挙動である

## 関連 ADR

- [[0002-remediation-stages]]
- [[0005-metrics-contract]]
- [[0006-weekly-digest-and-durable-state]]
