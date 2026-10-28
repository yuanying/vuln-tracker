# 0008. テスト・CI・イメージの公開

- Date: 2026-10-27
- Status: Accepted

## Context

集計役の中心は段階の判定と注釈の照合であり、どちらも入力の組み合わせが多い。外に読みに行くもの
（GitHub・レジストリ・trivy・Slack）はテストから本物に繋げられない。一方で、manager のキャッシュ・
RBAC・状態の ConfigMap の読み書きは、本物の API server でしか確かめられない。

自作イメージの CI は、既定ブランチへの push ごとに `:main` を出し、イメージに source と revision の
ラベルを付ける約束がある（タスクの契約 B）。集計役自身も自作イメージなので、同じ約束に従う。

## Decision

### テストの層

| 層 | 対象 | 外部 |
|---|---|---|
| 純関数の表駆動のテスト | 段階の判定、VEX の照合、タグの系列、マニフェストの読み、状態、ダイジェスト、メトリクス | なし |
| 偽物に繋ぐテスト | GitHub とレジストリのクライアント（httptest と go-containerregistry の手元のレジストリ）、trivy の呼び出し、1 巡の流れ | interface を偽物に差し替える |
| envtest | プロセス全体。`config/rbac` の ServiceAccount になりすまして動かし、VulnerabilityReport と Pod から段階を出し、状態の ConfigMap に書くまで | 本物の API server と etcd。外部は偽物 |

envtest で `config/rbac` の権限で動かすので、集計役が必要とする権限をマニフェストが欠けば、
テストが落ちる。VulnerabilityReport の CRD は Trivy Operator の公開のリポジトリ（v0.35.0）から取って
`testdata/crds` に置く。

`go test ./...` はすべての層を含む。envtest の control plane が無いとき（`KUBEBUILDER_ASSETS` が無い
とき）は envtest の層が理由を書いて skip する。`make test` は control plane を落としてから、
race detector を付けて全体を走らせる。

### CI

pull request ごとに vet・lint・test（envtest を含む）・`go.mod` の tidy・`config/` の kustomize・
イメージのビルドを走らせる。lint の設定は gated と同じ考え方で、linter を 1 つずつ名指しする。

### イメージの公開

- main への push で `ghcr.io/yuanying/vuln-tracker:main`、`v*` のタグで同じ名前のタグを出す。
  `latest` は出さない。プラットフォームは linux/amd64 だけ
- 公開の workflow の中で先にテストを走らせ、通ってから push する
- ラベル `org.opencontainers.image.source` と `org.opencontainers.image.revision` を付ける
- main への push の後、押し出された untagged の版を `dataaxiom/ghcr-cleanup-action`（SHA で固定）で
  消す。dry-run にせず、`validate: true` で残った版を確かめる。タグ付きの版は消さない
- trivy のバイナリは公式のイメージから版を固定して取り込む。Renovate が追うが、minor の更新は
  自動でマージしない（Trivy server と minor を揃えるため。ADR 0003）

## Consequences

- 段階の定義を変えるときは表を直せば足り、envtest まで要らない
- envtest は数秒かかる。`go test ./...` に含めたので、日常のループでも走る
- RBAC を狭めすぎた変更は envtest が止める。広げすぎた変更は止めない。広げるときは ADR 0007 を直す

## 関連 ADR

- [[0001-a-resident-tracker-for-remediation-stages]]
- [[0003-scanning-candidates-through-the-shared-trivy-server]]
- [[0007-read-only-credentials]]
- [[0010-weekly-dependency-release]] — 版タグを、人の変更を含まない版については機械も打つ
