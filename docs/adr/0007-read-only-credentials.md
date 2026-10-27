# 0007. 資格はすべて読み取りだけにする

- Date: 2026-10-27
- Status: Proposed

## Context

集計役が外から読むものは、private の fleet-infra、public の k8s-manifests-fraction、
ghcr・Docker Hub・quay.io・registry.k8s.io・registry.fraction.jp などのレジストリ、Trivy server
である。書く先は Slack の Incoming Webhook と、自分の状態の ConfigMap だけである。

集計役は外の文書（イメージのラベル、レジストリのタグ、VEX の文）を読む。どれも信用しない入力である。
資格に書き込みの権限があれば、集計役の不具合や、読み込んだ入力の悪用が、リポジトリやレジストリへの
書き込みにつながる。

## Decision

すべての資格を、読み取りの権限だけを持つものにする。どれも Secret から受け取り、無ければ匿名で読む。

| 相手 | 資格 | 権限 | 無いとき |
|---|---|---|---|
| fleet-infra（GitHub、private） | GitHub のトークン（環境変数） | fleet-infra の contents の読み取りと、pull requests の読み取りだけ（fine-grained PAT か、読み取りだけの GitHub App） | fleet-infra が読めない。`in-git` の判定、VEX、対応表、Renovate の PR が使えない |
| k8s-manifests-fraction（GitHub、public） | 同じトークンを使う。無ければ匿名 | 読み取り | 匿名で読む（API の rate limit は 1 時間 60 回） |
| レジストリ | docker の config.json の形の Secret（`kubernetes.io/dockerconfigjson`）をファイルで渡す | pull だけ（ghcr は `read:packages`、registry.fraction.jp は pull だけのアカウント、Docker Hub は rate limit を上げるためだけ） | 匿名で読む。registry.fraction.jp の発見は `unscannable` になる |
| Trivy server | トークン（任意、環境変数） | — | 今の Trivy server はトークンを要しない |
| Slack | Incoming Webhook の URL（環境変数） | その 1 チャンネルへの投稿だけ | ダイジェストを送らない |

- git は clone しない。GitHub の API で既定ブランチの HEAD を確かめ、変わったときだけ tarball を取る。
  集計役のイメージに git を入れずに済み、資格の使い道も API の読み取りに限られる
- trivy にもレジストリの資格を同じファイルで渡す（`DOCKER_CONFIG`）

### Kubernetes の権限

| 対象 | 動詞 | 範囲 |
|---|---|---|
| VulnerabilityReport（`aquasecurity.github.io`） | get・list・watch | クラスタ全体 |
| Pod | get・list・watch | クラスタ全体（動いている digest を知るため。ADR 0002） |
| ConfigMap | create | 集計役の namespace |
| ConfigMap `vuln-tracker-state` | get・update・patch | 集計役の namespace、`resourceNames` で 1 つに絞る |

Secret は Pod に環境変数とファイルで渡し、API で読む権限は持たせない。Lease の権限は、
リーダー選出を有効にしたとき（既定では無効。ADR 0001）だけ足す。

## Consequences

- 集計役が乗っ取られても、書けるのは Slack の 1 チャンネルと自分の ConfigMap だけである
- fleet-infra を読むトークンは、ユーザーが作る（fine-grained PAT か GitHub App）。作り方と置き方は
  fleet-infra 側の作業単位の README に書く
- Pod を cluster 全体で watch するので、Pod の数だけメモリを使う。キャッシュには、動いている
  digest を知るのに要るところ（コンテナの状態のイメージ ID）だけを残す

## 関連 ADR

- [[0001-a-resident-tracker-for-remediation-stages]]
- [[0002-remediation-stages]]
- [[0006-weekly-digest-and-durable-state]]
