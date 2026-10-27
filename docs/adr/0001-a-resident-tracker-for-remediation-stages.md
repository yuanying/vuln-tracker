# 0001. 対応の段階を集計する常駐の集計役を作る

- Date: 2026-10-27
- Status: Accepted

## Context

本番クラスタ `fraction` では Trivy Operator（0.35.0）が、動いているワークロードのイメージを
定期的にスキャンし、VulnerabilityReport（`aquasecurity.github.io/v1alpha1`）を作っている。
レポートは TTL 24h で消えては取り直される。2026-10-27 の時点でレポートは 134 件、
イメージは 62 種、イメージ × 脆弱性の組は 3,908 ある。

修正版のある Critical は PrometheusRule `TrivyFixableCriticalVulnerability` が Slack に送っている。
これには次の問題がある。

- 鳴る数が多く、他のアラートが埋もれる
- 「直す準備はどこまで進んでいるか」が分からない。自作のイメージなら、依存は main で更新済みだが
  リリース前、リリースは出たが fleet-infra が古い版のまま、fleet-infra には入ったが本番に未反映、
  という途中の状態がある。外のイメージなら、上流が同じ系列の新しい版で直したかどうかがある。
  VulnerabilityReport は「今動いている版」しか見ないので、どれも見えない
- 「なぜ対応していないか」の理由がどこにも無い。理由は fleet-infra の `security/vex/` に
  OpenVEX で置くことになった（fleet-infra ADR 0001）が、それを読む者がまだいない

今動いている版の外側——`:main`・リリース・上流の新しい版・git に書かれた版——を読んで、
脆弱性ごとに「対応のどの段階にいるか」を決める者が要る。

## Decision

### 何をするか

`vuln-tracker` はクラスタに常駐する集計役である。次をする。

1. VulnerabilityReport を読み、本番で動いている「イメージ × 脆弱性」の一覧を作る
2. イメージごとに、直っているかもしれない版（候補）を見つけ、Trivy server にクライアントとして
   繋いでスキャンする（ADR 0003）
3. 候補のスキャン結果と git の中身から、脆弱性ごとに段階を決める（ADR 0002）
4. fleet-infra の OpenVEX の注釈を当てる（ADR 0004）
5. 段階と注釈をメトリクスとして /metrics に出す。Grafana のダッシュボードと、即時のアラートの
   PrometheusRule は、このメトリクスだけで書く（ADR 0005）
6. 週次のダイジェストを自分で Slack に送る（ADR 0006）

集計役は読むだけである。クラスタに書くのは、自分の状態を置く ConfigMap 1 つだけで、
GitHub・レジストリには書かない（ADR 0007）。

### 作り

gated・cnidaria-cni と同じく、Go と controller-runtime で書き、単一のプロセスにする。
controller-runtime はライブラリとして使い、kubebuilder の scaffold には従わない。

| 部品 | 形 |
|---|---|
| VulnerabilityReport と Pod の読み取り | manager のキャッシュで watch する |
| git（fleet-infra・k8s-manifests-fraction）、レジストリ、VEX の定期読み | Runnable |
| 候補のスキャン | Runnable。1 本ずつ順に（ADR 0003） |
| 段階の判定 | 純関数。Kubernetes の型にも外部の API にも依存させない |
| 週次ダイジェスト | Runnable |
| /metrics | manager の metrics server |

段階の判定と VEX の照合を純関数に切り出すのは、ここが集計役の中心であり、表駆動のテストで
厚く確かめたいからである。外部（GitHub・レジストリ・trivy・Slack）は interface で切り、
テストでは偽物にする。

### レプリカは 1 つ、リーダー選出は使わない

状態の ConfigMap を書き、Slack にダイジェストを送り、Trivy server を叩くのは、どれも
1 つのプロセスだけがやるべきことである。レプリカを 1 つにし、Deployment の strategy を
`Recreate` にして、古い Pod と新しい Pod が同時に動く時間を作らない。

リーダー選出は既定で使わない（フラグで有効にはできる）。レプリカ 1 では選出が守るものが無く、
Lease の RBAC と、リースの満了を待つ起動の遅れだけが増える。止まっている間はメトリクスが
途切れるが、即時のアラートは「新しいもの」だけを鳴らすので、数分の空白は害にならない。

## Consequences

- VulnerabilityReport が変わればすぐ一覧と段階が更新される。git とレジストリは定期読みなので、
  そちらの変化が段階に出るまでには読みの間隔ぶん遅れる
- 集計役が止まっている間は、ダッシュボードの段階が途切れる。即時のアラートも鳴らない。
  集計役自身の死活は、kube-prometheus の既存の `TargetDown` などで拾う
- 自宅のクラスタの資源を使う。スキャンは 1 本ずつ・間隔を空けて行う（ADR 0003）
- 判定が純関数なので、段階の定義を変えるときはテストの表を変えれば足りる

## 関連 ADR

- [[0002-remediation-stages]] — 段階の定義と、判定に何を読むか
- [[0003-scanning-candidates-through-the-shared-trivy-server]] — 候補のスキャン
- [[0004-applying-openvex-annotations]] — 注釈の重ね方
- [[0005-metrics-contract]] — メトリクスの契約と即時のアラート
- [[0006-weekly-digest-and-durable-state]] — 週次ダイジェストと状態の置き場
- [[0007-read-only-credentials]] — 資格
