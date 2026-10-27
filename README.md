# vuln-tracker

本番クラスタで動くイメージの脆弱性について、対応の段階と注釈（OpenVEX）を集計してメトリクスと週次ダイジェストに出す集計役。

## 何をするか

- Trivy Operator の VulnerabilityReport と Pod を読み、本番で動いている「イメージ × 脆弱性 × パッケージ」（発見）の一覧を作る
- イメージごとに、直っているかもしれない版（候補）を探し、Trivy Operator の Trivy server にクライアントとして繋いでスキャンする
- 候補のスキャンの結果から、発見ごとに **段階** を決める
- fleet-infra の `security/vex/` の OpenVEX の注釈を、Trivy と同じ規則で当てる
- 段階と注釈を Prometheus のメトリクスとして出し、週次のダイジェストを Slack に送る
- 有効にすれば、注釈も対応もない新しい修正版ありの Critical を、fraction-agents の vuln-responder に A2A で依頼する

読むだけで、書くのは自分の状態の ConfigMap 1 つと Slack、それに有効にしたときの vuln-responder への依頼だけである。設計の判断は [docs/adr/](docs/adr/) にある。

## 段階

| 段階 | 意味 | 対象 |
|---|---|---|
| `in-git` | fleet-infra か k8s-manifests-fraction に書かれた版では直っている。本番に未反映 | すべて |
| `fixed-in-release` | リリースのタグでは直っている。git は古い版のまま | 自作 |
| `fixed-upstream` | 上流の同じ系列の新しい版では直っている。git は古い版のまま | 外 |
| `fixed-in-main` | `:main` では直っている。リリース未 | 自作 |
| `unfixed` | どの候補でも残っている | すべて |
| `unscannable` | 直った候補が無く、スキャンかレジストリの読みに失敗したものがある | すべて |
| `pending` | 直った候補が無く、まだスキャンしていない候補がある | すべて |

本番が直った版になれば、その発見は消える。

- **自作** は、イメージのラベル `org.opencontainers.image.source` が `--self-source-prefix`（既定 `https://github.com/yuanying/`）で始まるもの。候補は `:main`、レジストリのタグで最新のリリース、git に書かれた版
- **外** はそれ以外。候補は同じ系列（`v` の有無・major・数字の数・接尾辞が同じ）の最新版、git に書かれた版。`latest` のように版の無いタグは、同じタグの digest が変わったらその digest
- 段階の詳しい定義は [ADR 0002](docs/adr/0002-remediation-stages.md)

## メトリクス

`image` は `<registry>/<repository>`（Docker Hub は `index.docker.io`、公式イメージは `library/`）。fleet-infra の VEX のファイル `security/vex/<image>.openvex.json` と同じ名前である。契約の全体と理由は [ADR 0005](docs/adr/0005-metrics-contract.md)。

| 名前 | ラベル | 値 |
|---|---|---|
| `vuln_tracker_finding` | `image` `tag` `digest` `severity` `stage` `fixable` `vex_state` `vex_expired` `vulnerability_id` `package` `installed_version` `fixed_version` `vex_status` `vex_review_by` | その組を初めて見た時刻（unix 秒）。導入時からあったものは 0。`--detail-severities` の重大度だけ |
| `vuln_tracker_findings` | `image` `tag` `digest` `severity` `stage` `fixable` `vex_state` `vex_expired` | 発見の件数。すべての重大度 |
| `vuln_tracker_image_info` | `image` `tag` `digest` `self_built` `source` `revision` | 1。`source` が空なら対応先不明 |
| `vuln_tracker_image_workload_info` | `image` `tag` `digest` `namespace` `kind` `name` `container` | 1 |
| `vuln_tracker_candidate_info` | `image` `digest` `candidate` `candidate_tag` `candidate_digest` `revision` `result` | 最後にスキャンした時刻。まだなら 0 |
| `vuln_tracker_image_renovate_pr_info` | `image` `url` | 1 |
| `vuln_tracker_scans_total` | `result` | スキャンの本数 |
| `vuln_tracker_scan_duration_seconds` | | スキャンの所要時間（histogram） |
| `vuln_tracker_sync_timestamp_seconds` | `target`（`fleet-infra` `k8s-manifests-fraction` `registry`） | 最後に読めた時刻 |
| `vuln_tracker_sync_errors_total` | `target`（上に `vex` を加える） | 読めなかった回数 |
| `vuln_tracker_digest_sent_timestamp_seconds` | | 最後にダイジェストを送れた時刻 |
| `vuln_tracker_responder_request_info` | `target` `target_type` `state` `pr` | vuln-responder への依頼の状態が最後に変わった時刻。target ごとに 1 系列 |

| ラベル | 値 |
|---|---|
| `stage` | 上の段階の表 |
| `fixable` | VulnerabilityReport の `fixedVersion` が空でなければ `true` |
| `vex_state` | 注釈の `state`（`upstream` `not-exploitable` `in-progress` `investigating` `fixed`）。注釈が無ければ `none` |
| `vex_expired` | 注釈の `review-by` が今日（`--timezone`）より前なら `true` |
| `candidate` | `main` `release` `upstream` `git` |
| `result` | `scanned` `failed` `pending` |
| `target_type` | `source`（自作イメージのソースのリポジトリ）`image`（外のイメージ） |
| `state`（依頼） | A2A の Task の状態（`submitted` `working` `completed` `failed` `rejected` `canceled` など）か、集計役の `error`（送れなかった）`timeout`（待つのをやめた） |

即時のアラート「注釈も対応もない、新しい、修正版のある Critical」の式の例は ADR 0005 にある。理由の文はメトリクスに出さない。ダッシュボードでは `image` から fleet-infra の VEX のファイルへリンクする。

## 設定

フラグで渡す。資格は環境変数でだけ受け取る（フラグにはしない）。

| フラグ | 既定 | 意味 |
|---|---|---|
| `--namespace` | `$POD_NAMESPACE` | 状態の ConfigMap の namespace |
| `--state-configmap` | `vuln-tracker-state` | 状態の ConfigMap の名前 |
| `--trivy-server` | `http://trivy-service.trivy-system:4954` | Trivy server |
| `--trivy-binary` | `/usr/local/bin/trivy` | trivy のバイナリ |
| `--trivy-cache-dir` | `/work/cache` | trivy の Java DB の置き場 |
| `--trivy-temp-dir` | `/work/tmp` | trivy の一時ファイル。スキャンごとに空にする |
| `--scan-timeout` | `10m` | 1 本のスキャンの時限 |
| `--scan-interval` | `1m` | スキャンの後に空ける時間 |
| `--fleet-infra` | `yuanying/fleet-infra@main` | VEX と対応表を読むリポジトリ |
| `--manifests` | `yuanying/fleet-infra@main,yuanying/k8s-manifests-fraction@master` | 版を読むマニフェストのリポジトリ |
| `--git-interval` | `10m` | リポジトリの HEAD を確かめる間隔 |
| `--self-source-prefix` | `https://github.com/yuanying/` | 自作と見なす source の前置き |
| `--renovate-author` | `renovate` | Renovate の PR の作者の login に当てる正規表現 |
| `--detail-severities` | `CRITICAL,HIGH` | 発見ごとに出し、ダイジェストに載せる重大度 |
| `--timezone` | `Asia/Tokyo` | `review-by` とダイジェストの時刻の基準 |
| `--digest-schedule` | `Mon 09:00` | ダイジェストを送る曜日と時刻 |
| `--dashboard-url` | （なし） | ダイジェストからリンクするダッシュボード |
| `--vex-base-url` | `https://github.com/yuanying/fleet-infra/blob/main/` | VEX のファイルへのリンクの前置き |
| `--metrics-bind-address` | `:8080` | /metrics |
| `--health-probe-bind-address` | `:8081` | /healthz・/readyz |
| `--leader-elect` | `false` | リーダー選出。レプリカ 1 では使わない |
| `--responder-url` | （なし） | vuln-responder の A2A の URL。空なら依頼しない |
| `--responder-token-file` | `/var/run/secrets/a2a/token` | audience `a2a` の projected token。送るたびに読み直す |
| `--responder-mode` | `vex-only` | 依頼の `mode`（`vex-only`・`fix`） |
| `--responder-new-within` | `168h` | 依頼する「新しい」の窓 |
| `--responder-task-timeout` | `3h` | Task を待つ上限 |
| `--responder-poll-interval` | `1m` | 依頼を送るか Task を見に行く間隔 |

### 要る Secret

どれも任意で、無ければその機能が止まるだけである。どれにも書き込みの権限を持たせない（[ADR 0007](docs/adr/0007-read-only-credentials.md)）。

| Secret（`config/` の Deployment が読む名前） | キー | 渡し方 | 中身と権限 | 無いとき |
|---|---|---|---|---|
| `vuln-tracker-github` | `token` | 環境変数 `GITHUB_TOKEN` | fine-grained PAT。対象リポジトリは fleet-infra と k8s-manifests-fraction、権限は Contents: Read と Pull requests: Read（Metadata: Read は自動）。GitHub App の installation token も使えるが 1 時間で切れる | private の fleet-infra が読めない（`in-git`・注釈・対応表・Renovate の PR が使えない）。public のリポジトリは匿名で読む |
| `vuln-tracker-slack` | `webhook-url` | 環境変数 `SLACK_WEBHOOK_URL` | Slack の Incoming Webhook の URL | ダイジェストを送らない |
| `vuln-tracker-registry` | `.dockerconfigjson`（型 `kubernetes.io/dockerconfigjson`） | `/etc/vuln-tracker/docker/config.json`（`DOCKER_CONFIG`） | pull だけのレジストリの資格。registry.fraction.jp、必要なら ghcr（`read:packages`）、Docker Hub（rate limit を上げるため） | 匿名で読む。registry.fraction.jp のイメージは `unscannable` |
| `vuln-tracker-trivy` | `token` | 環境変数 `TRIVY_TOKEN` | Trivy server のトークン | 今の Trivy server はトークンを要しない |

### fleet-infra の対応表

ラベルの無いイメージのソースと、既定の規則で系列が読めないタグは、fleet-infra の `security/image-sources.yaml` で補う。ファイルは任意で、無ければ空の表として動く。中身は `images` の一覧で、1 項目は次のキーを持つ。

| キー | 要否 | 値 |
|---|---|---|
| `image` | 必須 | `<registry>/<repository>`（例 `index.docker.io/searxng/searxng`） |
| `source` | 任意 | ソースの URL。ラベルが無いときだけ使う |
| `tagPattern` | 任意 | 系列のタグに当てる正規表現。最初のキャプチャが比べる版（例 `^(\d+\.\d+\.\d+)-[0-9a-f]+$`） |

読めない形のファイルは使わず、前に読めた表を使い続ける（`vuln_tracker_sync_errors_total{target="vex"}` が増える）。

## vuln-responder への依頼

`--responder-url` を与えると、即時のアラートと同じ「注釈も対応もない、新しい、修正版のある Critical」を、target ごとに vuln-responder へ A2A 1.0 で依頼する。詳細は [ADR 0009](docs/adr/0009-requesting-triage-from-vuln-responder.md)。

| 項目 | 振る舞い |
|---|---|
| target | 自作イメージはソースのリポジトリ（例 `yuanying/hshelf`）、それ以外はイメージ（例 `index.docker.io/longhornio/longhorn-engine`） |
| メッセージ | 人が読む text の part と、`kind` が `vuln-triage/v1` の data の part |
| context | vuln-responder が採番した contextId を target ごとに覚え、次の依頼を同じ context に続ける。知らないと言われたら新しい context で送り直す |
| 重複 | target ごとに頼んだ発見（イメージ・脆弱性・パッケージ）を状態の ConfigMap に覚え、頼んでいない発見が増えたときだけ頼む |
| 同時に | 1 件まで。Task が終わるまで次を送らない |
| 失敗 | 10 分から倍にして待ち、5 回目の失敗であきらめる |
| 返事 | Task の状態と、返事にある PR の URL をメトリクスとダイジェストに出す |

有効にするには、Deployment に `--responder-url` を足し、vuln-responder の受け付ける呼び出し元に `system:serviceaccount:vuln-tracker:vuln-tracker` を足す。token の volume は `config/` に入っている。

## デプロイ

`config/` に kustomize のマニフェストがある。

| 種別 | 名前 | 役割 |
|---|---|---|
| Namespace | `vuln-tracker` | |
| ServiceAccount | `vuln-tracker` | |
| ClusterRole / ClusterRoleBinding | `vuln-tracker` | VulnerabilityReport と Pod の get・list・watch |
| Role / RoleBinding | `vuln-tracker` | ConfigMap の create と、`vuln-tracker-state` の get・update・patch |
| Deployment | `vuln-tracker` | レプリカ 1、`Recreate`。作業領域は emptyDir（`sizeLimit: 2Gi`）。audience `a2a` の projected token を `/var/run/secrets/a2a/token` に置く |
| Service | `vuln-tracker` | /metrics（ポート名 `metrics`） |

`config/prometheus/servicemonitor.yaml` は kube-prometheus 向けの ServiceMonitor の例で、既定の kustomization には含めない。状態の ConfigMap は集計役が作るので、マニフェストには含めない。

イメージは `ghcr.io/yuanying/vuln-tracker`。main への push で `:main`、`v*` のタグでそのタグが出る。

## 開発

| コマンド | 内容 |
|---|---|
| `make test` | すべてのテスト（envtest を含む。control plane は自動で落とす） |
| `make lint` | golangci-lint |
| `make vet` | gofmt の検査と go vet |
| `make image` | イメージを手元でビルド |
