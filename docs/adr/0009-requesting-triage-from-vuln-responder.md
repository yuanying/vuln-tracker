# 0009. vuln-responder に A2A で脆弱性の対応を依頼する

- Date: 2026-10-27
- Status: Accepted（いつ・何を頼むかと、重複を避ける記録の鍵を ADR 0011 で広げた）

## Context

脆弱性を解析して対応を自分で判断する係 vuln-responder を、fraction-agents の新しい係として置く
（grill-me の決定 8・9）。この係に仕事を頼むのは集計役である。集計役は、どの発見が「注釈も対応もない、
新しい、修正版のある Critical」かを知っている唯一の場所だからである（ADR 0005 の即時のアラート）。

依頼の形は、タスクの契約 D で決めた。要点は次のとおりである。

- A2A 1.0（fraction-agents の汎用ホスト。fraction-agents ADR 0007）で、クラスタの中の Service に送る
- 認証は、集計役の ServiceAccount の projected token（audience `a2a`）を bearer で送る（fraction-agents ADR 0003）
- 依頼の単位は target 1 つにつき 1 件。target は「自作イメージのソースのリポジトリ」か
  「fleet-infra の、この外のイメージ」（grill-me の決定 10）。同じ target の次の依頼は同じ context に続ける
- メッセージは、人が読む text の part と、機械が読む data の part（`kind` が `vuln-triage/v1`）を 1 つずつ
- 同じ finding の組で 2 度は頼まない。同時に投げるのは 1 件まで。既定は off で、本番で on にする
- vuln-responder は Task を完了し、text で判断の要約、artifact か text に PR の URL を返す。
  呼び出し元は機械なので、input-required で聞き返すことはしない

契約 D は「contextId を target から決める」と書いたが、fraction-agents の汎用ホストは contextId を
**自分だけが採番する**（fraction-agents ADR 0007）。呼び出し元が付けた contextId は、その呼び出し元の
既存の context に限って受け付け、それ以外はエラーにする。また、使われない context は保持の期間の後に消える。

## Decision

### いつ・何を頼むか

- 頼む発見は、即時のアラートと同じ条件で選ぶ（ADR 0005）
  - 重大度が `CRITICAL`、`fixable` が `true`、注釈が無い（`vex_state` が `none`）
  - 段階が `unfixed`・`fixed-upstream`・`unscannable`・`pending` のいずれか
  - 初めて見た時刻が 0 でなく、今から `--responder-new-within`（既定 7 日、アラートの窓と同じ）の内
- 発見を target ごとに束ねる
  - 自作のイメージ（ADR 0002）で、source が `https://github.com/<owner>/<repo>` の形なら、target は
    ソースのリポジトリ（`type` が `source`、`repository` が `<owner>/<repo>`）
  - それ以外は、イメージ（`type` が `image`、`image` が `<registry>/<repository>`）
- 頼むのは、集計役の評価の 1 巡ごとではなく、別の巡回（`--responder-poll-interval`、既定 1 分）である。
  巡回 1 回でするのは、走っている依頼の様子を 1 度見るか、新しい依頼を 1 件送るかのどちらか 1 つだけである

### 重複を避ける記録

依頼の記録を、状態の ConfigMap（ADR 0006）に target ごとに 1 つ置く。

| 項目 | 中身 |
|---|---|
| target | `type` と、`repository` か `image` |
| context | vuln-responder が採番した contextId |
| Task | 最後に送った Task の ID と、その状態 |
| 頼んだ組 | これまでに頼み終えた発見の組（`<image>\|<脆弱性>\|<パッケージ>`）。tag と digest は含めない |
| 送っている組 | 今の依頼に入れた発見の組 |
| PR | 返事から読み取った PR の URL |
| 要約 | 返事の先頭の 1 行（ダイジェスト用） |
| 試した回数・次に試す時刻 | 失敗のときの backoff |
| 時刻 | 送った時刻と、状態が最後に変わった時刻 |

- いま頼む条件に当たる発見のうち、**頼んだ組に無いものが 1 つでもあれば** 頼む。依頼には、その target の
  条件に当たる発見を全部入れる（新しいものだけではない）。vuln-responder が target の全体を見て判断できるように
  するためである
- 頼んだ組に無いものが無ければ頼まない。発見が減っただけ、版を上げて digest が変わっただけ、では頼み直さない
- context は、記録にあれば付けて送る。vuln-responder がその contextId を知らない（保持の期間で消えた、
  PVC を作り直した）とエラーを返したら、その場で contextId を付けずに送り直し、新しく採番された contextId を記録する
  - 退けた案: 契約 D のとおり target から contextId を作る。汎用ホストが受け付けない
- 同時に走らせる依頼は 1 件まで。走っている依頼（終わっていない Task）があるうちは、ほかの target にも送らない。
  target の順は名前の順で決める

### Task の扱い

- 送るときは `SendMessage` に `returnImmediately` を付け、すぐ戻る Task を記録する。以後は巡回ごとに `GetTask` で見る
- 終わりの状態の扱い

| Task の状態 | 扱い |
|---|---|
| `completed` | 成功。送っている組を頼んだ組に足す。返事の text・data の part から最初の GitHub の PR の URL を読み取って記録する。無ければ空（判断できず PR を出さなかった、を含む） |
| `canceled` | 人が止めたものとみなし、成功と同じく頼んだ組に足す。頼み直さない |
| `failed`・`rejected` | 失敗。backoff の後に頼み直す |
| 送れなかった（通信・認証・JSON-RPC のエラー） | 失敗。状態は `error` |
| `--responder-task-timeout`（既定 3 時間）を過ぎても終わらない | 失敗。状態は `timeout`。待つのをやめる |
| それ以外（`submitted`・`working`・`input-required` など） | 走っているとして待つ |

- 失敗の backoff は 10 分から始めて倍にし、5 回目の失敗であきらめる（10 分・20 分・40 分・80 分）。
  あきらめたら、送っている組を頼んだ組に足す。同じ組では頼み直さず、新しい発見が増えたときに改めて頼む
- 待つのをやめた Task を vuln-responder で止める（CancelTask）ことはしない。vuln-responder の時間の上限
  （fraction-agents ADR 0019）に任せる

### メッセージ

- data の part は契約 D の形（`kind` が `vuln-triage/v1`）。`mode`・`target`・`findings`・`dashboard`・`vexFile` を持つ
  - `findings` の各項目は、発見の脆弱性・重大度・パッケージ・入っている版・修正版・段階・注釈の state・イメージ・tag・digest・
    動いている場所（namespace・kind・name・container）
  - `vexFile` は fleet-infra の VEX のファイルの path（ADR 0004）。ソースのリポジトリが複数のイメージを出しているときは、
    名前の順で最初のイメージのものを入れる。どのイメージのものかは各項目の `image` で分かる
- text の part は、同じ中身を人が読める形で書く。target・mode・発見の一覧・ダッシュボードの URL と、
  返事の形（判断の要約、PR を出したらその URL、判断できなければ PR を出さずに理由）を書く
- `mode` は `--responder-mode`（`vex-only`・`fix`、既定 `vex-only`）。何を許すかを決めるのは vuln-responder の側の設定であり、
  この値は依頼の意図を伝えるだけである

### 資格

- projected token をファイル（既定 `/var/run/secrets/a2a/token`）から読み、**送るたびに読み直す**。
  kubelet が期限の前に入れ替えるからである
- token は、ログとエラーに書かない

### クライアント

- A2A 1.0 の JSON-RPC over HTTP を、`SendMessage` と `GetTask` の 2 つだけ自分で書く
  - 退けた案: 公式の Go の SDK（a2a-go）を使う。使うのは 2 つのメソッドだけで、gRPC などの依存が増える割に得るものが少ない
- 要求に `A2A-Version: 1.0` を付ける。返事の拡張（fraction-agents ADR 0015）は有効にしない。PR の URL は text からも読めるからである

### 有効にするフラグ

| フラグ | 既定 | 意味 |
|---|---|---|
| `--responder-url` | 空 | vuln-responder の A2A の URL。空なら依頼の機能はまるごと止まる（何も送らず、token も読まない） |
| `--responder-token-file` | `/var/run/secrets/a2a/token` | projected token のファイル |
| `--responder-mode` | `vex-only` | data の `mode` |
| `--responder-new-within` | `168h` | 「新しい」の窓 |
| `--responder-task-timeout` | `3h` | Task を待つ上限 |
| `--responder-poll-interval` | `1m` | 巡回の間隔 |

### 見せ方

- メトリクス `vuln_tracker_responder_request_info`（ADR 0005 に足す）。target ごとに 1 系列で、
  ラベルは `target`（リポジトリかイメージの名前）・`target_type`（`source`・`image`）・`state`・`pr`、値は状態が最後に変わった時刻
- `state` は Task の状態を小文字にしたもの（`submitted`・`working`・`completed`・`failed`・`rejected`・`canceled`・`input-required` など）に、
  集計役の `error`・`timeout` を加えたもの
- 週次ダイジェスト（ADR 0006）に「vuln-responder への依頼」の節を足す。前回のダイジェストの後に状態が変わった依頼を、
  target・状態・PR のリンク・要約で載せる。依頼の機能が off なら節を出さない

## Consequences

- 本番で on にするには、Deployment に `--responder-url` を足し、vuln-responder の受け付ける呼び出し元に
  `system:serviceaccount:vuln-tracker:vuln-tracker` を足す。projected token の volume は `config/` に常に入っている
- 集計役が外に書く先が、Slack と自分の ConfigMap に、vuln-responder への依頼が加わる。依頼そのものは
  リポジトリに書く権限を持たない。書くのは vuln-responder であり、その範囲は vuln-responder の側で絞る（ADR 0007）
- 1 巡回に 1 件なので、target が多いと最初の依頼が行き渡るまで時間がかかる。vuln-responder も同時に 1 件しか走らせない
- 導入時からある発見は、初めて見た時刻が 0 なので頼まない（ADR 0005）。頼みたいときは、人が vuln-responder に直接頼む
- 頼んだ組は消さないので、一度頼んだ発見が消えてまた出ても、同じ target に頼み直さない。頼み直したいときは、状態の ConfigMap の
  その target の記録を消す（ConfigMap ごと消すと、初めて見た時刻も失う。ADR 0006）
- 汎用ホストが contextId を消したときは、新しい context になり、前の依頼の経過は vuln-responder の側に残らない

## 関連 ADR

- [[0002-remediation-stages]]
- [[0004-applying-openvex-annotations]]
- [[0005-metrics-contract]]
- [[0006-weekly-digest-and-durable-state]]
- [[0007-read-only-credentials]]
- [[0011-requesting-version-bumps-when-a-stage-advances]]
