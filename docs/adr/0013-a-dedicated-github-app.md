# 0013. GitHub は専用の GitHub App の installation token で読む

- Date: 2026-10-29
- Status: Accepted

## Context

ADR 0007 では、GitHub を環境変数 `GITHUB_TOKEN` の 1 つのトークン（fine-grained PAT）で読むとした。
GitHub App の installation token は 1 時間で切れるので、入れ替える仕組みが無いうちは PAT を使う、
という判断だった。

発見ごとに対応の進み具合を 2 軸で出す（ADR 0014）には、マニフェストのリポジトリに加えて、
自作のイメージのソースのリポジトリの PR も読む必要がある。ソースのリポジトリは十数個あり、private のものもある。
リポジトリを足すたびに PAT の対象を直すのは人の手間で、PAT の期限の管理も人の手に残る。

release-lag は同じ持ち主のリポジトリを読むために、専用の GitHub App を作り、installation token を
失効前に入れ替える仕組みを持っている（release-lag の ADR 0003、`internal/githubapp`）。

## Decision

- vuln-tracker 専用の GitHub App を作る。権限は Repository permissions の **Contents: Read-only**・
  **Pull requests: Read-only**・**Metadata: Read-only** だけ。Account permissions は要らない。
  Webhook は使わない。インストール先は持ち主（yuanying）の **All repositories**
- token の入れ替えは release-lag の `internal/githubapp` と同じやり方にする。App の private key
  （PEM。GitHub が渡す PKCS#1 のほか PKCS#8 も読める）で RS256 の JWT に署名し、installation token と
  引き換える。token の失効の 5 分前を過ぎたら次を発行し直す。JWT は 9 分で失効させ、時計のずれに備えて
  発行時刻を 1 分前にずらす。JWT の署名は標準ライブラリで書く
- 設定はフラグで渡す

| フラグ | 既定 | 意味 |
|---|---|---|
| `--github-app-id` | `0` | App の ID。`0` なら App を使わず、今までどおり `GITHUB_TOKEN` で読む |
| `--github-app-installation-id` | `0` | 持ち主へのインストールの ID。App ID を指定したら必須 |
| `--github-app-private-key-file` | `/var/run/secrets/github-app/private-key.pem` | App の private key |

- private key は Secret `vuln-tracker-github-app` のキー `private-key.pem` を
  `/var/run/secrets/github-app/` に読み取り専用でマウントする。Secret は `optional` にして、
  App を作る前でも Deployment が `GITHUB_TOKEN` で動けるようにする。鍵は起動時に 1 回読む
- App ID を指定したのに鍵が読めない、または鍵として読めないときは、起動を失敗させる。匿名で読み続けると、
  private のリポジトリがすべて読めないまま、段階や 2 軸の状態が静かに古くなるからである
- App ID を指定したときは `GITHUB_TOKEN` を送らない。どちらか一方だけを使う
- installation token を得られないとき（GitHub の障害・App の削除）は、その回の GitHub の読みが失敗する。
  失敗はこれまでどおり `vuln_tracker_sync_errors_total` に数え、前に読めた中身で続ける

### ADR 0007 との関係

ADR 0007 の「資格はすべて読み取りだけ」は変わらない。App の権限は読み取りだけで、リポジトリに書けない。
ADR 0007 の表の GitHub の行は、この ADR の App を正とし、`GITHUB_TOKEN` は App ID が 0 のときの後方互換として残す。

## Consequences

- ソースのリポジトリを増やしても、資格の側の作業は要らない（All repositories にインストールしているため）
- private key を差し替えたら Pod を作り直す
- installation の rate limit は 1 時間 5,000 回である。見積もりは ADR 0014 に書く
- App の作成・private key のダウンロード・インストール・sops での暗号化はユーザーが行う。手順は fleet-infra の
  README に書く。PAT の Secret `vuln-tracker-github` は App に移った後で片付ける

## 関連 ADR

- [[0007-read-only-credentials]]
- [[0014-two-axes-of-remediation-and-linked-pull-requests]]
