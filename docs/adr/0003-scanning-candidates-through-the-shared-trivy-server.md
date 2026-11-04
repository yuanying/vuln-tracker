# 0003. 候補の版は、共有の Trivy server にクライアントとして繋いでスキャンする

- Date: 2026-10-27
- Status: Accepted（2026-11-04 に、候補のスキャンで jar を解析しないことにした。「作業領域」の追記）

## Context

段階の判定（ADR 0002）には、本番で動いていない版（`:main`・リリース・上流の新しい版・git に
書かれた版）のスキャンが要る。Trivy Operator はこれをしない。

クラスタには Trivy Operator の Trivy server（`trivy-system` の StatefulSet `trivy-server`、
0.75.0、Service `trivy-service:4954`）がある。脆弱性 DB を 1 つ持ち、Trivy Operator のスキャン Job は
クライアントとしてここに問い合わせる。サーバーにトークンは設定されていない
（2026-10-27、fleet-infra の `infrastructure/trivy-operator/` で確認）。

自宅のクラスタなので、資源とディスクに余裕は無い。Trivy Operator もスキャンを同時 1 本に絞っている。

## Decision

### trivy のバイナリを client モードで呼ぶ

集計役のイメージに trivy のバイナリを入れ、`trivy image --server <URL> --image-src remote` で
呼ぶ。Trivy の Go のライブラリは import しない。ライブラリの API は版ごとに変わり、依存も大きい。
バイナリなら Trivy Operator のスキャン Job と同じ経路になり、結果がずれない。

- バイナリの版は固定してイメージに入れる。Trivy server と同じ minor（今は 0.75.x）に揃える。
  Renovate が追えるよう、版は Dockerfile の 1 か所に書く
- `--image-src remote` で、イメージはレジストリから直接読む。ノードに pull しない
- 結果は JSON で受け取り、脆弱性の ID とパッケージの組だけを使う
- 脆弱性 DB はサーバーのものを使う。集計役は脆弱性 DB を落とさない

### スキャンは 1 本ずつ、間隔を空ける

スキャンは 1 つの待ち行列に並べ、同時に 1 本だけ走らせる。1 本終わるごとに、少なくとも
1 分（設定できる）空ける。1 本の時限は 10 分とする（Trivy Operator の `scanJobTimeout` と同じ）。

同じ digest は 24 時間に 1 回だけスキャンする。結果はメモリに持ち、再起動すれば取り直す。

### 作業領域

trivy の作業領域（`TMPDIR` とキャッシュのディレクトリ）は emptyDir に置き、`sizeLimit` を付ける
（既定 2Gi。マニフェストの例に書く）。client モードでも、jar を解析するための Java の DB を
クライアントが落とすので、これはキャッシュのディレクトリに残す（2026-11-04 からは jar を解析せず、Java DB を落とさない。下の追記）。それ以外の一時ファイルは、1 本のスキャンが終わるごとに消す。

#### 追記（2026-11-04）: jar を解析しない

**Context.** v0.4.1 の本番の Pod が、約 30 分ごとに emptyDir の `sizeLimit`（2Gi）を超えて evict された。
trivy（0.76.1）は、イメージの中に jar を見つけると、jar の analyzer が Java DB
（`ghcr.io/aquasecurity/trivy-java-db:1`）を落とす。圧縮の tarball を `TMPDIR` に置いたまま、キャッシュのディレクトリの
`java-db` に展開する。2026-11-04 の版で tarball が 994MB、展開した DB が 1.57GB あり、どちらも同じ emptyDir に載るので
ピークで 2Gi を超える。展開し終えても 1.57GB が残り、ほかのスキャンに使える余裕は約 0.57GB しかない。DB は 3 日ごとに取り直される。

きっかけは fleet-infra の git に書かれた候補 `nginx:1.21` で、Debian の gettext が入れる `usr/share/java/libintl-0.21.jar` を持つ。
Java のアプリではない。スキャンの結果はメモリにしか持たず、次にスキャンする候補は名前順の先頭から選ぶので、
evict のたびに同じ候補で Java DB を落とし直していた。

**Decision.** 候補のスキャンでは、jar の analyzer が扱う拡張子（jar・war・ear・par、大文字小文字を問わない。
trivy 0.76.1 のソースで確かめた）のファイルを `--skip-files` で外す。Java DB は落とさない。emptyDir の大きさは 2Gi のまま変えない。

- trivy には analyzer を切る CLI の指定が無い。`--skip-files` に当たるファイルは、層を読む段階で analyzer に渡らない。
  jar の analyzer は jar が 1 つも渡らなければ動かず、Java DB を取りに行かない
- `--skip-files` は Trivy server のキャッシュの鍵にも入るので、外す前に jar を解析した層の情報が使い回されることはない
- 戻すフラグは設けない。戻すには作業領域の大きさから考え直す必要があり、フラグを切り替えるだけでは済まないからである
- 手元で trivy 0.76.1 を空のキャッシュで `nginx:1.21` に走らせ、jar が外れ、`java-db` が作られず、Java DB を落とすログも
  出ないことを確かめた（standalone で実行）。同じ引数から `--skip-files` を除き、Java DB の取得を禁じて走らせると、
  jar の analyzer が Java DB を求めてスキャンが失敗した

**Consequences.**

- 候補のスキャンに Maven（Java）の脆弱性が出なくなる。Trivy Operator の VulnerabilityReport には出続けるので、
  本番に Maven の発見があると、どの候補でも「消えている」ように見え、直っていないのに `in-git` などの段階へ進んだと
  誤って判定されうる（ADR 0002）
- 2026-11-04 の時点で、本番の VulnerabilityReport に Maven の発見は 0 件である（packagePURL で確かめた）。
  Java のアプリのイメージを本番に入れるときは、この決定を戻す。Java DB の大きさに合わせて作業領域を広げるか、
  別の置き場を用意してから jar の解析を戻す

### Trivy server のキャッシュ

Trivy の client/server モードでは、クライアントが解析した層の情報（blob）をサーバーのキャッシュに
置く。イメージのスキャンでは、クライアントはこれを消さない（Trivy 0.75.0 のソースで、イメージの
artifact の `Clean` が何もしないことを確かめた）。したがって集計役がスキャンするたびに、
サーバーの emptyDir に層の情報が増える。Trivy Operator のスキャンも同じように増やしている。

サーバーには blob を消す RPC があるが、blob の ID は trivy の出力に出ないので、集計役が自分の
置いたものだけを消すことはできない。集計役は Trivy server に書く権限も、Pod を作り直す権限も
持たない（ADR 0007）。

そこで集計役の側では消さない。

- 集計役はスキャンの本数を `vuln_tracker_scans_total` に出す（ADR 0005）
- 入れてから、サーバーのキャッシュのディレクトリの増え方を測る（fleet-infra 側の作業単位）
- 増え方が問題になるなら、fleet-infra の側でサーバーのキャッシュを定期的に消す
  （Trivy server を定期的に作り直す、など）。DB は起動時に落とし直されるので、作り直しは安全である

## Consequences

- 集計役のスキャンは Trivy Operator のスキャンと同じ DB を使うので、本番の版と候補の版の結果を
  比べられる
- 集計役のイメージは trivy のバイナリのぶん大きくなる（おおよそ 200MB）
- Trivy server が落ちている間、スキャンは失敗し、該当する発見は `unscannable` になりうる。
  失敗したスキャンは次の巡回で取り直す
- 層の取得はレジストリへの読みになる。Docker Hub では manifest の取得が匿名の rate limit に数えられる
  ので、Docker Hub のイメージは 24 時間に 1 回より多くはスキャンしない
- サーバーのキャッシュの掃除は集計役の外に置く。増え方を測るまで、掃除の仕組みは作らない

## 関連 ADR

- [[0002-remediation-stages]]
- [[0007-read-only-credentials]]
