# 0011. 段階が直った版まで進んだら、vuln-responder に版上げを頼む

- Date: 2026-10-28
- Status: Accepted

## Context

ADR 0009 で、集計役は「注釈も対応もない、新しい、修正版のある Critical」だけを vuln-responder に頼むようにした。
これは注釈（VEX）を書いてもらうための依頼である。直す流れ（`mode` が `fix`）を回すには、それだけでは足りない。
直った版が出たあと、本番の版を上げる PR を出す人がいないからである。

直す流れは、イメージを誰が作るかで 2 通りある（タスクで 2026-10-28 に決めた）。

- **自作**: vuln-responder がソースのリポジトリに直す PR を出す → 人がマージする → すぐにパッチ版がリリースされる →
  集計役が `fixed-in-release` を見て、同じ context で頼み直す → vuln-responder が fleet-infra に版上げの PR を出す
  （Renovate を待たない）→ 人がマージして apply する
- **外**: 段階が `fixed-upstream` になったら、vuln-responder が fleet-infra に版上げの PR を出す。
  Renovate の PR が既にあれば、それを指す

どちらも、段階が「直った版がある」（`fixed-in-release`・`fixed-upstream`。ADR 0002）に進んだことが、頼むきっかけになる。
この版上げは、注釈が付いていても要る。たとえば hshelf の Ruby 同梱の json は「上流待ち」（`upstream`）の注釈が付いているが、
ベースイメージが直ってリリースが直れば、版を上げる PR が要る。

## Decision

### きっかけの一覧

発見ごとに、頼むきっかけを高々 1 つ決める。どのきっかけも重大度は `CRITICAL` だけである。

| きっかけ（`trigger`） | 段階 | 注釈 | 修正版 | 新しさ | `mode` | 頼むこと |
|---|---|---|---|---|---|---|
| `bump` | `fixed-in-release`（自作） | 問わない | 問わない | 問わない | `fix` だけ | 直ったリリースのタグに、fleet-infra の版を上げる PR |
| `bump` | `fixed-upstream`（外） | 問わない | 問わない | 問わない | `fix` だけ | 上流の直った版に、fleet-infra の版を上げる PR。Renovate の PR があればそれで足りるかを判断する |
| `triage` | `unfixed`・`unscannable`・`pending` | なし | あり | 窓の内 | 両方 | 解析して対応を判断する（ADR 0009 のまま）。`fix` なら、ソースのリポジトリに直す PR も含む |
| `triage` | `fixed-upstream` | なし | あり | 窓の内 | `vex-only` だけ | ADR 0009 のまま。`fix` では上の `bump` になる |
| なし | `fixed-in-main` | | | | | 頼まない。リリースを待つ（vuln-responder の直しのマージですぐ出る。Renovate の更新は週次で出る） |
| なし | `in-git` | | | | | 頼まない。あとは apply だけで、人がする |

- `bump` の 2 つは、修正版の有無と新しさを問わない。版を実際にスキャンして消えたことが分かっている（ADR 0002）ので、
  修正版の欄が空でも上げれば消える。また、導入時からある古い発見でも、直った版があるなら上げる価値は同じである
- `mode` が `vex-only` のとき、`bump` は 1 つも出ない。`vex-only` での依頼は v0.2.0（ADR 0009）と同じになる
- 注釈の付いた `unfixed` の発見は、`fix` でも頼まない
  - 注釈は、その発見について人か vuln-responder が既に下した判断である。ソースで直せるもの（lock の依存など）が残っているなら、
    その判断の時点で直す PR になっているはずである
  - 退けた案: 注釈が `upstream` でも、修正版があれば `fix` で頼む。Ruby 同梱の json のように、ソースでは直せないから
    `upstream` にしたものを、注釈がある限り繰り返し頼むことになる。判断を見直したいときは、注釈の見直す期限（`review-by`）を使う

### 重複を避ける記録

ADR 0009 の「頼んだ組」を、きっかけごとに効く形に広げる。組の鍵は次のとおりである。

| きっかけ | 鍵 |
|---|---|
| `triage` | `<image>\|<脆弱性>\|<パッケージ>`（ADR 0009 と同じ。v0.2.0 の記録をそのまま使える） |
| `bump` | `<image>\|<脆弱性>\|<パッケージ>\|<段階>` |

- 同じ発見でも、段階が進めば鍵が変わるので、もう一度頼める。たとえば `triage` で頼んだあと（直す PR を出した）、
  リリースで直って `fixed-in-release` になれば、`bump` として 1 度だけ頼む
- 鍵に版のタグと digest は含めない。版上げの PR がマージされる前に次のリリースが出ても、同じ発見で頼み直さない。
  頼み直したいときは、ADR 0009 と同じく、状態の ConfigMap のその target の記録を消す
- 1 回の依頼には、その target のきっかけに当たる発見を **きっかけを問わず全部** 入れる（ADR 0009 と同じ）。
  頼むかどうかは、鍵が頼んだ組に無いものが 1 つでもあるかで決める
- target・context・同時に 1 件・backoff・Task の扱いは ADR 0009 のまま。版上げの依頼も、そのソースのリポジトリか
  イメージの context に続く。直す PR を出したときの経過を、vuln-responder が同じ context で読めるようにするためである

### 依頼の文面に足すもの

data の part（`kind` は `vuln-triage/v1` のまま。未知のキーは無視する約束なので、足すだけなら kind を変えない）の
`findings` の各項目に、次を足す。

| キー | 中身 |
|---|---|
| `trigger` | `triage` か `bump` |
| `fixedInTag`・`fixedInDigest` | `bump` のとき、その脆弱性が消えた版（`fixed-in-release` ならリリースの候補、`fixed-upstream` なら上流の候補）のタグと digest。`triage` では出さない |
| `renovatePRs` | そのイメージの名前が出てくる、開いている Renovate の PR の URL（`vuln_tracker_image_renovate_pr_info` と同じ）。無ければ出さない |

`stage` は ADR 0009 から既にある。

text の part は、発見をきっかけごとの節に分けて書く。

- `triage` の節: これまでと同じく「新しく見つかった、注釈も対応も無い、修正版のある Critical。解析して対応を判断してほしい」
- `bump` の節: 「直った版が出た。fleet-infra（か k8s-manifests-fraction）に書かれたこのイメージの版を、その版に上げる PR を出してほしい。
  注釈が付いていれば、版上げで要らなくなる注釈の扱いも判断してほしい」。各発見に、段階・直った版のタグと digest・注釈の state を書く
- Renovate の PR があれば、その URL を書き、「それで足りるなら新しい PR は出さず、その URL を返事に書く」と添える

### フラグ

新しいフラグは足さない。`bump` は `--responder-mode` が `fix` のときだけ出るので、`fix` にすることが有効にすることを兼ねる。

## Consequences

- `--responder-mode` を `fix` にした直後は、`fixed-in-release`・`fixed-upstream` の Critical を持つ target に、
  導入時からある古い発見も含めて順に頼む。1 巡回に 1 件・同時に 1 件（ADR 0009）なので、行き渡るまで時間がかかる
- `vex-only` のままなら、振る舞いは v0.2.0 から変わらない。状態の ConfigMap の記録もそのまま読める
- vuln-responder の PR の URL として記録されるのは返事の最初の PR の URL なので、Renovate の PR を指したときはその URL になる
- `fixed-in-main` では頼まないので、`:main` で直ったがリリースされない（人の変更が混ざって自動のリリースが止まった）ものは、
  人がリリースするまで進まない。ダッシュボードとダイジェストで拾う
- 注釈付きの `unfixed` を頼まないので、注釈が誤っていれば見直す期限まで残る

## 関連 ADR

- [[0002-remediation-stages]]
- [[0005-metrics-contract]]
- [[0006-weekly-digest-and-durable-state]]
- [[0009-requesting-triage-from-vuln-responder]]
- [[0010-weekly-dependency-release]]
