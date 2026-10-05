# Coruna 研究報告

[English](README.md) | **繁體中文** | [한국어](README.ko.md)

> [!CAUTION]
> 本文件記錄針對真實 iOS 攻擊行動中所擷取之惡意樣本的分析成果，
> **僅供研究用途**發布——服務於防禦研究人員與威脅情資分析。**不發布
> 任何解密金鑰、密碼或種子**（僅以結構方式描述，持有樣本者可離線
> 定位）；不含任何惡意二進位檔、攻擊程式碼或 C2 實作；所有 IOC
> 均已去特徵化或泛化處理；不重現任何受害者內容。本文僅描述攻擊者
> 建構的技術——不得用於攻擊任何人。樣本僅可於隔離分析環境中操作。

## 這是什麼

針對 **Coruna** 的深度研究——一套商用等級的 iOS 攻擊工具包，曾在
真實水坑（watering-hole）攻擊行動中現身。該工具包串接 WebKit 漏洞
利用，在 iOS 13–17 上完成完整裝置控制，隨後部署 23 個植入模組的
間諜系統——加密錢包、簡訊、WhatsApp 與相簿——並以網域生成演算法
（DGA）隱藏其 C2 通訊流量。

本研究基於對擷取工具包樣本的分析。在「投放了什麼？」之外，本文件
回答後續問題：植入體連到哪裡（完整逆向的 DGA）、流量長什麼樣子
（C2 協定與 90 請求鑑識時間線）、惡意程式在裝置上做什麼（模組系統
與由 App 觸發的資料竊取）。

## 功能概覽

| 功能 | 細節 |
|------|------|
| 支援 iOS 版本 | iOS 13.0–17.2.1，各版本對應攻擊鏈（WebKit 記憶體破壞 → PAC 繞過 → 沙盒逃逸） |
| 錢包竊取 | 19 款錢包 App——MetaMask、imToken、Trust Wallet、TronLink、BitKeep、TON Keeper、Uniswap、Phantom、MyTonWallet、Exodus、Ronin、Krystal、TonHub、Global Wallet、Coin98、Bitpie、Solflare、OKX（EVM / Solana / TON / Tron / Ronin） |
| 模組系統 | 23 個注入模組：19 個錢包 + WhatsApp（`wap.js`）+ 簡訊（`sms.js`）+ SpringBoard 核心常駐（`new.js`）+ 設定接收器（`helion.js`） |
| 相簿竊取 | 裝置相片打包為加密 `.dat` 容器（7z 衍生格式）後批量外傳 |
| 簡訊 / SIM 蒐集 | 電話號碼、SIM 卡在位/有效狀態、電信業者資訊 |
| C2 通訊 | DGA 生成網域、加密 POST 流量、由 App 觸發的批量上傳 |

## 攻擊鏈一覽

```
受害者開啟水坑頁面（偽造註冊網站）
  └─ 隱藏 iframe 拉取混淆的載入器 JS
      ├─ 第一階段 — WebKit / WASM 記憶體破壞 → 讀寫原語
      ├─ 第二階段 — PAC 繞過（A12+ 裝置）
      └─ 第三階段 — 沙盒逃逸 + 記憶體內 Mach-O 載入器
          └─ bootstrap.dylib 解密/下載 .min.js 植入體
              └─ 經 powerd / SpringBoard 注入達成常駐
                  └─ DGA 網域 C2 流量
                      └─ 23 個注入模組 → 錢包 / 簡訊 /
                         WhatsApp / 相簿竊取
```

## 核心發現（TL;DR）

1. **四層加密、全系靜態金鑰。** 檔案加密採 ChaCha20（DJB 變體，
   30 把金鑰階層）、自訂 `F00DBEEF` 容器格式、執行期模組採
   7z AES-256、C2 流量採 AES-256-ECB。所有金鑰內嵌於樣本或可
   離線推導——沒有任何裝置專屬秘密。
2. **DGA 完全可重現。** 非標準 MurmurHash2 變體作為 BSD libc
   `random()` 的種子來源；生成一個網域的成本是一次雜湊、一次
   延遲燒毀與 15 次亂數抽取。自樣本內嵌種子預測的網域與擷取
   流量完全吻合。
3. **C2 協定小而不對稱。** 明文 `/vhx` 心跳、由時間戳衍生金鑰
   加密的 Base64 AES-256-ECB POST 主體、以及固定長度的極小
   回應權杖。
4. **資料竊取由 App 觸發。** 在擷取的連線紀錄中，開啟一款加密
   錢包 App 立即引發心跳爆發與兩次大型加密上傳（1.8 MB 與
   624 KB）；相簿走同一批量通道。
5. **23 個注入模組、其中 19 個針對錢包**，橫跨五個生態系，
   另有 WhatsApp、簡訊、相簿與 SpringBoard 核心常駐——是可租用
   的監控產品，而非國家級情蒐。

---

## 1. 加密體系

| 層 | 保護對象 | 演算法 | 金鑰材料 |
|----|----------|--------|----------|
| A | payload 檔案（`.min.js`） | ChaCha20（DJB 變體） | 30 把金鑰階層，內嵌於投放頁與樣本 |
| B | 檔案容器格式 | 自訂 `F00DBEEF` 格式 | —（僅結構） |
| C | 執行期模組（`.7z`） | 7z AES-256 | 單一固定全行動密碼 |
| D | C2 流量 | AES-256-ECB | 由內嵌前綴 + 時間戳推導 |

最重要的防禦性發現：**沒有任何環節需要裝置或連線專屬的機密。**
這套堆疊只提供傳輸混淆，對持有樣本者並無真正的機密性。

### 1.1 A 層 — ChaCha20（DJB 變體）

payload 檔案*不是*標準 IETF ChaCha20。`bootstrap.dylib` 內（偏移
`0xad8c`）的實作是原始的 DJB 變體：

- 64 位元計數器、64 位元 nonce（實務上全零）
- 每個明文開頭為 magic `0x0BEDF00D`
- 8 位元組標頭之後為原始 XZ/lzma 串流

以標準函式庫搭配 96 位元 nonce 解密會得到亂碼——這是逆向此
工具包時的典型失敗模式。

**金鑰階層（三層）：**

```
第 1 層 — 主金鑰（1 把）：group.html 中的混淆 uint32 陣列，
          傳給 platformModule.init()；解碼為 16 字元 JS 字串後
          以 UTF-16LE 儲存 → 32 位元組金鑰。解鎖 manifest。
第 2 層 — 各 OS payload 金鑰（19 把）：解密後 manifest 內部、
          偏移 0x120 起、每筆 100 位元組。每個 iOS 版本/架構
          組合一份 payload。
第 3 層 — 子 manifest 金鑰（10 把）：每個 payload 容器內的
          type-0x07 條目（468 位元組）、偏移 0x0108。共用模組。
```

manifest 條目布局：

```
0x00–0x1F : 32 位元組 ChaCha20 金鑰（每檔一把）
0x20–0x27 : 檔案大小（LE64）
0x28      : 條目類型（0x01 = 檔案，0x07 = 子 manifest）
0x29–0x3F : 填充
```

**off-by-one 陷阱：** 參考實作在解密 manifest 金鑰表時對
`size - 1` 位元組作雜湊。天真的「乾淨版」重新實作若對整張表
作雜湊，會在最後一筆條目產出錯誤金鑰——一位元組的差異會默默
破壞整條解密管線。

### 1.2 B 層 — F00DBEEF 容器

```
0x00–0x03 : 0BEDF00D            magic
0x04–0x07 : 0000000A            版本
0x08–0x0B : 區段數（LE）
0x0C–0x0F : 00000001            標頭大小
0x20–..   : 區段表（每筆 16 位元組）
```

實戰觀察到的區段類型：`0x01` 程式碼、`0x02` 設定、`0x03` 字串、
`0x07` 子 manifest（金鑰材料）、`0x09` 資源。

### 1.3 C 層 — 7z 模組傳輸

安裝完成後，植入體自 `/details/<名稱>.js` 端點取得以**單一固定
全行動密碼**加密的 7z 封裝——密碼以常數形式內嵌於二進位檔，
非裝置或連線衍生，且跨模組、跨行動快照重複使用。此處不披露
該值。

### 1.4 D 層 — AES-256-ECB C2 流量

```
key       = SHA256(<16 字元固定前綴，內嵌於每個樣本> + x-ts)[:32]
plaintext = <x-ts 時間戳字串> + <JSON 內容>
padding   : PKCS7
transport : POST 主體放 Base64(密文)，時間戳以 x-ts 標頭回傳
response  : Base64(16 個隨機位元組) — 24 字元回應權杖
```

由於時間戳以明文傳輸（`x-ts` 標頭），任何觀察連線的人——或持有
樣本的人——都能推導每個請求的金鑰。對 JSON 使用 ECB 也會洩漏
區塊級的重複樣式。

### 1.5 評估

- **機密性薄弱、混淆性強**——只能擋下隨意檢視與天真的閘道掃描。
- **ECB 誤用**讓流量可被指紋化。
- **off-by-one 怪癖與 DJB nonce 變體是可靠的實作指紋**，可用於
  在其他攻擊行動中識別 Coruna 家族工具。

---

## 2. DGA 演算法逆向工程

Coruna 植入體不攜帶寫死的 C2 清單。它內嵌單一 32 個十六進位
字元的種子，按需生成網域。封鎖一個現存網域只移除一個主機；
預測完整序列則能把 DGA 變成防禦資產。

生成一個網域的確切成本：

```
1 次 murmurhash2_coruna(活動識別碼)  → RNG 種子
1 次 delay 燒毀                       → 10 個 uint16 槽位消耗 1 個
15 次 random()                        → 標籤字元
```

結果為 15 個小寫 `[a-z0-9]` 字元組成的標籤，掛在低價可拋棄 TLD
之下（擷取的行動中使用 `.icu`）。

### 2.1 非標準 MurmurHash2

```python
MURMUR_M = 0x5BD1E995
MURMUR_INIT = 0x12345678          # 並非標準的 0 種子

def murmurhash2_coruna(data: bytes, h: int = MURMUR_INIT) -> int:
    h ^= len(data)                # 初始化方式與參考版 MurmurHash2 不同
    for i in range(0, len(data) - (len(data) & 3), 4):
        k = int.from_bytes(data[i:i+4], "little")
        k = (k * MURMUR_M) & 0xFFFFFFFF
        k ^= k >> 24
        k = (k * MURMUR_M) & 0xFFFFFFFF
        h = (h * MURMUR_M) & 0xFFFFFFFF
        h ^= k
    tail = data[len(data) & ~3:]
    if len(tail) >= 3: h ^= tail[2] << 16
    if len(tail) >= 2: h ^= tail[1] << 8
    if len(tail) >= 1:
        h ^= tail[0]
        h = (h * MURMUR_M) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * MURMUR_M) & 0xFFFFFFFF
    h ^= h >> 15
    return h
```

### 2.2 BSD libc random()，TYPE_3

植入體使用 BSD libc 的 `random()`，而非單純的 LCG：

```python
class BSDRandom:
    """BSD libc random()，TYPE_3（31 字元狀態）。"""

    DEG_3, SEP_3 = 31, 3

    def __init__(self, seed: int):
        self.state = [0] * self.DEG_3
        self.state[0] = seed & 0xFFFFFFFF
        word = seed & 0xFFFFFFFF
        for i in range(1, self.DEG_3):
            # 僅用於狀態初始化的 Schrage 安全 LCG
            hi, lo = divmod(word, 127773)
            word = ((16807 * lo - 2836 * hi) & 0x7FFFFFFF) or 0x7FFFFFFF
            self.state[i] = word
        for _ in range(310):       # 預熱丟棄
            self.next()

    def next(self) -> int:
        i, j = 0, self.SEP_3
        word = 0
        while word & 0x80000000 == 0:
            i, j = 0, self.SEP_3
            word = (self.state[i] & 0x7FFFFFFF) + self.state[j]
            self.state[i] = word
            i = j if (i := (i + 1) % self.DEG_3) == 0 else i
            j = j + 1 if (j := (j + 1) % self.DEG_3) == 0 else j
        return (word >> 1) & 0x7FFFFFFF
```

重新實作並不難——但前提是你*知道*它是 TYPE_3 且含 310 次預熱
抽取。猜成「就是 rand()」會產生永遠對不上的網域。

### 2.3 標籤生成

```python
LABEL_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789"

def generate_domain(rnd: BSDRandom, tld: str = "icu") -> str:
    label = "".join(LABEL_CHARS[rnd.next() % len(LABEL_CHARS)]
                    for _ in range(15))
    return f"{label}.{tld}"
```

植入體維護 10 個 delay 槽位（uint16 值）；每次生成網域消耗一個
槽位——這是自我限速的節流機制。

### 2.4 位置與驗證

DGA 實作位於 Mach-O payload 的非匯出函式區；行動種子位於每個
行動世代的固定位移（兩個觀察到的行動快照使用不同種子——操作者
輪替種子而非演算法）。種子值不予披露。

驗證：以擷取行動 Mach-O 中提取的種子餵入重新實作，重現了擷取
流量中觀察到的完整網域序列——第一個生成的網域與主要 C2 主機
吻合、第二個與模組下載主機吻合。DGA 完全確定：持有任一 Coruna
樣本的防禦者，可在攻擊者註冊網域之前列舉該行動完整的未來網域
清單。

### 2.5 防禦劇本

1. 自擷取樣本提取種子（每個行動世代有固定位移）。
2. 以上述演算法重生成序列——每個網域成本：一次雜湊、一次
   delay 燒毀、15 次 RNG 抽取（微秒等級）。
3. 在 DNS 層黑名單 / sinkhole 整份清單，包含尚未註冊的網域。
4. 對符合 15 字元隨機 `[a-z0-9]` 標籤模式的新註冊低價 TLD 網域
   設置告警。

### 實作指紋

- MurmurHash2 搭配 `0x12345678` 種子常數；`h ^= len(data)` 初始化。
- 含 310 次預熱的 BSD `random()` TYPE_3。
- 與網域生成綁定的 delay 槽位節流。
- 低價 TLD 下 15 字元 `[a-z0-9]` 標籤。

---

## 3. C2 通訊協定

九個端點、一個明文心跳，其餘全是加密 POST——刻意精簡，且極易
在網路流量中被指紋化。

| 端點 | 方法 | 用途 | 主體 |
|------|------|------|------|
| `/vhx` | GET | 心跳 | 明文 `OK` 回應 |
| `/a` | POST | 註冊 / 簽到 | 加密 |
| `/event` | POST | 事件回報 | 加密 |
| `/u` | POST | 已安裝 App 清單 | 加密 |
| `/nb` | POST | 批量上傳（相簿、大型資料） | 加密 |
| `/ub` | POST | 單筆上傳 | 加密 |
| `/details/<模組>` | GET | 模組下載（7z 封裝） | — |
| `/api/ip-sync/sync` | POST | 操作者端 IP 同步 | 加密 |
| `/config` | POST | 設定推拉（`config.json`） | 加密 |

```
客戶端                                         伺服器
  │                                              │
  │  POST /a（或 /event /u /nb /ub…）            │
  │  標頭：  x-ts: <unix 秒>                      │
  │  主體：  Base64( AES-256-ECB(                 │
  │           key = SHA256(PREFIX + x-ts)[:32],   │
  │           pt  = x-ts ‖ JSON,                 │
  │           pad = PKCS7 ) )                    │
  │─────────────────────────────────────────────>│
  │                                              │
  │  200 OK                                       │
  │  主體：Base64( 16 個隨機位元組 )               │
  │<─────────────────────────────────────────────│
```

`PREFIX` 是編譯進該行動每個樣本的固定 16 字元常數；其值不在此
披露（持有樣本者可在金鑰推導呼叫旁的字串常數中提取）。

**為什麼此設計很弱：**

- 時間戳以明文同行，因此任何網路觀察者都能推導每個請求的金鑰
  ——此機制只防隨意的內容檢視。
- 對 JSON 使用 AES-256-**ECB** 會洩漏區塊級重複。
- 16 個隨機位元組的回應不含任何資訊；只是讓回應具有固定且可
  辨識的大小（24 個 Base64 字元）。
- 註冊內容包含穩定的裝置識別碼——植入體連線在網域輪替間仍可
  被追蹤。

**心跳生命週期：** 植入體定期對當前 DGA 網域發出 `GET /vhx`；
存活伺服器回應明文 `OK`。失敗時植入體推進 DGA 游標（消耗一個
delay 槽位）、改試下一個生成的網域——這是讓它在網域被撤下後
仍可達的「死亡開關」，也是讓它暴露於被動 DNS 監控的訊號。

**模組抓取：** 普通 `GET` 請求回傳 7z 加密封裝。模組採延遲
取得——只有在偵測到或開啟對應的受害者 App 之後——因此抓包中的
模組流量可直接映射受害者的已安裝 App。

**設定通道：** `helion.js` 管理一份 JSON 區塊（各模組設定、排程
參數、網域游標狀態），快取於磁碟；變更生效無需重新部署。

**偵測特徵：**

- 週期性的明文 `GET /vhx` → `OK` 往返。
- 純高熵 Base64 的 POST 主體，且必伴數值型 `x-ts` 標頭。
- 固定 24 字元大小的回應主體。
- 回傳 7z 封裝的 `GET /details/<名稱>.js` 請求。
- 受害者 App 開啟後立即出現的加密 POST 爆發。

---

## 4. 流量鑑識 — 90 請求時間線

一次完整感染連線——從水坑頁面到穩態 C2——被完整擷取以供分析
（約 90 個請求）。它以縮影呈現完整生命週期。

| 階段 | 流量 | 揭示內容 |
|------|------|----------|
| 1. 投放 | 水坑頁面 + 隱藏 iframe 資源 | 誘餌與攻擊載入器 |
| 2. 基礎設施 | IP 回聲查詢、OCSP/CRL 檢查、操作者同步主機 | 偵察與側信道記帳 |
| 3. 植入啟動 | 首次 DGA 網域接觸、註冊、App 清單、模組下載 | 植入體甦醒 |
| 4. 穩態 | 心跳迴圈 + 事件回報，受害者 App 開啟後爆發 | 排程與資料竊取 |

**側信道（第 2 階段）：** 植入體站穩之前，攻擊層先查詢公用
IP 回聲服務（「我的 IP」），隨後 POST 到操作者控制的
`/api/ip-sync/sync` 端點——把受害者位址與操作者端紀錄同步。
網頁先查 IP 回聲、接著出現這個冷僻 POST，並非正常網頁行為，
是植入前的可靠早期指標。

**植入啟動（第 3 階段）：** 第一個 DGA 生成網域以 `CONNECT`
形式出現——低價 TLD 上 15 字元隨機標籤的網域、持新簽發憑證。
數秒之內：心跳、註冊、App 清單與模組下載。

**由 App 觸發的竊取（第 4 階段）：** 穩態是安靜的心跳/事件
迴圈；**開啟受害者 App 即引爆資料竊取。**在擷取的連線中，開啟
一款加密錢包 App（imToken）產生了立即的 `/event` 回報爆發、
一筆 **1.8 MB** 加密 POST 送往批量上傳端點（`/nb`）、以及隨後
又一筆 **624 KB** POST。內容為 AES 加密容器；其大小與時序
（而非內容）才是鑑識訊號。

**判讀「未知」主機**——誤判非惡意主機只會浪費精力：

| 主機類別 | 判定 | 原因 |
|----------|------|------|
| 簽發憑證機構的 OCSP/CRL 端點 | 合法 | 新簽發憑證的標準 TLS 驗證 |
| 公用 IP 回聲服務 | 服務合法、用途惡意 | 偵察側信道 |
| 操作者同步主機 | 惡意 | 操作者記帳 |
| 15 字元隨機標籤的低價 TLD 網域 | 惡意 | DGA 產物（已驗證，見第 2 節） |

**POST 體積側寫：**

| 端點 | 典型大小 | 備註 |
|------|----------|------|
| `/event` | 0.5–0.7 KB | 高頻 |
| `/a` | 約 1.3 KB | 註冊時一次 |
| `/u` | 約 1 KB | 週期性刷新 |
| `/nb` | **觀測到 1.8 MB / 624 KB** | 批量竊取，由 App 觸發 |
| `/ub` | 小 | 輔助上傳路徑 |

**鑑識檢查清單：**

1. 建立安靜迴圈的基線：週期性 `GET /vhx → OK` 搭配帶 `x-ts`
   標頭的 POST，即植入體的靜息心跳。
2. 將爆發與 App 開啟關聯——錢包 App 開啟後數秒內出現 1.8 MB
   加密 POST，近乎定論。
3. 裝置連過的任何 15 字元隨機標籤網域，都可對照 DGA 演算法
   檢驗（見第 2 節）。
4. 盯住側信道：IP 回聲查詢後接 `POST /api/ip-sync/sync`，可在
   植入前識別該行動。
5. 別追著憑證機構跑——OCSP/CRL 流量是憑證基礎設施在正常運作。

---

## 5. 植入模組 — 功能與偵測

| 功能 | 涉及模組 | 備註 |
|------|----------|------|
| 錢包竊取 | 19 個錢包模組 | 助記詞、私鑰、App 資料 |
| 相簿竊取 | 核心 + 批量上傳 | 加密 `.dat` 容器經 `/nb` 外傳 |
| 簡訊 / SIM | `sms.js` | 電話號碼、SIM 在位/有效狀態、電信業者 |
| WhatsApp | `wap.js` | 聊天資料庫存取 |
| 常駐 / 核心 | `new.js`（CorePayload.dylib） | SpringBoard 注入、排程、DGA 迴圈 |
| 設定與下載 | `helion.js` | `config.json` 接收器、模組下載器 |

植入體經 C2 抓取 7z 加密模組並注入執行中的程序；下載採**延遲
載入**——先盤點已安裝 App（`/u`），只抓取對應的模組。

### 19 個錢包目標

| 生態系 | 錢包 |
|--------|------|
| EVM / 多鏈 | MetaMask、Trust Wallet、imToken、BitKeep、OKX、Global Wallet、Krystal、Coin98、Bitpie、Exodus |
| Solana | Phantom、Solflare |
| TON | TON Keeper、MyTonWallet、TonHub |
| Tron | TronLink |
| DEX / 其他 | Uniswap、Ronin |

每個錢包模組收割該 App 的沙盒資料——金鑰庫、助記詞備份與偏好
設定——並打包送往批量上傳通道。

### 相簿竊取

- 相片被包進以 PLzma 風格 SDK 構建的自訂 `.dat` 容器——7z 衍生
  格式，結合 AES 加密與 LZMA2 壓縮，觀測批次中並套用 ARM64 BCJ
  分支過濾器（7z coder `0x0a`）。
- 觀測批次中每個容器打包約上百張相片。
- 容器走批量上傳端點（`/nb`），對應擷取連線中的大型加密 POST
  （見第 4 節）。

### 支援的 iOS 版本

| iOS 區間 | 攻擊鏈（觀測階段名稱） |
|----------|------------------------|
| 13.0–14.x | buffout → breezy |
| 15.0–15.5 | jacurutu → VariantB |
| 15.6–16.1 | bluebird → seedbell |
| 16.2–16.5 | terrorbird → seedbell |
| 16.6–17.2 | cassowary → seedbell_pre → seedbell_17 |

payload manifest 攜帶逐版本/架構的條目（擷取的行動中有 19 組），
因此工具包交付的組建能精確對應受害者的 OS。manifest 的 `0x04`
旗標族標記版本涵蓋範圍——比對不同樣本間的這些旗標，是區分行動
世代的快速方法。

### 偵測與威脅獵捕

- **程序注入**：dylib 自非系統路徑載入 SpringBoard 或 powerd。
- **檔案痕跡**：App 可寫位置中的加密 `.dat` 容器與 `.min.js`
  檔案；以 `.js` URL 形式抓取的 7z 封裝。
- **行為面**：錢包 App 開啟後數秒內，對新註冊網域出現大型加密
  上傳。
- **YARA 機會**：F00DBEEF magic、DJB ChaCha20 常數序列、
  MurmurHash2 的 `0x12345678` 種子常數，都是可靠的二進位簽章。

### 評估

模組名冊讀起來像一份產品型錄：五個生態系的 19 款錢包，外加
WhatsApp、簡訊與相簿——這樣的涵蓋面服務的是財務動機的竊取，
而非國家級情蒐。結合商業化外觀的版本矩陣，此工具包最恰當的
理解是**可租用的監控產品**：操作者輪替種子與網域，核心平台
則重複使用。

---

## 授權

文件內容採 [CC BY 4.0](LICENSE) 授權。
