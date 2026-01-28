+++
weight = 10
+++

{{% section %}}

# 什麼是「網頁」？

---

## Web 的組成

{{% columns %}}
{{% column %}}
### Frontend (前端)
**使用者看得見的部分**

- HTML (結構)
- CSS (樣式)
- JavaScript (互動)
{{% /column %}}

{{% column %}}
### Backend (後端)
**使用者看不見的部分**

- 資料庫
- 伺服器邏輯
- API
{{% /column %}}
{{% /columns %}}

---

## 我們今天專注在...

<h3 style="color:#4ade80">Frontend 前端開發</h3>

製作靜態網頁不需要後端！

---

## 瀏覽器如何顯示網頁？

<ol>
<li class="fragment">你輸入網址 (URL)</li>
<li class="fragment">瀏覽器向伺服器發送請求</li>
<li class="fragment">伺服器回傳 HTML、CSS、JavaScript 檔案</li>
<li class="fragment">瀏覽器解析並渲染(render)成你看到的網頁</li>
</ol>

---

## 網址結構 (URL)

```text
https://github.com/hlc23/frontend-101?tab=code#readme
```

<ul>
<li class="fragment"><code>https://</code> - 協定 (Protocol)</li>
<li class="fragment"><code>github.com</code> - 網域 (Domain)</li>
<li class="fragment"><code>/hlc23/frontend-101</code> - 路徑 (Path)</li>
<li class="fragment"><code>?tab=code</code> - 查詢參數 (Query)</li>
<li class="fragment"><code>#readme</code> - 錨點 (Fragment)</li>
</ul>

---

## 💡 動動腦

打開瀏覽器的開發者工具 (F12)

- 切換到 **Network** 標籤
- 重新整理頁面
- 觀察有哪些檔案被載入？

---

## 靜態網頁 vs 動態網頁

{{% columns %}}
{{% column %}}
### 靜態網頁
- 內容固定
- 只有 HTML/CSS/JS
- 速度快
- 便宜/免費託管
{{% /column %}}

{{% column %}}
### 動態網頁
- 內容可變動
- 需要後端伺服器
- 可以有資料庫
- 使用者互動多
{{% /column %}}
{{% /columns %}}

---

## 🎯 小練習

**問題**: 以下哪些是靜態網頁？

<ul>
<li class="fragment">A. 個人履歷網站</li>
<li class="fragment">B. Facebook</li>
<li class="fragment">C. 產品介紹頁面</li>
<li class="fragment">D. 網路銀行</li>
</ul>

<p class="fragment" style="color:#4ade80">答案: A 和 C</p>

{{% /section %}}
