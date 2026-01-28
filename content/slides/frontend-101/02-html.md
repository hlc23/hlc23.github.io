+++
weight = 20
+++

{{% section %}}

# HTML 基礎
## HyperText Markup Language

---

## 什麼是 HTML？

- **H**yper**T**ext **M**arkup **L**anguage
- 超文本標記語言
- 定義網頁的**結構**和**內容**
- 使用「標籤」(tags) 來標記內容

---

## HTML 基本結構

```html
<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <title>我的第一個網頁</title>
</head>
<body>
    <h1>Hello, World!</h1>
</body>
</html>
```

---

## HTML 標籤結構

```html
<tagname>內容</tagname>
```

<ul>
<li class="fragment"><code>&lt;tagname&gt;</code> - 開始標籤</li>
<li class="fragment"><code>&lt;/tagname&gt;</code> - 結束標籤</li>
<li class="fragment">內容 - 放在標籤之間</li>
</ul>

---

## 特殊標籤：自閉合標籤

有些標籤不需要結束標籤

```html
<br>      <!-- 換行 -->
<hr>      <!-- 水平線 -->
<img src="photo.jpg">  <!-- 圖片 -->
<input type="text">    <!-- 輸入框 -->
```

---

## 標題標籤

```html
<h1>最大的標題</h1>
<h2>第二大的標題</h2>
<h3>第三大的標題</h3>
<h4>第四大的標題</h4>
<h5>第五大的標題</h5>
<h6>最小的標題</h6>
```

<p class="fragment">💡 <code>&lt;h1&gt;</code> 通常一個頁面只用一次（主標題）</p>

---

## 段落與文字

```html
<p>這是一個段落</p>

<strong>粗體文字</strong>
<em>斜體文字</em>
<u>底線文字</u>

<br>  <!-- 換行 -->
<hr>  <!-- 水平分隔線 -->
```

---

## 連結標籤

```html
<!-- 外部連結 -->
<a href="https://google.com">Google</a>

<!-- 內部頁面 -->
<a href="/about.html">關於我</a>

<!-- 錨點連結 -->
<a href="#section1">跳到第一節</a>

<!-- 開新分頁 -->
<a href="https://github.com" target="_blank">
    GitHub
</a>
```

---

## 圖片標籤

```html
<img src="photo.jpg" alt="照片描述">
```

<ul>
<li class="fragment"><code>src</code> - 圖片來源 (必填)</li>
<li class="fragment"><code>alt</code> - 替代文字 (必填，無障礙設計)</li>
<li class="fragment"><code>width</code> - 寬度 (選填)</li>
<li class="fragment"><code>height</code> - 高度 (選填)</li>
</ul>

---

## 列表

```html
<!-- 無序列表 -->
<ul>
    <li>項目一</li>
    <li>項目二</li>
    <li>項目三</li>
</ul>

<!-- 有序列表 -->
<ol>
    <li>第一步</li>
    <li>第二步</li>
    <li>第三步</li>
</ol>
```

---

## 容器標籤

```html
<!-- div: 區塊容器 (block-level) -->
<div>
    <h2>區塊標題</h2>
    <p>區塊內容</p>
</div>

<!-- span: 行內容器 (inline) -->
<p>這是<span style="color:red">紅色</span>文字</p>
```

---

## 語意化標籤 (HTML5)

```html
<header>頁首</header>
<nav>導航列</nav>
<main>
    <article>文章內容</article>
    <section>章節</section>
</main>
<aside>側邊欄</aside>
<footer>頁尾</footer>
```

<p class="fragment">💡 使用語意化標籤讓程式碼更易讀</p>

---

## 表單元素

```html
<form>
    <label for="name">姓名：</label>
    <input type="text" id="name" name="name">
    
    <label for="email">Email：</label>
    <input type="email" id="email" name="email">
    
    <textarea name="message"></textarea>
    
    <button type="submit">送出</button>
</form>
```

---

## HTML 屬性

```html
<tag attribute="value">內容</tag>
```

常見屬性：
- `id` - 唯一識別碼
- `class` - 類別名稱（可重複）
- `style` - 內嵌樣式
- `title` - 提示文字
- `src` - 來源
- `href` - 連結

---

## 🎯 實作練習 1

建立一個簡單的自我介紹頁面，包含：

1. 一個 `<h1>` 主標題（你的名字）
2. 一張照片 `<img>`
3. 一個段落 `<p>` 介紹自己
4. 一個列表 `<ul>` 列出 3 個興趣
5. 一個連結 `<a>` 到你的社群媒體

---

## 🎯 練習解答範例

```html
<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <title>關於我</title>
</head>
<body>
    <h1>張小明</h1>
    <img src="photo.jpg" alt="我的照片">
    <p>大家好，我是一個網頁開發初學者！</p>
    <h2>我的興趣：</h2>
    <ul>
        <li>程式設計</li>
        <li>閱讀</li>
        <li>旅行</li>
    </ul>
    <a href="https://github.com/username">我的 GitHub</a>
</body>
</html>
```

---

## 💡 小測驗

**問題**: 以下哪個標籤用來建立超連結？

<ul>
<li class="fragment">A. <code>&lt;link&gt;</code></li>
<li class="fragment">B. <code>&lt;a&gt;</code></li>
<li class="fragment">C. <code>&lt;href&gt;</code></li>
<li class="fragment">D. <code>&lt;url&gt;</code></li>
</ul>

<p class="fragment" style="color:#4ade80">答案: B (<code>&lt;a&gt;</code>)</p>

---

## 💡 小測驗

**問題**: `<div>` 和 `<span>` 的差別是？

<ul>
<li class="fragment">A. <code>&lt;div&gt;</code> 是區塊元素，<code>&lt;span&gt;</code> 是行內元素</li>
<li class="fragment">B. <code>&lt;div&gt;</code> 是行內元素，<code>&lt;span&gt;</code> 是區塊元素</li>
<li class="fragment">C. 沒有差別</li>
</ul>

<p class="fragment" style="color:#4ade80">答案: A</p>

{{% /section %}}
