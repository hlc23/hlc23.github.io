---
title: "Frontend 101 速查表"
date: 2026-02-03T15:58:00+08:00
draft: false
tableOfContents: true
addAnchors: true
description: '從零開始學網頁開發的完整速查表，涵蓋 HTML、CSS 和 GitHub Pages 部署'
categories:
  - Programming
tags:
  - Tutorial
  - Frontend
  - HTML
  - CSS
---

這份速查表是基於 Frontend 101 課程整理而成，提供網頁開發新手快速查找 HTML 和 CSS 語法的參考資料。

## 網頁基礎概念

### Web 的組成

網頁開發分為兩大部分：

#### Frontend (前端)
**使用者看得見的部分**

- **HTML** - 網頁的結構
- **CSS** - 網頁的樣式
- **JavaScript** - 網頁的互動

#### Backend (後端)
**使用者看不見的部分**

- 資料庫
- 伺服器邏輯
- API

💡 **製作靜態網頁不需要後端！**

---

## HTML 基礎

### 什麼是 HTML？

- **H**yper**T**ext **M**arkup **L**anguage
- 超文本標記語言
- 定義網頁的**結構**、**語意**和**內容**
- 使用「標籤」(tags) 來標記內容

### HTML 基本結構

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

### HTML 標籤結構

```html
<tagname>內容</tagname>
```

- `<tagname>` - 開始標籤
- `</tagname>` - 結束標籤
- 內容 - 放在標籤之間

💡 有些標籤不需要結束標籤（如 `<br>`, `<img>`, `<hr>`）

---

## HTML 常用標籤

### 標題標籤

```html
<h1>最大的標題</h1>
<h2>第二大的標題</h2>
<h3>第三大的標題</h3>
<h4>第四大的標題</h4>
<h5>第五大的標題</h5>
<h6>最小的標題</h6>
```

💡 `<h1>` 通常一個頁面只用一次（主標題）

### 段落與文字

```html
<p>這是一個段落</p>

<strong>粗體文字</strong>
<em>斜體文字</em>
<u>底線文字</u>

<br>  <!-- 換行 -->
<hr>  <!-- 水平分隔線 -->
```

### 註解

```html
<!-- 這是一個註解 -->
<p>這段文字會顯示在網頁上</p>
<!--
    多行註解
-->
```

💡 在 VS Code 中，使用 `Ctrl + /` 可以快速加入/移除註解

### 連結標籤

```html
<!-- 外部連結 -->
<a href="https://google.com">Google</a>

<!-- 內部頁面 -->
<a href="/about.html">關於我</a>

<!-- 開新分頁 -->
<a href="https://github.com" target="_blank">
    GitHub
</a>
```

### 圖片標籤

```html
<img src="photo.jpg" alt="照片描述">
<img src="https://example.com/image.png" alt="範例圖片" width="300" height="200">
```

**屬性說明：**
- `src` - 圖片來源（必填）
- `alt` - 替代文字（必填，無障礙設計）
- `width` - 寬度（選填）
- `height` - 高度（選填）

### 列表

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

### 容器標籤

```html
<!-- div: 區塊容器 (block-level) -->
<div>
    <h2>區塊標題</h2>
    <p>區塊內容</p>
</div>

<!-- span: 行內容器 (inline) -->
<p>這是<span style="color:red">紅色</span>文字</p>
```

💡 div 和 span 本身沒有任何樣式或語意，主要用來包裝內容，但可以用 CSS 來為它們添加樣式

### HTML 屬性

```html
<tag attribute="value">內容</tag>
```

**常見屬性：**
- `id` - 唯一識別碼
- `class` - 類別名稱（可重複）
- `style` - 內嵌樣式
- `src` - 來源
- `href` - 連結

---

## CSS 基礎

### 什麼是 CSS？

- **C**ascading **S**tyle **S**heets
- 階層樣式表
- 控制網頁的**外觀**和**排版**
- 讓 HTML 更美觀

### 連結 CSS 檔案

```html
<!-- index.html -->
<head>
    <link rel="stylesheet" href="style.css">
</head>
```

```css
/* style.css */
p {
    color: green;
    font-size: 16px;
}
```

### CSS 語法結構

```css
selector {
    property: value;
    property: value;
}
```

- **選擇器** (Selector) - 選擇要套用樣式的元素
- **屬性** (Property) - 要改變的樣式
- **值** (Value) - 樣式的設定值

---

## CSS 選擇器

### 1. 標籤選擇器

選擇所有指定標籤的元素

```css
p {
    color: blue;
}
```

### 2. Class 選擇器

使用 `.` 開頭，可重複使用

```html
<p class="highlight">重點文字</p>
```

```css
.highlight {
    background-color: yellow;
}
```

### 3. ID 選擇器

使用 `#` 開頭，應該是唯一的

```html
<h1 id="main-title">主標題</h1>
```

```css
#main-title {
    color: red;
}
```

⚠️ ID 在頁面中應該是唯一的

### 4. 組合選擇器

```css
/* 選擇 div 內的所有 p */
div p {
    color: blue;
}

/* 選擇多個標籤 */
h1, h2, h3 {
    font-family: Arial;
}
```

---

## 常用 CSS 屬性

### 文字樣式

```css
.text {
    color: #333;              /* 文字顏色 */
    font-size: 16px;          /* 字體大小 */
    font-weight: bold;        /* 粗體 */
    font-family: Arial;       /* 字體 */
    text-align: center;       /* 對齊 */
    text-decoration: none;    /* 移除底線 */
    line-height: 1.5;         /* 行高 */
}
```

### 顏色表示法

```css
.colors {
    color: red;                    /* 顏色名稱 */
    color: #ff0000;                /* 16進位 */
    color: rgb(255, 0, 0);         /* RGB */
    color: rgba(255, 0, 0, 0.5);   /* RGBA (透明度) */
}
```

### 背景

```css
.box {
    background-color: #f0f0f0;
    background-image: url('bg.jpg');
    background-size: cover;
    background-position: center;
    background-repeat: no-repeat;
}
```

### 邊框

```css
.box {
    border: 2px solid black;     /* 粗細 樣式 顏色 */
    border-radius: 10px;         /* 圓角 */
}
```

---

## CSS 盒子模型 (Box Model)

每個 HTML 元素都是一個「盒子」，由以下部分組成：

- **Content** - 內容區域
- **Padding** - 內距（內容與邊框之間）
- **Border** - 邊框
- **Margin** - 外距（元素與其他元素之間）

### 盒子模型屬性

```css
.box {
    width: 300px;
    height: 200px;
    padding: 20px;        /* 內距 */
    margin: 10px;         /* 外距 */
    border: 2px solid #000;
}
```

### Padding/Margin 簡寫

```css
/* 四個方向相同 */
padding: 20px;

/* 上下 左右 */
padding: 10px 20px;

/* 上 左右 下 */
padding: 10px 20px 15px;

/* 上 右 下 左 (順時針) */
padding: 10px 15px 20px 25px;
```

---

## Display 屬性

```css
.block {
    display: block;     /* 區塊元素（佔滿一行）*/
}

.inline {
    display: inline;    /* 行內元素（不換行）*/
}

.none {
    display: none;      /* 隱藏元素 */
}
```

---

## Flexbox 排版 🎯

Flexbox（彈性盒子布局）是現代網頁排版的神器！

### 什麼是 Flexbox？

- Flexible Box Layout (彈性盒子布局)
- 輕鬆實現水平/垂直排列
- 自動調整元素大小和間距
- 響應式設計的好幫手

### 啟用 Flexbox

```css
.container {
    display: flex;
}
```

```html
<div class="container">
    <div>項目 1</div>
    <div>項目 2</div>
    <div>項目 3</div>
</div>
```

### Flex 主軸方向

```css
.container {
    display: flex;
    flex-direction: row;      /* 水平排列（預設）*/
    /* flex-direction: column; */ /* 垂直排列 */
}
```

### 主軸對齊 (justify-content)

```css
.container {
    display: flex;
    justify-content: flex-start;   /* 靠左（預設）*/
    /* justify-content: center; */    /* 置中 */
    /* justify-content: flex-end; */  /* 靠右 */
    /* justify-content: space-between; */ /* 兩端對齊 */
    /* justify-content: space-around; */  /* 平均分配 */
}
```

### 交叉軸對齊 (align-items)

```css
.container {
    display: flex;
    align-items: flex-start;   /* 靠上（預設）*/
    /* align-items: center; */    /* 垂直置中 */
    /* align-items: flex-end; */  /* 靠下 */
}
```

### Flex 換行

```css
.container {
    display: flex;
    flex-wrap: nowrap;    /* 不換行（預設）*/
    /* flex-wrap: wrap; */   /* 換行 */
}
```

### Flex 子項目屬性

```css
.item {
    flex: 1;            /* 平均分配空間 */
    /* flex: 2; */        /* 佔 2 份空間 */
    
    order: 1;           /* 調整順序 */
    align-self: center; /* 個別對齊方式 */
}
```

### Flexbox 實戰範例：導航列

```html
<div class="navbar">
    <div class="logo">LOGO</div>
    <div class="menu">選單</div>
</div>
```

```css
.navbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 20px;
    background-color: #333;
    color: white;
}
```

### Flexbox 實戰範例：卡片排版

```html
<div class="container">
    <div class="card">卡片 1</div>
    <div class="card">卡片 2</div>
    <div class="card">卡片 3</div>
</div>
```

```css
.container {
    display: flex;
    gap: 20px;              /* 間距 */
    padding: 20px;
}

.card {
    flex: 1;                /* 平均分配 */
    padding: 30px;
    background-color: #4ade80;
    border-radius: 10px;
    text-align: center;
}
```

---

## 部署到 GitHub Pages

### 什麼是 GitHub Pages？

- GitHub 提供的**免費**網站託管服務
- 自動從你的 Repository 建立網站
- 支援自訂網域
- 適合靜態網站（HTML/CSS/JS）

### 部署步驟

#### 1. 建立 GitHub Repository

1. 登入你的 GitHub 帳號
2. 點選右上角的 **+**，選擇 **New repository**
3. Repository name: `my-website`
4. 點選 **Create repository**

#### 2. 上傳你的網站檔案

將你的 `index.html` 和其他檔案上傳到 Repository

#### 3. 啟用 GitHub Pages

1. 在 GitHub 網站開啟你的 Repository
2. 點選 **Settings** (設定)
3. 在左側選單找到 **Pages**
4. 在 **Source** 區域：
   - Branch: 選擇 `main`
   - Folder: 選擇 `/ (root)`
5. 點選 **Save**

#### 4. 等待部署

- ⏳ GitHub 會自動開始部署
- ⏳ 通常需要 1-2 分鐘
- ✅ 完成後會顯示網址

### 你的網站網址

```text
https://你的用戶名.github.io/repository-name/
```

例如：
```text
https://hlc23.github.io/my-website/
```

### 常見問題

#### 404 Not Found

可能原因：
- 檔案名稱不是 `index.html`
- 檔案在子資料夾內
- 還在部署中（等 1-2 分鐘）

#### CSS/圖片載入失敗

檢查路徑：

```html
<!-- ❌ 絕對路徑可能有問題 -->
<link rel="stylesheet" href="/style.css">

<!-- ✅ 使用相對路徑 -->
<link rel="stylesheet" href="style.css">
```

### 更新網站

1. 在本地修改檔案
2. 上傳到 GitHub
3. 等待 1-2 分鐘，網站自動更新

---

## 學習資源

### 推薦資源

- [MDN Web Docs](https://developer.mozilla.org/zh-TW/) - 最完整的網頁技術文件
- [W3Schools](https://www.w3schools.com/) - 適合初學者的教學網站

### 開發工具

- **VS Code** - 推薦的程式碼編輯器
  - Live Server Extension - 即時預覽網頁
- **GitHub Account** - 用於部署網站

---

## 複習重點

### CSS 選擇器

- `.className` - Class 選擇器（可重複使用）
- `#idName` - ID 選擇器（唯一）
- `tagName` - 標籤選擇器

### Flexbox 對齊

- `justify-content` - 控制主軸（水平）對齊
- `align-items` - 控制交叉軸（垂直）對齊
- 垂直置中使用 `align-items: center;`

### 記住

- HTML 定義結構
- CSS 控制樣式
- 靜態網頁不需要後端
- GitHub Pages 提供免費託管

---

## 實作練習建議

### 練習 1：自我介紹頁面

建立一個簡單的自我介紹頁面，包含：

1. 一個 `<h1>` 主標題（你的名字）
2. 一張照片 `<img>`
3. 一個段落 `<p>` 介紹自己
4. 一個列表 `<ul>` 列出 3 個興趣
5. 一個連結 `<a>` 到你的社群媒體

### 練習 2：Flexbox 卡片排版

使用 Flexbox 建立一個卡片排版：

1. 建立一個容器 `.container`
2. 裡面放 3 個卡片 `.card`
3. 使用 Flexbox 讓卡片水平排列
4. 卡片之間有適當間距

### 練習 3：完整部署流程

完整流程練習：

1. 建立一個簡單的網站專案
2. 建立 GitHub Repository
3. 啟用 GitHub Pages
4. 確認網站可以正常訪問
5. 修改內容並更新網站

---

**祝你學習愉快！** 🎉
