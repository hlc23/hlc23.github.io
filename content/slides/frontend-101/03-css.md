+++
weight = 30
+++

{{% section %}}

# CSS 基礎
## Cascading Style Sheets

---

## 什麼是 CSS？

- **C**ascading **S**tyle **S**heets
- 階層樣式表
- 控制網頁的**外觀**和**排版**
- 讓 HTML 更美觀

---

## CSS 三種寫法

1. **內嵌樣式** (Inline)
2. **內部樣式** (Internal)
3. **外部樣式** (External) ⭐ 推薦

---

## 1. 內嵌樣式 (Inline)

直接寫在 HTML 標籤內

```html
<p style="color: red; font-size: 20px;">
    這是紅色文字
</p>
```

<p class="fragment" style="color:#fbbf24">⚠️ 不推薦：難以維護</p>

---

## 2. 內部樣式 (Internal)

寫在 `<head>` 的 `<style>` 標籤內

```html
<head>
    <style>
        p {
            color: blue;
            font-size: 18px;
        }
    </style>
</head>
```

---

## 3. 外部樣式 (External) ⭐

獨立的 `.css` 檔案

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

<p class="fragment" style="color:#4ade80">✅ 最推薦：方便管理和重複使用</p>

---

## CSS 語法結構

```css
selector {
    property: value;
    property: value;
}
```

<ul>
<li class="fragment"><strong>選擇器</strong> (Selector) - 選擇要套用樣式的元素</li>
<li class="fragment"><strong>屬性</strong> (Property) - 要改變的樣式</li>
<li class="fragment"><strong>值</strong> (Value) - 樣式的設定值</li>
</ul>

---

## CSS 選擇器

### 1. 標籤選擇器

```css
p {
    color: blue;
}
```

選擇所有 `<p>` 標籤

---

## CSS 選擇器

### 2. Class 選擇器

```html
<p class="highlight">重點文字</p>
```

```css
.highlight {
    background-color: yellow;
}
```

<p class="fragment">💡 使用 <code>.</code> 開頭</p>

---

## CSS 選擇器

### 3. ID 選擇器

```html
<h1 id="main-title">主標題</h1>
```

```css
#main-title {
    color: red;
}
```

<p class="fragment">💡 使用 <code>#</code> 開頭</p>
<p class="fragment">⚠️ ID 在頁面中應該是唯一的</p>

---

## CSS 選擇器

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

---

## 常用 CSS 屬性

### 顏色表示法

```css
.colors {
    color: red;                    /* 顏色名稱 */
    color: #ff0000;                /* 16進位 */
    color: rgb(255, 0, 0);         /* RGB */
    color: rgba(255, 0, 0, 0.5);   /* RGBA (透明度) */
}
```

---

## 常用 CSS 屬性

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

---

## 常用 CSS 屬性

### 邊框

```css
.box {
    border: 2px solid black;     /* 粗細 樣式 顏色 */
    border-radius: 10px;         /* 圓角 */
}
```

---

## CSS 盒子模型 (Box Model)

每個 HTML 元素都是一個「盒子」

```text
┌─────────────────────────┐
│       Margin (外距)      │
│  ┌───────────────────┐  │
│  │  Border (邊框)    │  │
│  │  ┌─────────────┐  │  │
│  │  │ Padding(內距)│  │  │
│  │  │ ┌─────────┐ │  │  │
│  │  │ │ Content │ │  │  │
│  │  │ └─────────┘ │  │  │
│  │  └─────────────┘  │  │
│  └───────────────────┘  │
└─────────────────────────┘
```

---

## 盒子模型屬性

```css
.box {
    width: 300px;
    height: 200px;
    padding: 20px;        /* 內距 */
    margin: 10px;         /* 外距 */
    border: 2px solid #000;
}
```

---

## 簡寫屬性

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

# Flexbox 排版 🎯

現代網頁排版的神器！

---

## 什麼是 Flexbox？

- Flexible Box Layout (彈性盒子布局)
- 輕鬆實現水平/垂直排列
- 自動調整元素大小和間距
- 響應式設計的好幫手

---

## 啟用 Flexbox

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

---

## Flex 主軸方向

```css
.container {
    display: flex;
    flex-direction: row;      /* 水平排列（預設）*/
    /* flex-direction: column; */ /* 垂直排列 */
}
```

---

## 主軸對齊 (justify-content)

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

---

## 交叉軸對齊 (align-items)

```css
.container {
    display: flex;
    height: 300px;
    align-items: stretch;      /* 拉伸（預設）*/
    /* align-items: center; */    /* 垂直置中 */
    /* align-items: flex-start; */ /* 靠上 */
    /* align-items: flex-end; */   /* 靠下 */
}
```

---

## Flex 換行

```css
.container {
    display: flex;
    flex-wrap: nowrap;    /* 不換行（預設）*/
    /* flex-wrap: wrap; */   /* 換行 */
}
```

---

## Flex 子項目屬性

```css
.item {
    flex: 1;            /* 平均分配空間 */
    /* flex: 2; */        /* 佔 2 份空間 */
    
    order: 1;           /* 調整順序 */
    align-self: center; /* 個別對齊方式 */
}
```

---

## 🎯 Flexbox 實戰範例

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

---

## 🎯 實作練習 2

使用 Flexbox 建立一個卡片排版：

1. 建立一個容器 `.container`
2. 裡面放 3 個卡片 `.card`
3. 使用 Flexbox 讓卡片水平排列
4. 卡片之間有適當間距
5. 每個卡片有背景色、內距和圓角

---

## 🎯 練習解答範例

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

## 📝 複習重點

**CSS 選擇器類型**

- `.className` - Class 選擇器（可重複使用）
- `#idName` - ID 選擇器（唯一）
- `tagName` - 標籤選擇器
- `@` 符號用於 at-rules（如 @media、@keyframes）
- 選擇器讓我們能精確定位要套用樣式的元素

---

## 📝 複習重點

**Flexbox 對齊方式**

- `justify-content` 控制主軸（水平）對齊
- `align-items` 控制交叉軸（垂直）對齊
- 垂直置中使用 `align-items: center;`
- `text-align` 只用於文字對齊，不是 Flexbox 屬性
- 記住：items 是控制交叉軸的關鍵

{{% /section %}}
