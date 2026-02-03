---
title: "Frontend 101 Cheatsheet"
date: 2026-02-03T15:58:00+08:00
draft: false
tableOfContents: true
addAnchors: true
description: 'A comprehensive cheatsheet for learning web development from scratch, covering HTML, CSS, and GitHub Pages deployment'
categories:
  - Programming
tags:
  - Tutorial
  - Frontend
  - HTML
  - CSS
---

This cheatsheet is compiled from the Frontend 101 course, providing a quick reference for HTML and CSS syntax for web development beginners.

## Web Fundamentals

### Components of the Web

Web development is divided into two main parts:

#### Frontend
**The part users can see**

- **HTML** - Structure of the webpage
- **CSS** - Styling of the webpage
- **JavaScript** - Interactions on the webpage

#### Backend
**The part users cannot see**

- Database
- Server logic
- API

💡 **Creating static websites doesn't require a backend!**

---

## HTML Basics

### What is HTML?

- **H**yper**T**ext **M**arkup **L**anguage
- Defines the **structure**, **semantics**, and **content** of web pages
- Uses "tags" to mark up content

### Basic HTML Structure

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>My First Webpage</title>
</head>
<body>
    <h1>Hello, World!</h1>
</body>
</html>
```

### HTML Tag Structure

```html
<tagname>Content</tagname>
```

- `<tagname>` - Opening tag
- `</tagname>` - Closing tag
- Content - Placed between tags

💡 Some tags don't need a closing tag (e.g., `<br>`, `<img>`, `<hr>`)

---

## Common HTML Tags

### Heading Tags

```html
<h1>Largest heading</h1>
<h2>Second largest heading</h2>
<h3>Third largest heading</h3>
<h4>Fourth largest heading</h4>
<h5>Fifth largest heading</h5>
<h6>Smallest heading</h6>
```

💡 `<h1>` should typically be used only once per page (main title)

### Paragraphs and Text

```html
<p>This is a paragraph</p>

<strong>Bold text</strong>
<em>Italic text</em>
<u>Underlined text</u>

<br>  <!-- Line break -->
<hr>  <!-- Horizontal rule -->
```

### Comments

```html
<!-- This is a comment -->
<p>This text will be displayed on the webpage</p>
<!--
    Multi-line comment
-->
```

💡 In VS Code, use `Ctrl + /` to quickly add/remove comments

### Link Tags

```html
<!-- External link -->
<a href="https://google.com">Google</a>

<!-- Internal page -->
<a href="/about.html">About Me</a>

<!-- Open in new tab -->
<a href="https://github.com" target="_blank">
    GitHub
</a>
```

### Image Tags

```html
<img src="photo.jpg" alt="Photo description">
<img src="https://example.com/image.png" alt="Example image" width="300" height="200">
```

**Attribute explanations:**
- `src` - Image source (required)
- `alt` - Alternative text (required, for accessibility)
- `width` - Width (optional)
- `height` - Height (optional)

### Lists

```html
<!-- Unordered list -->
<ul>
    <li>Item one</li>
    <li>Item two</li>
    <li>Item three</li>
</ul>

<!-- Ordered list -->
<ol>
    <li>First step</li>
    <li>Second step</li>
    <li>Third step</li>
</ol>
```

### Container Tags

```html
<!-- div: Block container (block-level) -->
<div>
    <h2>Block heading</h2>
    <p>Block content</p>
</div>

<!-- span: Inline container (inline) -->
<p>This is <span style="color:red">red</span> text</p>
```

💡 div and span have no inherent styling or semantics; they're mainly used to wrap content, but can be styled with CSS

### HTML Attributes

```html
<tag attribute="value">Content</tag>
```

**Common attributes:**
- `id` - Unique identifier
- `class` - Class name (can be reused)
- `style` - Inline styling
- `src` - Source
- `href` - Link

---

## CSS Basics

### What is CSS?

- **C**ascading **S**tyle **S**heets
- Controls the **appearance** and **layout** of web pages
- Makes HTML more beautiful

### Linking CSS Files

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

### CSS Syntax Structure

```css
selector {
    property: value;
    property: value;
}
```

- **Selector** - Selects elements to apply styles to
- **Property** - The style to change
- **Value** - The setting value for the style

---

## CSS Selectors

### 1. Tag Selector

Selects all elements of a specified tag

```css
p {
    color: blue;
}
```

### 2. Class Selector

Starts with `.`, can be reused

```html
<p class="highlight">Highlighted text</p>
```

```css
.highlight {
    background-color: yellow;
}
```

### 3. ID Selector

Starts with `#`, should be unique

```html
<h1 id="main-title">Main Title</h1>
```

```css
#main-title {
    color: red;
}
```

⚠️ IDs should be unique on a page

### 4. Combinator Selectors

```css
/* Select all p inside div */
div p {
    color: blue;
}

/* Select multiple tags */
h1, h2, h3 {
    font-family: Arial;
}
```

---

## Common CSS Properties

### Text Styling

```css
.text {
    color: #333;              /* Text color */
    font-size: 16px;          /* Font size */
    font-weight: bold;        /* Bold */
    font-family: Arial;       /* Font family */
    text-align: center;       /* Alignment */
    text-decoration: none;    /* Remove underline */
    line-height: 1.5;         /* Line height */
}
```

### Color Notation

```css
.colors {
    color: red;                    /* Color name */
    color: #ff0000;                /* Hexadecimal */
    color: rgb(255, 0, 0);         /* RGB */
    color: rgba(255, 0, 0, 0.5);   /* RGBA (with opacity) */
}
```

### Background

```css
.box {
    background-color: #f0f0f0;
    background-image: url('bg.jpg');
    background-size: cover;
    background-position: center;
    background-repeat: no-repeat;
}
```

### Border

```css
.box {
    border: 2px solid black;     /* Width style color */
    border-radius: 10px;         /* Rounded corners */
}
```

---

## CSS Box Model

Every HTML element is a "box" composed of:

- **Content** - Content area
- **Padding** - Space between content and border
- **Border** - Border
- **Margin** - Space between elements

### Box Model Properties

```css
.box {
    width: 300px;
    height: 200px;
    padding: 20px;        /* Padding */
    margin: 10px;         /* Margin */
    border: 2px solid #000;
}
```

### Padding/Margin Shorthand

```css
/* All sides the same */
padding: 20px;

/* Top/bottom left/right */
padding: 10px 20px;

/* Top left/right bottom */
padding: 10px 20px 15px;

/* Top right bottom left (clockwise) */
padding: 10px 15px 20px 25px;
```

---

## Display Property

```css
.block {
    display: block;     /* Block element (takes full width) */
}

.inline {
    display: inline;    /* Inline element (doesn't break line) */
}

.none {
    display: none;      /* Hide element */
}
```

---

## Flexbox Layout 🎯

Flexbox is the modern tool for web layout!

### What is Flexbox?

- Flexible Box Layout
- Easily arrange elements horizontally/vertically
- Automatically adjust element size and spacing
- Great for responsive design

### Enabling Flexbox

```css
.container {
    display: flex;
}
```

```html
<div class="container">
    <div>Item 1</div>
    <div>Item 2</div>
    <div>Item 3</div>
</div>
```

### Flex Direction

```css
.container {
    display: flex;
    flex-direction: row;      /* Horizontal (default) */
    /* flex-direction: column; */ /* Vertical */
}
```

### Main Axis Alignment (justify-content)

```css
.container {
    display: flex;
    justify-content: flex-start;   /* Left (default) */
    /* justify-content: center; */    /* Center */
    /* justify-content: flex-end; */  /* Right */
    /* justify-content: space-between; */ /* Space between */
    /* justify-content: space-around; */  /* Space around */
}
```

### Cross Axis Alignment (align-items)

```css
.container {
    display: flex;
    align-items: flex-start;   /* Top (default) */
    /* align-items: center; */    /* Vertical center */
    /* align-items: flex-end; */  /* Bottom */
}
```

### Flex Wrap

```css
.container {
    display: flex;
    flex-wrap: nowrap;    /* No wrap (default) */
    /* flex-wrap: wrap; */   /* Wrap */
}
```

### Flex Item Properties

```css
.item {
    flex: 1;            /* Distribute space equally */
    /* flex: 2; */        /* Take 2 portions of space */
    
    order: 1;           /* Adjust order */
    align-self: center; /* Individual alignment */
}
```

### Flexbox Example: Navigation Bar

```html
<div class="navbar">
    <div class="logo">LOGO</div>
    <div class="menu">Menu</div>
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

### Flexbox Example: Card Layout

```html
<div class="container">
    <div class="card">Card 1</div>
    <div class="card">Card 2</div>
    <div class="card">Card 3</div>
</div>
```

```css
.container {
    display: flex;
    gap: 20px;              /* Spacing */
    padding: 20px;
}

.card {
    flex: 1;                /* Distribute equally */
    padding: 30px;
    background-color: #4ade80;
    border-radius: 10px;
    text-align: center;
}
```

---

## Deploying to GitHub Pages

### What is GitHub Pages?

- **Free** website hosting service provided by GitHub
- Automatically builds a website from your repository
- Supports custom domains
- Suitable for static websites (HTML/CSS/JS)

### Deployment Steps

#### 1. Create GitHub Repository

1. Log in to your GitHub account
2. Click **+** in the top right, select **New repository**
3. Repository name: `my-website`
4. Click **Create repository**

#### 2. Upload Your Website Files

Upload your `index.html` and other files to the repository

#### 3. Enable GitHub Pages

1. Open your repository on GitHub
2. Click **Settings**
3. Find **Pages** in the left sidebar
4. In the **Source** section:
   - Branch: Select `main`
   - Folder: Select `/ (root)`
5. Click **Save**

#### 4. Wait for Deployment

- ⏳ GitHub will automatically start deployment
- ⏳ Usually takes 1-2 minutes
- ✅ URL will be displayed when complete

### Your Website URL

```text
https://your-username.github.io/repository-name/
```

For example:
```text
https://hlc23.github.io/my-website/
```

### Common Issues

#### 404 Not Found

Possible causes:
- File is not named `index.html`
- File is in a subfolder
- Still deploying (wait 1-2 minutes)

#### CSS/Images Not Loading

Check paths:

```html
<!-- ❌ Absolute path may have issues -->
<link rel="stylesheet" href="/style.css">

<!-- ✅ Use relative path -->
<link rel="stylesheet" href="style.css">
```

### Updating Your Website

1. Modify files locally
2. Upload to GitHub
3. Wait 1-2 minutes, website updates automatically

---

## Learning Resources

### Recommended Resources

- [MDN Web Docs](https://developer.mozilla.org/) - Most comprehensive web technology documentation
- [W3Schools](https://www.w3schools.com/) - Beginner-friendly tutorial website

### Development Tools

- **VS Code** - Recommended code editor
  - Live Server Extension - Live preview of web pages
- **GitHub Account** - For website deployment

---

## Key Points Review

### CSS Selectors

- `.className` - Class selector (can be reused)
- `#idName` - ID selector (unique)
- `tagName` - Tag selector

### Flexbox Alignment

- `justify-content` - Controls main axis (horizontal) alignment
- `align-items` - Controls cross axis (vertical) alignment
- For vertical centering, use `align-items: center;`

### Remember

- HTML defines structure
- CSS controls styling
- Static websites don't need a backend
- GitHub Pages provides free hosting

---

## Practice Suggestions

### Exercise 1: Self-Introduction Page

Create a simple self-introduction page including:

1. An `<h1>` main heading (your name)
2. A photo `<img>`
3. A paragraph `<p>` introducing yourself
4. A list `<ul>` of 3 interests
5. A link `<a>` to your social media

### Exercise 2: Flexbox Card Layout

Create a card layout using Flexbox:

1. Create a container `.container`
2. Put 3 cards `.card` inside
3. Use Flexbox to arrange cards horizontally
4. Add appropriate spacing between cards

### Exercise 3: Complete Deployment

Complete deployment practice:

1. Create a simple website project
2. Create a GitHub repository
3. Enable GitHub Pages
4. Verify the website is accessible
5. Modify content and update the website

---

**Happy learning!** 🎉
