# Frontend 101 Presentation

## Overview
This is a comprehensive Reveal.js presentation designed for a 2-hour beginner's workshop on web development. The presentation teaches students how to create static websites using HTML and CSS, and how to deploy them to GitHub Pages.

## Presentation Structure

The presentation consists of 9 files total: 2 index files (bilingual support), 6 content sections, and 1 README. The presentation content is organized into 6 main sections with approximately 112 slides total:

### 1. Introduction (`_index.md` / `_index.en.md`)
- Course objectives and goals
- Duration: ~2 hours
- Target audience: Complete beginners
- Today's agenda overview

### 2. Web Basics (`01-web-basics.md`)
**Topics covered:**
- What is the Web?
- Frontend vs Backend
- How browsers display web pages
- URL structure breakdown
- Static vs Dynamic websites

**Interactive elements:**
- Developer tools exercise (Network tab)
- Quiz: Identifying static websites

### 3. HTML Basics (`02-html.md`)
**Topics covered:**
- What is HTML?
- HTML document structure
- Tag syntax (opening, closing, self-closing)
- Common elements:
  - Headings (h1-h6)
  - Paragraphs and text formatting
  - Links and images
  - Lists (ordered/unordered)
  - Containers (div, span)
  - Semantic HTML5 elements
  - Form elements
- HTML attributes

**Interactive elements:**
- Practice Exercise 1: Build a self-introduction page
- Quiz: Link tag identification
- Quiz: div vs span difference

### 4. CSS Basics (`03-css.md`)
**Topics covered:**
- What is CSS?
- Three ways to write CSS (inline, internal, external)
- CSS syntax structure
- Selectors (tag, class, ID, combined)
- Common properties:
  - Text styling
  - Colors (names, hex, RGB, RGBA)
  - Backgrounds
  - Borders
- CSS Box Model
- Display properties
- **Flexbox Layout System:**
  - flex-direction
  - justify-content
  - align-items
  - flex-wrap
  - flex child properties

**Interactive elements:**
- Practice Exercise 2: Build card layout with Flexbox
- Quiz: CSS selector types
- Quiz: Flexbox alignment

### 5. Git Basics (`04-git.md`)
**Topics covered:**
- What is Git?
- Why use version control?
- Git workflow (Working → Staging → Local → Remote)
- What is GitHub?
- GitHub Desktop overview
- Creating a repository
- Commit process and best practices
- Push to GitHub

**Interactive elements:**
- Practice: Create repository and make first commit
- Quiz: What is a commit?
- Quiz: GitHub Desktop advantages

### 6. GitHub Pages Deployment (`05-github-pages.md`)
**Topics covered:**
- What is GitHub Pages?
- Advantages (free, fast, HTTPS, CDN)
- Deployment steps
- File structure requirements
- Checking deployment status
- Common issues and troubleshooting
- Updating your website
- Custom domain setup
- Responsive design basics

**Interactive elements:**
- Practice Exercise 3: Deploy a complete website
- Personal portfolio project suggestions
- Quiz: GitHub Pages capabilities
- Quiz: Website update process

### 7. Summary and Resources (`06-summary.md`)
**Topics covered:**
- Lesson recap
- Final project suggestions
- Learning path recommendations (3 stages)
- Resource links:
  - Learning platforms (MDN, W3Schools, freeCodeCamp, Codecademy)
  - Practice platforms (Frontend Mentor, CSS Battle, Flexbox Froggy, Grid Garden)
  - Design inspiration (Dribbble, Behance, Awwwards)
  - Tools (Coolors, Adobe Color, Font Awesome, Unsplash, Pexels)
- Learning tips
- FAQ section
- Course assignment

## Presentation Features

### Learning Elements
- **Multiple practice exercises** throughout the presentation
- **Quiz questions** with answers for each major section
- **Real-world examples** and best practices
- **Interactive demonstrations** suggestions
- **Progressive difficulty** from basics to deployment

### Technical Features
- Uses Reveal.js with the "black" theme
- Monokai syntax highlighting for code blocks
- Smooth slide transitions
- Section grouping for logical organization
- Fragment animations for progressive disclosure
- Code examples in multiple languages (HTML, CSS, JavaScript, Python)

## Accessing the Presentation

Once deployed, the presentation will be available at:
```
https://hlc23.dev/slides/frontend-101/
```

## Navigation

- **Arrow keys**: Navigate between slides
- **Esc or O**: Overview mode
- **S**: Speaker notes
- **F**: Fullscreen
- **B or .**: Pause (blackout)

## Teaching Tips

1. **Timing**: Approximately 1 minute per slide, with extra time for exercises
2. **Hands-on**: Encourage students to code along during exercises
3. **Breaks**: Plan breaks after HTML and CSS sections
4. **Q&A**: Leave time for questions at the end of each major section
5. **Final Project**: Reserve 30 minutes at the end for students to build and deploy their own website

## Customization

The presentation uses these settings (configurable in `_index.md`):
- Theme: black
- Highlight theme: monokai
- Transition: slide
- Transition speed: default

To change these, edit the `[reveal_hugo]` section in the front matter.

## Prerequisites

For students attending this workshop:
- A computer with internet access
- A text editor (VS Code, Sublime Text, or similar)
- A web browser (Chrome, Firefox, or Edge)
- A GitHub account (free)
- GitHub Desktop installed

## Course Materials

Students should create a project folder for the workshop and will build:
1. A simple self-introduction page (HTML practice)
2. A styled card layout (CSS practice)
3. A complete personal website (final project)

All projects will be version controlled with Git and deployed to GitHub Pages.

## License

This presentation follows the license of the parent repository.
