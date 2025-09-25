---
title: "Syntax"
date: 2025-08-29T03:31:45+08:00
draft: true # Set 'false' to publish
tableOfContents: false # Enable/disable Table of Contents
description: ' '
categories:
  - 
tags:
  -
---


記一下幾個不常用的語法跟 Shortcodes  
{{<spoiler>}}懶得翻 doc 就直說{{</spoiler>}}

---

## Code block options
````text {file="content/example.md"}
```LANG [OPTIONS]
CODE
```
````

- `hl_Lines="1,3-5"`: Highlight specific lines
- `lineNoStart=N`: Start line numbering from N
- `lineNos`: Enable line numbers
- `tabWidth=N`: Set tab width to N spaces

## Shortcodes

### Spoiler

support image and text content  

```
{{</* spoiler */>}}SPOILER CONTENT{{</* /spoiler */>}} // process markdown then shortcodes
{{%/* spoiler */%}}SPOILER CONTENT{{%/* /spoiler */%}} // process shortcodes then markdown
```

### alert

```
{{</* alert "severity" "title" */>}}ALERT CONTENT{{</* /alert */>}}
```

Available severity levels:
- `info` : Information icon (circle with 'i')
- `warning` : Warning icon (triangle with exclamation)
- `error` : Error icon (circle with exclamation)
- `success` : Success icon (circle with checkmark)

Parameters:
- First parameter: severity level (required)
- Second parameter: title (optional)

Examples:
```
{{</* alert "info" "Information" */>}}This is an info alert{{</* /alert */>}}
{{</* alert "warning" */>}}This is a warning without title{{</* /alert */>}}
{{</* alert "error" "Error Occurred" */>}}Something went wrong{{</* /alert */>}}
{{</* alert "success" "Success!" */>}}Operation completed successfully{{</* /alert */>}}
```