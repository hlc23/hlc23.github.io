+++
title = "{{ replace .Name "-" " " | title }}"
date = {{ .Date }}
outputs = ["Reveal"]
[reveal_hugo]
theme = "black"              # black, white, league, beige, sky, night, serif, simple, solarized
highlight_theme = "monokai"  # monokai, zenburn, github, dracula, etc.
transition = "slide"         # none, fade, slide, convex, concave, zoom
transition_speed = "default" # default, fast, slow
+++

# {{ replace .Name "-" " " | title }}

Your presentation starts here

---

## Slide 2

Add your content

Use `---` to separate horizontal slides

---

## Slide 3

Use `___` to separate vertical slides

---

## Features

- Bullet points
- **Bold text**
- *Italic text*
- `Code inline`

---

## Code Example

```python
def hello_world():
    print("Hello, World!")
```

---

## Thank You! 🎉
