+++
title = "{{ replace .Name "-" " " | title }}"
date = {{ .Date }}
outputs = ["Reveal"]
addAnchors: false  # Force anchors OFF
[reveal_hugo]
theme = "black"              # black, white, league, beige, sky, night, serif, simple, solarized
# custom_theme = "reveal-hugo/themes/robot-lung.css"
highlight_theme = "monokai"  # monokai, zenburn, github, dracula, etc.
transition = "slide"         # none, fade, slide, convex, concave, zoom
transition_speed = "default" # default, fast, slow
+++

# {{ replace .Name "-" " " | title }}

Your presentation starts here

---

## Slide 2

Add your content  

Put the shortcode around the slides you want to group together.

```markdown
{{%/* section */%}}

## Section slide 1

---

## Section slide 2

{{%/* /section */%}}
```

Keep going down.

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
