+++
weight = 60
+++

{{% section %}}

# SSRF

---

## What is SSRF?

---

<ul>
  <li class="fragment">Server-Side Request Forgery</li>
  <li class="fragment">攻擊者利用<span style="color:yellow">伺服器</span>發送惡意請求</li>
</ul>

---

### CSRF vs SSRF
{{% columns %}}
{{% column %}}
#### CSRF
控制 Browser 發送請求  
提權, 盜用使用者身份
{{% /column %}}

{{% column %}}
#### SSRF
控制 Server 發送請求
存取內網資源, RCE
{{% /column %}}
{{% /columns %}}

---



---

{{% /section %}}