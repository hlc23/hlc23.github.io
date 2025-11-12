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

### DEMO

[Lab: SSRF-DEMO](https://github.com/hlc23/CS-Labs/tree/main/ssrf-demo)

---

{{% /section %}}

---

{{% section %}}

## How SSRF works?

---

因為伺服器通常有較高的權限   
<span class="fragment">內網滲透</span> <span class="fragment">敏感資料存取</span>  
<h3 class="fragment">RCE (Remote Code Execution)</h3>

---

## Labs

---

- [Lab: SSRF-1](https://github.com/hlc23/CS-Labs/tree/main/SSRF-1)

---

{{% /section %}}