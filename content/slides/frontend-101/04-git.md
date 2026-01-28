+++
weight = 40
+++

{{% section %}}

# Git 版本控制入門
## 用 GitHub Desktop 管理你的程式碼

---

## 什麼是 Git？

- **版本控制系統** (Version Control System)
- 追蹤檔案的變更歷史
- 多人協作開發
- 隨時回到過去的版本

---

## 為什麼需要 Git？

<ul>
<li class="fragment">📝 記錄每次修改</li>
<li class="fragment">⏮️ 隨時恢復到舊版本</li>
<li class="fragment">🤝 團隊協作不衝突</li>
<li class="fragment">🔍 查看誰改了什麼</li>
<li class="fragment">🌿 平行開發多個功能</li>
</ul>

---

## Git 基本概念

```text
工作目錄 → 暫存區 → 本地倉庫 → 遠端倉庫
(Working) (Staging) (Local)  (Remote)
```

<ul>
<li class="fragment"><strong>工作目錄</strong>: 你正在編輯的檔案</li>
<li class="fragment"><strong>暫存區</strong>: 準備提交的檔案</li>
<li class="fragment"><strong>本地倉庫</strong>: 你電腦上的版本紀錄</li>
<li class="fragment"><strong>遠端倉庫</strong>: 雲端的版本紀錄 (GitHub)</li>
</ul>

---

## 什麼是 GitHub？

- Git 的雲端託管平台
- 全球最大的程式碼託管網站
- 開發者的社群平台
- 可以展示你的作品集

---

## GitHub Desktop

圖形化介面的 Git 工具

<ul>
<li class="fragment">✅ 不需要記指令</li>
<li class="fragment">✅ 視覺化操作</li>
<li class="fragment">✅ 適合初學者</li>
</ul>

---

## 下載 GitHub Desktop

1. 前往 https://desktop.github.com
2. 下載對應你的作業系統版本
3. 安裝並登入你的 GitHub 帳號

<p class="fragment">💡 還沒有 GitHub 帳號？先去 github.com 註冊一個</p>

---

## 建立新的 Repository (倉庫)

**步驟**：

1. 開啟 GitHub Desktop
2. 點選 **File → New Repository**
3. 填寫資訊：
   - Name: `my-first-website`
   - Description: 我的第一個網站
   - Local Path: 選擇儲存位置
4. 點選 **Create Repository**

---

## Repository 建立完成！

你會在本地端看到一個新資料夾

```text
my-first-website/
├── .git/           (Git 資料夾，不要動它)
└── README.md       (專案說明檔)
```

---

## 加入你的網頁檔案

將你剛剛寫的 HTML 和 CSS 檔案放進這個資料夾

```text
my-first-website/
├── .git/
├── README.md
├── index.html      ← 你的 HTML
└── style.css       ← 你的 CSS
```

---

## Commit 提交變更

在 GitHub Desktop 中：

1. 左側會顯示變更的檔案
2. 在左下角輸入 **Commit message**
   - 例如：`Add HTML and CSS files`
3. 點選 **Commit to main**

---

## 什麼是 Commit？

- 一次「存檔」
- 記錄這次改了什麼
- 每個 commit 都有唯一的 ID
- 可以隨時回到任何一個 commit

---

## Commit Message 怎麼寫？

好的 commit message 範例：

```text
✅ Add homepage HTML structure
✅ Update navigation bar styling
✅ Fix mobile responsive layout
```

不好的範例：

```text
❌ update
❌ fix bug
❌ 改了一些東西
```

---

## Push 到 GitHub

1. 點選右上角 **Publish repository**
2. 選擇：
   - ✅ Public (公開，任何人都能看到)
   - ☐ Private (私人，只有你能看到)
3. 點選 **Publish repository**

---

## 恭喜！🎉

你的程式碼已經上傳到 GitHub 了！

在 GitHub Desktop 點選 **View on GitHub**

就能在瀏覽器看到你的 Repository

---

## Git 工作流程總結

```text
1. 修改檔案 (工作目錄)
      ↓
2. 檢視變更 (GitHub Desktop)
      ↓
3. 撰寫 Commit Message
      ↓
4. Commit (儲存到本地)
      ↓
5. Push (上傳到 GitHub)
```

---

## 🎯 小練習

1. 建立一個新的 Repository
2. 加入你的 HTML 和 CSS 檔案
3. 進行第一次 commit
4. Push 到 GitHub
5. 在瀏覽器開啟你的 GitHub Repository

---

## 💡 小測驗

**問題**: Git 的 commit 是什麼？

<ul>
<li class="fragment">A. 刪除檔案</li>
<li class="fragment">B. 上傳到雲端</li>
<li class="fragment">C. 記錄一次變更</li>
<li class="fragment">D. 建立新分支</li>
</ul>

<p class="fragment" style="color:#4ade80">答案: C (記錄一次變更)</p>

---

## 💡 小測驗

**問題**: GitHub Desktop 的主要優點是？

<ul>
<li class="fragment">A. 比指令列更快</li>
<li class="fragment">B. 圖形化介面，容易上手</li>
<li class="fragment">C. 功能比 Git 更強大</li>
<li class="fragment">D. 不需要網路</li>
</ul>

<p class="fragment" style="color:#4ade80">答案: B (圖形化介面，適合初學者)</p>

{{% /section %}}
