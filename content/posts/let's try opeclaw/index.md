---
title: "Let's Try Openclaw"
date: 2026-02-25T21:17:45+08:00
draft: false # Set 'false' to publish
tableOfContents: false # Enable/disable Table of Contents
addAnchors: true
description: ''
categories:
  - AI
tags:
  - Let's try
---

## Intro

最近有個 AI agent，Openclaw 感覺蠻酷的，甚至出現 [moltbook](https://www.moltbook.com/) 這種 AI agent 專用的平台。  
酷酷的新東西不就是要來玩看看嗎。

## Setup

畢竟只是架起來玩玩看，而且他能幫我做什麼暫時也沒有想法。  
所以我想把整個費用壓到最低看看效果就好，當然另一方面是沒錢 QQ。  

這東西畢竟是有能力去執行程式或指令的，最好還是給一個獨立的環境給他。因此我選擇了 Oracle cloud 的 Always Free 4C24G 的機器來安裝。

然後就是要給他接腦子 (LLM) 上去，身為一個乞丐我直接再裝一個 ollama 跑 local。  

**但是...** 這機器沒有 GPU 欸，也就是靠著 4 核爛爛的 CPU 在算，結果可想而知。   
如果只是單純 ollama 做簡單的互動那還有點說法，但實際上是 Openclaw 接到 Discord bot 根本動不了，我猜主要是除了使用者跟他的對話之外，還有其他的 prompt 會被一起送進去然後就要算超久。

既然本地算不動，就改找免費的 AI provider 來接 API。  
我就找到 [OpenRouter](https://openrouter.ai) 來用。  
原本想說找免費的模型，後來發現這樣找特定的模型來用好像會先撞到 RateLimit。  
改成讓 OpenRouter 來自動調度模型使用後就沒這個問題。  
於是我就得到了一個混合一些笨模型的傻龍蝦助手(?)

## Result...

之後在 DC 跟他互動了幾次，也有把瀏覽器的功能接上，但體感上就是...

**我不覺得這能幫我做些什麼**  

好吧，也許還是該捨得花錢在訂閱 AI API 的，也許他能聰明一點，但不會是現在...
