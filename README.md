## 项目简介

sdlc_golang 是一个基于 Go 语言构建的安全漏洞示范平台，旨在促进 DevSecOps 和安全开发生命周期 (SDLC) 实践。它通过模拟常见漏洞来增强开发人员的安全意识，并为安全行业从业者提供了一个实践和学习的环境。除了用于 DevSecOps 实践外，sdlc_golang 还可以用于学习漏洞知识、渗透测试和代码审计。本项目采用了前后端分离的设计模式，其中后端利用了轻量级框架 Gin，而前端则使用了 Vue 3。

**新增功能：**

sdlc_golang 现在集成了静态应用安全测试 (SAST) 技术，能够对代码进行实时扫描，识别潜在的安全漏洞。这一功能进一步增强了平台的安全性，帮助开发人员在代码编写阶段就能发现并修复潜在的安全问题，从而提升整体应用的安全性。

## 使用样例
sast扫描
![image](https://github.com/Night-Master/sdlc/blob/main/data/use2.png)
漏洞示范
![image](https://github.com/Night-Master/sdlc/blob/main/data/use2.png)

## 主要特性

- **前后端分离**：后端处理业务逻辑，前端负责用户交互。
- **轻量高效**：使用 Gin 框架，确保高并发下的性能稳定。
- **代码扫描**：使用ast技术对代码进行安全检测，为devsecops中漏洞左移做保障。

## 技术栈

- **后端**: Go (Gin 框架)
- **前端**: Vue 3

## 安装与运行

1. 下载最新版本的发布包
2. 运行发布包中的start.bat
3. 在web登录界面输入账号：user1，密码：hello
### 系统需求

- 支持的操作系统: Windows x86
- 计划支持: Linux, ARM 架构

## Project Description

`sdlc` is a security vulnerability management platform built with the Go language, aimed at promoting DevSecOps and Secure Development Lifecycle (SDLC) practices. It enhances developers' security awareness by simulating common vulnerabilities. In addition to being useful for DevSecOps, it can also be used by those in the security industry to learn about vulnerabilities or penetration testing, as well as for code auditing. It provides an environment for both practice and learning. The project employs a separation of frontend and backend design patterns, using the lightweight Gin framework for the backend and Vue 3 for the frontend.

## Key Features

- **Separation of Frontend and Backend**: The backend handles business logic, while the frontend manages user interaction.
- **Lightweight and Efficient**: Uses the Gin framework to ensure stable performance under high concurrency.
- **Future Expansion**: Plans to integrate Static Application Security Testing (SAST) functionality.

## Technology Stack

- **Backend**: Go (Gin Framework)
- **Frontend**: Vue 3

## Installation and Running

1. Download the latest release package.
2. Run the `start.bat` file included in the release package.
3. Log in to the web interface with the account: `user1`, password: `hello`.
### System Requirements

- Supported operating systems: Windows x86
- Planned support: Linux, ARM architecture

## プロジェクトの説明

`sdlc`はGo言語で構築されたセキュリティ脆弱性管理プラットフォームであり、DevSecOpsおよびセキュアな開発ライフサイクル（SDLC）の実践を促進することを目指しています。一般的な脆弱性をシミュレートすることで開発者のセキュリティ意識を強化します。DevSecOpsだけでなく、セキュリティ業界の人々が脆弱性やペンテストについて学ぶためにも使用できます。またコードレビューにも利用可能です。フロントエンドとバックエンドを分離する設計パターンが採用されており、バックエンドは軽量フレームワークのGinを利用し、フロントエンドはVue 3を使用しています。

## 主な機能

- **フロントエンドとバックエンドの分離**：バックエンドはビジネスロジックを処理し、フロントエンドはユーザーとの対話を担当します。
- **軽量かつ効率的**：Ginフレームワークを使用して、高負荷時のパフォーマンスを安定させます。
- **将来の拡張性**：スタティック アプリケーション セキュリティ テスト（SAST）機能を統合する予定です。

## テクノロジースタック

- **バックエンド**: Go (Gin フレームワーク)
- **フロントエンド**: Vue 3

## インストールと実行

1. 最新のリリースパッケージをダウンロードしてください。
2. リリースパッケージ内の`start.bat`を実行してください。
3. ウェブインターフェースにアカウント: `user1`、パスワード: `hello`でログインしてください。
### システム要件

- 対応しているオペレーティングシステム: Windows x86
- 今後の対応予定: Linux, ARM アーキテクチャ
