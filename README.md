---
title: AI 歌曲工坊 · 账号服务
emoji: 🎵
colorFrom: indigo
colorTo: pink
sdk: docker
pinned: false
app_port: 7860
---

# AI 歌曲工坊 · 账号服务后端

供「AI 歌曲工坊」桌面端 EXE 使用的公网账号服务：
- 注册 / 登录 / 会话鉴权
- 部署者独立后台（开启/关闭用户使用权限）
- 数据存于 SQLite，随容器持久化

## 环境变量
| 变量 | 说明 | 默认 |
| --- | --- | --- |
| ADMIN_USERNAME | 部署者后台账号 | admin |
| ADMIN_PASSWORD | 部署者后台密码（生产必改） | admin123 |
| NEW_USER_ACTIVE | 1=注册即用；0=注册后需部署者在后台开启 | 1 |
