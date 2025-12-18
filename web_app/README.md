# Instagram Clone（FastAPI 版）

基于 instagrapi 的 Instagram 采集与展示后端，已迁移为 FastAPI，并增加基础安全措施（管理端 Basic Auth、凭据加密存储、配置校验）。

## 核心特性
- 多账号轮换采集，支持代理。
- 定时任务（APS cheduler）批量更新用户与媒体。
- 媒体下载到 `media/`，随机流式返回。
- 管理接口需 Basic Auth（默认 `admin/admin`，请务必修改）。

## 快速开始
```bash
cd web_app
pip install -r requirements.txt

# 配置环境变量（示例）
set SECRET_KEY=replace-me
set ADMIN_USERNAME=your-admin
set ADMIN_PASSWORD=strong-pass
set INSTAGRAM_ACCOUNTS=[{"username":"u1","password":"p1"}]

python run.py
# 访问 http://localhost:5000/health
```

## 主要环境变量
- `SECRET_KEY`：用于加密 Instagram 密码和 session（必须设置为强随机值）。
- `ADMIN_USERNAME` / `ADMIN_PASSWORD`：管理端 Basic Auth 凭据。
- `DATABASE_URL`：数据库连接字符串，默认为 SQLite。
- `INSTAGRAM_ACCOUNTS`：JSON 数组，形如 `[{"username":"u","password":"p","proxy":"http://..."}]`。
- `COLLECTION_INTERVAL_MINUTES` / `MAX_POSTS_PER_USER` / `DELAY_BETWEEN_REQUESTS`：采集节奏控制。

## API（节选）
- `GET /health`：健康检查
- `GET /stats`：统计信息
- `GET /medias?page=1&per_page=20`：随机媒体流
- 需 Basic Auth：
  - `POST /accounts`、`DELETE /accounts/{id}`
  - `POST /users`、`DELETE /users/{id}`
  - `POST /collect/{username}`
  - `POST /load_instagram_accounts`
  - `GET /jobs`、`GET /logs`

请求示例：
```bash
curl -u admin:admin -X POST http://localhost:5000/accounts \
  -H "Content-Type: application/json" \
  -d '{"username":"u1","password":"p1","proxy":null}'
```

## 安全改进
- 管理接口全部要求 Basic Auth。
- Instagram 密码加密存储（Fernet，基于 `SECRET_KEY` 派生）。
- 配置加载严格 JSON 校验，避免注入/崩溃。
- 调度器单实例启动，避免多进程重复执行。

## 注意与合规
本项目基于 Instagram 私有 API，可能违反平台条款；请评估并遵守相关法律与 ToS，控制采集频率与用途。***
