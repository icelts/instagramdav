import json
import logging
import math
import os
import random
import secrets
import smtplib
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional
from uuid import uuid4

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from instagrapi.exceptions import ChallengeRequired
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import func, or_
from sqlalchemy.orm import Session
from urllib.parse import quote, urlencode
from xml.sax.saxutils import escape
from email.message import EmailMessage

from config import Config
from database import Base, SessionLocal, engine
from instagram_client import build_client_manager
from models import CollectionLog, CollectionTask, InstagramAccount, Media, TargetUser, Message
from scheduler import CollectionScheduler
from security import CredentialCipher

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

PLACEHOLDER_IMAGE = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw=="

app = FastAPI(title="Instagram Clone API", version="0.1.0")
security = HTTPBasic(auto_error=False)
app.add_middleware(
    SessionMiddleware,
    secret_key=Config.SECRET_KEY,
    session_cookie="admin_session",
    same_site="lax",
)

Base.metadata.create_all(bind=engine)
base_dir = Path(__file__).resolve().parent
os.makedirs(Config.MEDIA_FOLDER, exist_ok=True)
os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
os.makedirs(base_dir / "static", exist_ok=True)
os.makedirs(base_dir / "templates", exist_ok=True)

def _ensure_album_id_column():
    try:
        with engine.begin() as conn:
            result = conn.exec_driver_sql("PRAGMA table_info(medias)")
            columns = {row[1] for row in result}
            if "album_id" not in columns:
                conn.exec_driver_sql("ALTER TABLE medias ADD COLUMN album_id VARCHAR(50)")
                logger.info("已添加 medias.album_id 列")
    except Exception as exc:
        logger.warning("检查/创建 album_id 列失败: %s", exc)

_ensure_album_id_column()

cipher = CredentialCipher(Config.SECRET_KEY)
client_manager = build_client_manager(Config.SECRET_KEY)
scheduler = CollectionScheduler(SessionLocal)
scheduler_started = False
templates = Jinja2Templates(directory=str(base_dir / "templates"))

app.mount("/static", StaticFiles(directory=str(base_dir / "static")), name="static")
app.mount("/media", StaticFiles(directory=Config.MEDIA_FOLDER), name="media")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _is_admin_logged_in(request: Request) -> bool:
    return request.session.get("admin_user") == Config.ADMIN_USERNAME


def verify_admin(
    request: Request,
    credentials: Optional[HTTPBasicCredentials] = Depends(security),
):
    if _is_admin_logged_in(request):
        return request.session["admin_user"]

    if credentials and credentials.username and credentials.password:
        correct_username = secrets.compare_digest(credentials.username, Config.ADMIN_USERNAME)
        correct_password = secrets.compare_digest(credentials.password, Config.ADMIN_PASSWORD)
        if correct_username and correct_password:
            return credentials.username

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized",
        headers={"WWW-Authenticate": "Basic"},
    )


class AccountCreate(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)
    proxy: Optional[str] = None
    totp_secret: Optional[str] = None


class UserCreate(BaseModel):
    username: str = Field(..., min_length=1)
    immediate_collect: bool = False


class MediaResponse(BaseModel):
    id: int
    media_id: str
    media_type: str
    caption: str
    like_count: int
    comment_count: int
    view_count: int
    media_url: Optional[str]
    thumbnail_url: Optional[str]
    taken_at: Optional[str]
    user: dict


@app.on_event("startup")
async def startup_event():
    global scheduler_started
    if not scheduler_started:
        scheduler.start()
        scheduler_started = True
        logger.info("调度器已启动")


@app.get("/health")
def health():
    return {"status": "ok"}


def _public_media_url(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    path_str = str(path)
    if path_str.startswith(("http://", "https://", "data:")):
        return path_str
    path_obj = Path(path_str)
    candidates = []
    if path_obj.is_absolute():
        candidates.append(path_obj)
    else:
        candidates.append(Path(Config.MEDIA_FOLDER) / path_obj)
        candidates.append((Path.cwd() / path_obj).resolve())
    for candidate in candidates:
        try:
            rel = candidate.relative_to(Path(Config.MEDIA_FOLDER))
            return f"/media/{rel.as_posix()}"
        except Exception:
            continue
    return None


def _absolute_url(request: Request, path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    if path.startswith(("http://", "https://", "data:")):
        return path
    base_url = str(request.base_url).rstrip("/")
    if path.startswith("/"):
        return f"{base_url}{path}"
    return f"{base_url}/{path}"


def _send_message_notification(request: Request, name: str, email: str, content: str) -> Optional[str]:
    if not Config.SMTP_HOST or not Config.NOTIFY_EMAIL:
        return None
    msg = EmailMessage()
    msg["Subject"] = f"新留言：{name}"
    msg["From"] = Config.SMTP_FROM or Config.NOTIFY_EMAIL
    msg["To"] = Config.NOTIFY_EMAIL
    msg["Reply-To"] = email
    base_url = str(request.base_url).rstrip("/")
    msg.set_content(
        "\n".join(
            [
                "收到新的留言：",
                f"姓名：{name}",
                f"邮箱：{email}",
                f"内容：{content}",
                f"查看页面：{base_url}/guestbook",
            ]
        )
    )
    try:
        with smtplib.SMTP(Config.SMTP_HOST, Config.SMTP_PORT, timeout=10) as smtp:
            if Config.SMTP_USE_TLS:
                smtp.starttls()
            if Config.SMTP_USER and Config.SMTP_PASSWORD:
                smtp.login(Config.SMTP_USER, Config.SMTP_PASSWORD)
            smtp.send_message(msg)
        return None
    except Exception as exc:
        logger.warning("发送留言通知失败: %s", exc)
        return str(exc)


def _safe_next_path(raw: str) -> str:
    if not raw or not raw.startswith("/"):
        return "/admin"
    return raw


@app.get("/robots.txt", response_class=PlainTextResponse)
def robots(request: Request):
    base_url = str(request.base_url).rstrip("/")
    lines = [
        "User-agent: *",
        "Allow: /",
        "Disallow: /admin",
        "Disallow: /login",
        "Disallow: /logout",
        f"Sitemap: {base_url}/sitemap.xml",
    ]
    return "\n".join(lines)


@app.get("/sitemap.xml", response_class=Response)
def sitemap(request: Request, db: Session = Depends(get_db)):
    base_url = str(request.base_url).rstrip("/")
    urls = []

    def add_url(path: str, lastmod: Optional[datetime] = None):
        loc = escape(f"{base_url}{path}")
        lastmod_str = ""
        if lastmod:
            lastmod_str = f"<lastmod>{lastmod.date().isoformat()}</lastmod>"
        urls.append(f"<url><loc>{loc}</loc>{lastmod_str}</url>")

    add_url("/")
    add_url("/guestbook")

    users = db.query(TargetUser).all()
    for user in users:
        add_url(f"/{user.username}", user.updated_at or user.last_collected)

    medias = db.query(Media).all()
    for media in medias:
        add_url(f"/m/{media.id}", media.collected_at or media.created_at)

    body = "".join(urls)
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        f"{body}</urlset>"
    )
    return Response(content=xml, media_type="application/xml")


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next_path: str = Query("/admin", alias="next")):
    next_path = _safe_next_path(next_path)
    if _is_admin_logged_in(request):
        return RedirectResponse(next_path or "/admin", status_code=303)
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "next": next_path,
            "error": None,
            "title": "管理员登录",
            "description": "管理员登录后台管理采集任务",
            "robots": "noindex,nofollow",
        },
    )


@app.post("/login")
def login_action(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next_path: str = Form("/admin", alias="next"),
):
    next_path = _safe_next_path(next_path)
    correct_username = secrets.compare_digest(username, Config.ADMIN_USERNAME)
    correct_password = secrets.compare_digest(password, Config.ADMIN_PASSWORD)
    if correct_username and correct_password:
        request.session["admin_user"] = username
        return RedirectResponse(next_path or "/admin", status_code=303)
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "next": next_path,
            "error": "用户名或密码错误",
            "title": "管理员登录",
            "description": "管理员登录后台管理采集任务",
            "robots": "noindex,nofollow",
        },
        status_code=status.HTTP_401_UNAUTHORIZED,
    )


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.get("/stats")
def api_stats(db: Session = Depends(get_db)):
    return {
        "users_count": db.query(func.count(TargetUser.id)).scalar(),
        "active_users_count": db.query(func.count(TargetUser.id)).filter_by(is_active=True).scalar(),
        "medias_count": db.query(func.count(Media.id)).scalar(),
        "accounts_count": db.query(func.count(InstagramAccount.id)).scalar(),
        "active_accounts_count": db.query(func.count(InstagramAccount.id)).filter_by(is_active=True).scalar(),
        "running_tasks_count": db.query(func.count(CollectionTask.id)).filter_by(status="running").scalar(),
    }


@app.get("/jobs")
def api_jobs(user=Depends(verify_admin)):
    jobs = []
    for job in scheduler.scheduler.get_jobs():
        jobs.append(
            {
                "id": job.id,
                "name": job.name,
                "next_run_time": job.next_run_time.isoformat() if job.next_run_time else None,
                "trigger": str(job.trigger),
            }
        )
    return {"jobs": jobs}


@app.get("/logs")
def api_logs(limit: int = 50, user=Depends(verify_admin), db: Session = Depends(get_db)):
    logs = (
        db.query(CollectionLog)
        .order_by(CollectionLog.created_at.desc())
        .limit(min(limit, 200))
        .all()
    )
    return [
        {
            "id": log.id,
            "account_id": log.account_id,
            "target_user_id": log.target_user_id,
            "action": log.action,
            "message": log.message,
            "status": log.status,
            "created_at": log.created_at.isoformat(),
        }
        for log in logs
    ]


@app.post("/accounts")
def add_account(payload: AccountCreate, user=Depends(verify_admin), db: Session = Depends(get_db)):
    exists = db.query(InstagramAccount).filter_by(username=payload.username).first()
    if exists:
        raise HTTPException(status_code=400, detail="账号已存在")
    proxy = payload.proxy.strip() if payload.proxy else None
    totp_secret = payload.totp_secret.strip() if payload.totp_secret else None
    try:
        session_data = client_manager.login_and_get_settings(
            payload.username, payload.password, proxy=proxy, totp_secret=totp_secret
        )
    except ChallengeRequired:
        raise HTTPException(status_code=400, detail="账号需要挑战验证，请先完成验证")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"登录失败: {exc}")
    account = InstagramAccount(
        username=payload.username,
        password=cipher.encrypt(payload.password),
        proxy=proxy,
        totp_secret=cipher.encrypt(totp_secret) if totp_secret else None,
        session_data=session_data,
        is_active=True,
    )
    db.add(account)
    db.commit()
    db.refresh(account)
    return {"id": account.id, "username": account.username}


@app.delete("/accounts/{account_id}")
def remove_account(account_id: int, user=Depends(verify_admin), db: Session = Depends(get_db)):
    account = db.query(InstagramAccount).get(account_id)
    if not account:
        raise HTTPException(status_code=404, detail="账号不存在")
    db.delete(account)
    db.commit()
    return {"status": "deleted"}


@app.post("/users")
def add_user(payload: UserCreate, user=Depends(verify_admin), db: Session = Depends(get_db)):
    existing = db.query(TargetUser).filter_by(username=payload.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="用户已存在")
    target = TargetUser(username=payload.username, is_active=True)
    db.add(target)
    db.commit()
    db.refresh(target)

    scheduler.add_collection_jobs()

    if payload.immediate_collect:
        client_manager.collect_user_data(db, payload.username)

    return {"id": target.id, "username": target.username}


@app.delete("/users/{user_id}")
def remove_user(user_id: int, user=Depends(verify_admin), db: Session = Depends(get_db)):
    target = db.query(TargetUser).get(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="用户不存在")
    db.delete(target)
    db.commit()
    return {"status": "deleted"}


@app.post("/collect/{username}")
def collect_user(username: str, user=Depends(verify_admin), db: Session = Depends(get_db)):
    success = client_manager.collect_user_data(db, username)
    if not success:
        raise HTTPException(status_code=400, detail="采集失败")
    return {"status": "ok"}


@app.post("/load_instagram_accounts")
def load_instagram_accounts(user=Depends(verify_admin), db: Session = Depends(get_db)):
    try:
        accounts_data = json.loads(Config.INSTAGRAM_ACCOUNTS)
        if not isinstance(accounts_data, list):
            raise ValueError("INSTAGRAM_ACCOUNTS 需要是数组")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"配置解析失败: {exc}")

    created = 0
    for account_data in accounts_data:
        username = account_data.get("username")
        password = account_data.get("password")
        proxy = account_data.get("proxy")
        totp_secret = account_data.get("totp_secret")
        if not username or not password:
            continue
        if db.query(InstagramAccount).filter_by(username=username).first():
            continue
        account = InstagramAccount(
            username=username,
            password=cipher.encrypt(password),
            proxy=proxy,
            totp_secret=cipher.encrypt(totp_secret) if totp_secret else None,
            is_active=True,
        )
        db.add(account)
        created += 1
    db.commit()
    return {"created": created}


@app.get("/medias")
def api_medias(page: int = 1, per_page: int = 20, db: Session = Depends(get_db)):
    page = max(page, 1)
    per_page = min(max(per_page, 1), 50)
    medias = (
        db.query(Media)
        .order_by(func.random())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )
    items: List[MediaResponse] = []
    for media in medias:
        user = db.query(TargetUser).get(media.user_id)
        items.append(
            MediaResponse(
                id=media.id,
                media_id=media.media_id,
                media_type=media.media_type,
                caption=media.caption or "",
                like_count=media.like_count or 0,
                comment_count=media.comment_count or 0,
                view_count=media.view_count or 0,
                media_url=media.media_url,
                thumbnail_url=media.thumbnail_url,
                taken_at=media.taken_at.isoformat() if media.taken_at else None,
                user={
                    "id": user.id if user else None,
                    "username": user.username if user else None,
                    "full_name": user.full_name if user else None,
                    "profile_pic_url": user.profile_pic_url if user else None,
                },
            )
        )
    return {"medias": items, "page": page, "per_page": per_page}


@app.get("/", response_class=HTMLResponse)
def homepage(request: Request, db: Session = Depends(get_db), q: Optional[str] = Query(None)):
    base_url = str(request.base_url).rstrip("/")
    query = (
        db.query(Media, TargetUser)
        .join(TargetUser, TargetUser.id == Media.user_id)
    )
    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(
                TargetUser.username.ilike(like),
                TargetUser.full_name.ilike(like),
                Media.caption.ilike(like),
            )
        ).order_by(Media.collected_at.desc())
    else:
        query = query.order_by(func.random())

    rows = query.limit(30).all()
    items = []
    for media, user in rows:
        media_url = _public_media_url(media.thumbnail_url or media.media_url)
        if media.media_type in {"video", "reel", "igtv"} and not media.thumbnail_url:
            media_url = None
        media_url = media_url or PLACEHOLDER_IMAGE
        items.append(
            {
                "id": media.id,
                "username": user.username,
                "full_name": user.full_name or "",
                "caption": media.caption or "",
                "taken_at": media.taken_at.isoformat() if media.taken_at else "",
                "media_url": media_url,
                "likes": media.like_count or 0,
                "comments": media.comment_count or 0,
                "detail_url": f"/m/{media.id}",
            }
        )
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "medias": items,
            "query": q or "",
            "title": "首页 · Instagram Clone",
            "description": "随机浏览采集到的 Instagram 图片与用户信息",
            "keywords": "Instagram,采集,图片,用户主页,帖子,中文,展示",
            "robots": "noindex,follow" if q else "index,follow",
            "json_ld": json.dumps(
                {
                    "@context": "https://schema.org",
                    "@type": "WebSite",
                    "name": "Instagram 采集展示",
                    "url": base_url,
                    "inLanguage": "zh-CN",
                    "potentialAction": {
                        "@type": "SearchAction",
                        "target": f"{base_url}/?q={{search_term_string}}",
                        "query-input": "required name=search_term_string",
                    },
                },
                ensure_ascii=False,
            ),
        },
    )


@app.get("/guestbook", response_class=HTMLResponse)
def guestbook_page(
    request: Request,
    db: Session = Depends(get_db),
    status: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
):
    messages = (
        db.query(Message)
        .order_by(Message.created_at.desc())
        .limit(50)
        .all()
    )
    return templates.TemplateResponse(
        "guestbook.html",
        {
            "request": request,
            "messages": messages,
            "status": status,
            "error": error,
            "title": "留言板 · Instagram Clone",
            "description": "留言板：提交问题与建议，我们将通过邮件回复。",
            "keywords": "留言板,反馈,问题,建议,中文,联系",
        },
    )


@app.post("/guestbook")
def guestbook_submit(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    content: str = Form(...),
    db: Session = Depends(get_db),
):
    name = name.strip()
    email = email.strip()
    content = content.strip()
    if not name or not email or not content:
        return RedirectResponse(f"/guestbook?error={quote('请填写完整信息')}", status_code=303)
    if len(content) > 1000:
        return RedirectResponse(f"/guestbook?error={quote('留言内容过长')}", status_code=303)
    msg = Message(name=name, email=email, content=content)
    db.add(msg)
    db.commit()
    mail_error = _send_message_notification(request, name, email, content)
    if mail_error:
        return RedirectResponse(
            f"/guestbook?status={quote('已保存，但邮件发送失败')}",
            status_code=303,
        )
    return RedirectResponse(
        f"/guestbook?status={quote('留言已提交，我们会通过邮件回复')}",
        status_code=303,
    )


def _render_user_profile(
    username: str,
    request: Request,
    db: Session,
    page: int,
):
    base_url = str(request.base_url).rstrip("/")
    user = db.query(TargetUser).filter_by(username=username).first()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")

    profile_pic_url = _public_media_url(user.profile_pic_url) or (user.profile_pic_url or "")
    profile_pic_abs = _absolute_url(request, profile_pic_url)
    faq_items = [
        {
            "q": f"如何查看更多 @{user.username} 的贴文？",
            "a": "在页面下方继续滚动即可加载更多已采集内容。",
        },
        {
            "q": "头像和简介来自哪里？",
            "a": "来自采集到的公开资料，可能存在更新时间差异。",
        },
        {
            "q": "为什么有些图片无法显示？",
            "a": "可能是视频或图集缩略图生成中，或原内容已不可访问。",
        },
    ]
    per_page = 24
    query = (
        db.query(Media)
        .filter_by(user_id=user.id)
        .order_by(Media.taken_at.is_(None), Media.taken_at.desc(), Media.id.desc())
    )
    total = query.count()
    medias = query.offset((page - 1) * per_page).limit(per_page).all()
    items = []
    for media in medias:
        media_url = _public_media_url(media.thumbnail_url or media.media_url)
        if media.media_type in {"video", "reel", "igtv"} and not media.thumbnail_url:
            media_url = PLACEHOLDER_IMAGE
        items.append(
            {
                "id": media.id,
                "media_type": media.media_type or "",
                "caption": media.caption or "",
                "media_url": media_url,
                "taken_at": media.taken_at.isoformat() if media.taken_at else "",
                "detail_url": f"/m/{media.id}",
            }
        )
    has_more = page * per_page < total
    return templates.TemplateResponse(
        "user_profile.html",
        {
            "request": request,
            "user": {
                "id": user.id,
                "username": user.username,
                "full_name": user.full_name or "",
                "biography": user.biography or "",
                "follower_count": user.follower_count or 0,
                "following_count": user.following_count or 0,
                "posts_count": user.posts_count or 0,
                "profile_pic_url": profile_pic_url,
                "last_collected": user.last_collected,
            },
            "medias": items,
            "page": page,
            "has_more": has_more,
            "next_page": page + 1 if has_more else None,
            "title": f"@{user.username} · 用户主页",
            "description": user.biography or f"查看 @{user.username} 的最新采集图片与资料",
            "og_image": profile_pic_url if profile_pic_url else None,
            "keywords": f"Instagram,采集,用户主页,{user.username},图片,帖子,粉丝,中文",
            "json_ld": json.dumps(
                {
                    "@context": "https://schema.org",
                    "@graph": [
                        {
                            "@type": "ProfilePage",
                            "name": f"@{user.username} 用户主页",
                            "url": f"{base_url}/{user.username}",
                            "inLanguage": "zh-CN",
                            "mainEntity": {
                                "@type": "Person",
                                "name": user.full_name or user.username,
                                "alternateName": user.username,
                                "description": user.biography or "",
                                "image": profile_pic_abs,
                            },
                        },
                        {
                            "@type": "FAQPage",
                            "mainEntity": [
                                {
                                    "@type": "Question",
                                    "name": item["q"],
                                    "acceptedAnswer": {"@type": "Answer", "text": item["a"]},
                                }
                                for item in faq_items
                            ],
                        },
                    ],
                },
                ensure_ascii=False,
            ),
            "faq_items": faq_items,
        },
    )


@app.get("/u/{username}", response_class=HTMLResponse)
def user_profile_legacy(
    username: str,
    page: int = Query(1, ge=1),
):
    query = f"?page={page}" if page and page != 1 else ""
    return RedirectResponse(f"/{username}{query}", status_code=301)


@app.get("/api/users/{username}/medias")
def api_user_medias(
    username: str,
    page: int = Query(1, ge=1),
    per_page: int = Query(24, ge=1, le=50),
    db: Session = Depends(get_db),
):
    user = db.query(TargetUser).filter_by(username=username).first()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")

    query = (
        db.query(Media)
        .filter_by(user_id=user.id)
        .order_by(Media.taken_at.is_(None), Media.taken_at.desc(), Media.id.desc())
    )
    total = query.count()
    medias = query.offset((page - 1) * per_page).limit(per_page).all()
    items = []
    for media in medias:
        media_url = _public_media_url(media.thumbnail_url or media.media_url)
        if media.media_type in {"video", "reel", "igtv"} and not media.thumbnail_url:
            media_url = PLACEHOLDER_IMAGE
        items.append(
            {
                "id": media.id,
                "media_type": media.media_type or "",
                "caption": media.caption or "",
                "media_url": media_url,
                "taken_at": media.taken_at.isoformat() if media.taken_at else "",
                "detail_url": f"/m/{media.id}",
                "username": user.username,
            }
        )
    return {
        "items": items,
        "page": page,
        "per_page": per_page,
        "total": total,
        "has_more": page * per_page < total,
    }


@app.get("/m/{media_id}", response_class=HTMLResponse)
def media_detail(media_id: int, request: Request, db: Session = Depends(get_db)):
    base_url = str(request.base_url).rstrip("/")
    row = (
        db.query(Media, TargetUser)
        .join(TargetUser, TargetUser.id == Media.user_id)
        .filter(Media.id == media_id)
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="媒体不存在")
    media, user = row
    media_url = _public_media_url(media.media_url)
    thumbnail_url = _public_media_url(media.thumbnail_url)
    media_url_abs = _absolute_url(request, media_url)
    thumbnail_abs = _absolute_url(request, thumbnail_url)
    is_video = media.media_type in {"video", "reel", "igtv"}
    album_items = []
    if media.album_id:
        album_medias = (
            db.query(Media)
            .filter_by(album_id=media.album_id)
            .order_by(Media.id.asc())
            .all()
        )
    else:
        album_medias = [media]
    for item in album_medias:
        item_is_video = item.media_type in {"video", "reel", "igtv"}
        item_thumbnail = _public_media_url(item.thumbnail_url)
        if item_is_video:
            item_media_url = _public_media_url(item.media_url) or ""
        else:
            item_media_url = _public_media_url(item.media_url) or item_thumbnail or PLACEHOLDER_IMAGE
        album_items.append(
            {
                "id": item.id,
                "media_type": item.media_type,
                "media_url": item_media_url,
                "thumbnail_url": item_thumbnail,
                "is_video": item_is_video,
            }
        )
    profile_pic_url = _public_media_url(user.profile_pic_url) or (user.profile_pic_url or "")
    faq_items = [
        {
            "q": "如何查看该用户的更多内容？",
            "a": f"点击用户名进入 /{user.username}，即可查看该用户的全部采集贴文。",
        },
        {
            "q": "采集时间和发布时间有什么区别？",
            "a": "采集时间指内容入库时间，发布时间以原平台为准，可能存在时间差。",
        },
    ]
    if media.album_id and len(album_items) > 1:
        faq_items.insert(
            0,
            {
                "q": "图集如何切换图片？",
                "a": "图集贴文支持左右按钮翻页，逐张查看图片或视频。",
            },
        )
    return templates.TemplateResponse(
        "media_detail.html",
        {
            "request": request,
            "media": {
                "id": media.id,
                "media_type": media.media_type,
                "caption": media.caption or "",
                "like_count": media.like_count or 0,
                "comment_count": media.comment_count or 0,
                "view_count": media.view_count or 0,
                "media_url": media_url,
                "thumbnail_url": thumbnail_url,
                "taken_at": media.taken_at,
                "is_video": is_video,
                "is_album": media.album_id is not None and len(album_items) > 1,
                "album_items": album_items,
                "album_count": len(album_items),
            },
            "user": {
                "id": user.id,
                "username": user.username,
                "full_name": user.full_name or "",
                "biography": user.biography or "",
                "follower_count": user.follower_count or 0,
                "following_count": user.following_count or 0,
                "posts_count": user.posts_count or 0,
                "profile_pic_url": profile_pic_url,
                "last_collected": user.last_collected,
            },
            "title": f"@{user.username} · 贴文详情",
            "description": media.caption or f"查看 @{user.username} 的采集贴文详情",
            "keywords": f"Instagram,采集,贴文详情,{user.username},图片,视频,中文",
            "og_type": "article",
            "og_image": thumbnail_url or media_url,
            "json_ld": json.dumps(
                {
                    "@context": "https://schema.org",
                    "@graph": [
                        {
                            "@type": "SocialMediaPosting",
                            "headline": media.caption or f"@{user.username} 的贴文",
                            "author": {"@type": "Person", "name": user.username},
                            "datePublished": media.taken_at.isoformat() if media.taken_at else None,
                            "image": thumbnail_abs or media_url_abs,
                            "url": f"{base_url}/m/{media.id}",
                            "inLanguage": "zh-CN",
                        },
                        {
                            "@type": "FAQPage",
                            "mainEntity": [
                                {
                                    "@type": "Question",
                                    "name": item["q"],
                                    "acceptedAnswer": {"@type": "Answer", "text": item["a"]},
                                }
                                for item in faq_items
                            ],
                        },
                    ],
                },
                ensure_ascii=False,
            ),
            "faq_items": faq_items,
        },
    )


@app.post("/seed_dummy")
def seed_dummy(count: int = 16, user=Depends(verify_admin), db: Session = Depends(get_db)):
    """
    生成占位用户与图片，便于前端预览。
    """
    count = min(max(count, 1), 60)
    demo_user = db.query(TargetUser).filter_by(username="demo_user").first()
    if not demo_user:
        demo_user = TargetUser(username="demo_user", full_name="Demo User", is_active=True)
        db.add(demo_user)
        db.commit()
        db.refresh(demo_user)

    user_folder = Path(Config.MEDIA_FOLDER) / "demo_user"
    user_folder.mkdir(parents=True, exist_ok=True)

    try:
        from PIL import Image, ImageDraw
    except ImportError:
        raise HTTPException(status_code=500, detail="缺少 Pillow 依赖")

    created = 0
    for _ in range(count):
        media_id = str(uuid4())
        img_path = user_folder / f"{media_id}.jpg"

        img = Image.new("RGB", (640, 640), color=tuple(random.randint(80, 200) for _ in range(3)))
        draw = ImageDraw.Draw(img)
        draw.text((20, 20), "Demo", fill=(255, 255, 255))
        img.save(img_path, "JPEG")

        media = Media(
            media_id=media_id,
            user_id=demo_user.id,
            media_type="photo",
            caption=f"Demo caption {media_id[:6]}",
            like_count=random.randint(0, 500),
            comment_count=random.randint(0, 120),
            view_count=random.randint(0, 2000),
            media_url=str(img_path),
            thumbnail_url=str(img_path),
            taken_at=datetime.utcnow() - timedelta(minutes=random.randint(0, 1440)),
        )
        db.add(media)
        created += 1

    db.commit()
    return {"status": "ok", "created": created}


@app.get("/admin", response_class=HTMLResponse)
def admin_page(
    request: Request,
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    range_days: int = Query(30, alias="range"),
    user_filter: Optional[str] = Query(None, alias="user"),
    error: Optional[str] = Query(None),
):
    if not _is_admin_logged_in(request):
        redirect_to = quote(str(request.url.path))
        return RedirectResponse(f"/login?next={redirect_to}", status_code=303)
    raw_accounts = db.query(InstagramAccount).all()
    accounts = []
    for account in raw_accounts:
        status_label = "✅ 可用" if account.is_active else "❌ 不可用"
        status_detail = None
        if not account.is_active:
            last_log = (
                db.query(CollectionLog)
                .filter(CollectionLog.account_id == account.id)
                .order_by(CollectionLog.created_at.desc())
                .first()
            )
            if last_log and "需要验证" in last_log.message:
                status_label = "⚠️ 需要验证"
            elif last_log and "登录失败" in last_log.message:
                status_label = "❌ 登录失败"
            else:
                status_label = "❌ 不可用"
            status_detail = last_log.message if last_log else "账号不可用"
        accounts.append(
            {
                "id": account.id,
                "username": account.username,
                "proxy": account.proxy,
                "status": status_label,
                "status_detail": status_detail,
            }
        )
    messages = (
        db.query(Message)
        .order_by(Message.created_at.desc())
        .limit(20)
        .all()
    )
    users = db.query(TargetUser).all()
    if range_days not in {7, 30, 90}:
        range_days = 30
    per_page = 20
    total = db.query(Media).count()
    total_pages = max(1, math.ceil(total / per_page)) if total else 1
    page = min(page, total_pages)
    media_rows = (
        db.query(Media, TargetUser)
        .join(TargetUser, TargetUser.id == Media.user_id)
        .order_by(Media.collected_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )
    medias = []
    for media, user in media_rows:
        medias.append(
            {
                "id": media.id,
                "username": user.username,
                "full_name": user.full_name or "",
                "caption": media.caption or "",
                "taken_at": media.taken_at.isoformat() if media.taken_at else "",
                "likes": media.like_count or 0,
                "comments": media.comment_count or 0,
                "media_type": media.media_type or "",
                "detail_url": f"/m/{media.id}",
            }
        )
    jobs = [
        {
            "id": job.id,
            "name": job.name,
            "next_run_time": job.next_run_time,
            "trigger": str(job.trigger),
        }
        for job in scheduler.scheduler.get_jobs()
    ]
    since_date = datetime.utcnow().date() - timedelta(days=range_days - 1)
    stats_query = (
        db.query(func.date(Media.collected_at).label("day"), func.count(Media.id))
        .filter(Media.collected_at.isnot(None))
        .filter(Media.collected_at >= since_date)
    )
    filtered_user = None
    if user_filter:
        filtered_user = db.query(TargetUser).filter_by(username=user_filter).first()
        if filtered_user:
            stats_query = stats_query.filter(Media.user_id == filtered_user.id)
        else:
            user_filter = None
    stats_rows = (
        stats_query.group_by("day")
        .order_by("day")
        .all()
    )
    stats_map = {str(day): count for day, count in stats_rows}
    stats = []
    max_count = 0
    for offset in range(range_days):
        day = since_date + timedelta(days=offset)
        day_str = day.isoformat()
        count = stats_map.get(day_str, 0)
        max_count = max(max_count, count)
        stats.append({"day": day_str, "count": count})
    chart_points = []
    chart_polyline = ""
    chart_area = ""
    if stats:
        denom = len(stats) - 1 or 1
        for idx, item in enumerate(stats):
            x = round(idx / denom * 100, 2)
            y = 60
            if max_count:
                y = round(60 - (item["count"] / max_count * 60), 2)
            chart_points.append(
                {
                    "x": x,
                    "y": y,
                    "count": item["count"],
                    "day": item["day"],
                }
            )
        chart_polyline = " ".join(f"{p['x']},{p['y']}" for p in chart_points)
        if chart_polyline:
            chart_area = f"{chart_polyline} 100,60 0,60"
    filter_params = {"range": range_days}
    if user_filter:
        filter_params["user"] = user_filter
    query_suffix = f"&{urlencode(filter_params)}" if filter_params else ""
    return templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "accounts": accounts,
            "users": users,
            "jobs": jobs,
            "medias": medias,
            "interval": Config.COLLECTION_INTERVAL_MINUTES,
            "page": page,
            "total_pages": total_pages,
            "has_prev": page > 1,
            "has_next": page < total_pages,
            "error": error,
            "title": "管理面板",
            "robots": "noindex,nofollow",
            "stats": stats,
            "stats_max": max_count,
            "chart_points": chart_points,
            "chart_polyline": chart_polyline,
            "chart_area": chart_area,
            "range_days": range_days,
            "user_filter": user_filter,
            "query_suffix": query_suffix,
            "filtered_user": filtered_user,
            "messages": messages,
        },
    )


@app.post("/admin/add_account")
def admin_add_account(
    username: str = Form(...),
    password: str = Form(...),
    proxy: Optional[str] = Form(None),
    totp_secret: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    user=Depends(verify_admin),
):
    if db.query(InstagramAccount).filter_by(username=username).first():
        return RedirectResponse(f"/admin?error={quote('账号已存在')}", status_code=303)
    proxy = proxy.strip() if proxy else None
    totp_secret = totp_secret.strip() if totp_secret else None
    try:
        session_data = client_manager.login_and_get_settings(
            username, password, proxy=proxy, totp_secret=totp_secret
        )
    except ChallengeRequired:
        return RedirectResponse(f"/admin?error={quote('账号需要挑战验证，请先完成验证')}", status_code=303)
    except Exception as exc:
        msg = f"登录失败: {exc}"
        return RedirectResponse(f"/admin?error={quote(msg)}", status_code=303)
    account = InstagramAccount(
        username=username,
        password=cipher.encrypt(password),
        proxy=proxy,
        totp_secret=cipher.encrypt(totp_secret) if totp_secret else None,
        session_data=session_data,
        is_active=True,
    )
    db.add(account)
    db.commit()
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/remove_account")
def admin_remove_account(
    account_id: int = Form(...),
    db: Session = Depends(get_db),
    user=Depends(verify_admin),
):
    acc = db.query(InstagramAccount).get(account_id)
    if acc:
        db.delete(acc)
        db.commit()
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/add_user")
def admin_add_user(
    username: str = Form(...),
    immediate_collect: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    user=Depends(verify_admin),
):
    if db.query(TargetUser).filter_by(username=username).first():
        return RedirectResponse("/admin", status_code=303)
    tgt = TargetUser(username=username, is_active=True)
    db.add(tgt)
    db.commit()
    if immediate_collect:
        client_manager.collect_user_data(db, username)
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/remove_user")
def admin_remove_user(
    user_id: int = Form(...),
    db: Session = Depends(get_db),
    user=Depends(verify_admin),
):
    tgt = db.query(TargetUser).get(user_id)
    if tgt:
        db.delete(tgt)
        db.commit()
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/set_interval")
def admin_set_interval(
    minutes: int = Form(...),
    db: Session = Depends(get_db),
    user=Depends(verify_admin),
):
    scheduler.set_collection_interval(minutes)
    return RedirectResponse("/admin", status_code=303)


@app.get("/{username}", response_class=HTMLResponse)
def user_profile_short(
    username: str,
    request: Request,
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
):
    return _render_user_profile(username, request, db, page)
