import json
import logging
import os
import random
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional
from uuid import uuid4

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session
from urllib.parse import quote

from config import Config
from database import Base, SessionLocal, engine
from instagram_client import build_client_manager
from models import CollectionLog, CollectionTask, InstagramAccount, Media, TargetUser
from scheduler import CollectionScheduler
from security import CredentialCipher

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="Instagram Clone API", version="0.1.0")
security = HTTPBasic(auto_error=False)
app.add_middleware(
    SessionMiddleware,
    secret_key=Config.SECRET_KEY,
    session_cookie="admin_session",
    same_site="lax",
)

Base.metadata.create_all(bind=engine)
os.makedirs(Config.MEDIA_FOLDER, exist_ok=True)
os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
os.makedirs("static", exist_ok=True)
os.makedirs("templates", exist_ok=True)

cipher = CredentialCipher(Config.SECRET_KEY)
client_manager = build_client_manager(Config.SECRET_KEY)
scheduler = CollectionScheduler(SessionLocal)
scheduler_started = False
templates = Jinja2Templates(directory="templates")

app.mount("/static", StaticFiles(directory="static"), name="static")
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
    try:
        rel = Path(path).relative_to(Path(Config.MEDIA_FOLDER))
        return f"/media/{rel.as_posix()}"
    except Exception:
        return None


def _safe_next_path(raw: str) -> str:
    if not raw or not raw.startswith("/"):
        return "/admin"
    return raw


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
    account = InstagramAccount(
        username=payload.username,
        password=cipher.encrypt(payload.password),
        proxy=payload.proxy,
        totp_secret=cipher.encrypt(payload.totp_secret) if payload.totp_secret else None,
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
def homepage(request: Request, db: Session = Depends(get_db)):
    medias = db.query(Media).order_by(func.random()).limit(30).all()
    placeholder = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw=="
    items = []
    for media in medias:
        user = db.query(TargetUser).get(media.user_id)
        media_url = _public_media_url(media.thumbnail_url or media.media_url) or placeholder
        items.append(
            {
                "username": user.username if user else "unknown",
                "full_name": user.full_name if user else "",
                "caption": media.caption or "",
                "taken_at": media.taken_at.isoformat() if media.taken_at else "",
                "media_url": media_url,
                "likes": media.like_count or 0,
                "comments": media.comment_count or 0,
            }
        )
    return templates.TemplateResponse("index.html", {"request": request, "medias": items})


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
def admin_page(request: Request, db: Session = Depends(get_db)):
    if not _is_admin_logged_in(request):
        redirect_to = quote(str(request.url.path))
        return RedirectResponse(f"/login?next={redirect_to}", status_code=303)
    accounts = db.query(InstagramAccount).all()
    users = db.query(TargetUser).all()
    jobs = [
        {
            "id": job.id,
            "name": job.name,
            "next_run_time": job.next_run_time,
            "trigger": str(job.trigger),
        }
        for job in scheduler.scheduler.get_jobs()
    ]
    return templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "accounts": accounts,
        "users": users,
        "jobs": jobs,
        "interval": Config.COLLECTION_INTERVAL_MINUTES,
        "title": "管理面板",
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
        return RedirectResponse("/admin", status_code=303)
    account = InstagramAccount(
        username=username,
        password=cipher.encrypt(password),
        proxy=proxy,
        totp_secret=cipher.encrypt(totp_secret) if totp_secret else None,
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
