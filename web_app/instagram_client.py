import json
import logging
import os
import random
import time
from datetime import datetime, timedelta
from typing import Optional

import pyotp
from instagrapi import Client
from instagrapi.exceptions import ChallengeRequired, PrivateError

from config import Config
from models import CollectionLog, CollectionTask, InstagramAccount, Media, TargetUser
from security import CredentialCipher

logger = logging.getLogger(__name__)


class InstagramClientManager:
    """
    管理 instagrapi 客户端的生命周期、账号轮换以及数据采集。
    注意：调用方需要传入 SQLAlchemy session，确保事务由上层控制。
    """

    def __init__(self, cipher: CredentialCipher):
        self.clients = {}  # account_id -> Client instance
        self.last_used = {}  # account_id -> datetime
        self.cipher = cipher

    def get_client(self, account: InstagramAccount, session) -> Client:
        if account.id not in self.clients:
            client = Client()

            if account.proxy:
                client.set_proxy(account.proxy)
                logger.info("账号 %s 设置代理: %s", account.username, account.proxy)

            if account.session_data:
                try:
                    client.set_settings(json.loads(account.session_data))
                    self._login_account(client, account, session, relogin=True)
                    logger.info("账号 %s 使用 session 重新登录成功", account.username)
                except Exception as exc:
                    logger.warning("账号 %s session 登录失败，将尝试普通登录: %s", account.username, exc)
                    self._login_account(client, account, session)
            else:
                self._login_account(client, account, session)

            self.clients[account.id] = client
            self.last_used[account.id] = datetime.utcnow()

        return self.clients[account.id]

    def _login_account(self, client: Client, account: InstagramAccount, session, relogin: bool = False):
        try:
            password = self.cipher.decrypt(account.password)
            totp_code = None
            if account.totp_secret:
                try:
                    totp_secret = self.cipher.decrypt(account.totp_secret)
                    totp_code = pyotp.TOTP(totp_secret).now()
                except Exception as exc:
                    logger.warning("账号 %s TOTP 生成失败: %s", account.username, exc)

            if totp_code:
                client.login(account.username, password, relogin=relogin, verification_code=totp_code)
            else:
                client.login(account.username, password, relogin=relogin)
            account.session_data = json.dumps(client.get_settings())
            account.last_used = datetime.utcnow()
            session.commit()
            logger.info("账号 %s 登录成功", account.username)
            self._log_action(session, account.id, None, "login", f"账号 {account.username} 登录成功", "success")
        except ChallengeRequired as exc:
            logger.error("账号 %s 需要挑战验证: %s", account.username, exc)
            account.is_active = False
            session.commit()
            self._log_action(session, account.id, None, "login", f"账号 {account.username} 需要验证", "error")
            raise
        except Exception as exc:
            logger.error("账号 %s 登录失败: %s", account.username, exc)
            account.is_active = False
            session.commit()
            self._log_action(session, account.id, None, "login", f"账号 {account.username} 登录失败: {exc}", "error")
            raise

    def login_and_get_settings(
        self,
        username: str,
        password: str,
        proxy: Optional[str] = None,
        totp_secret: Optional[str] = None,
    ) -> str:
        client = Client()
        if proxy:
            client.set_proxy(proxy)
        totp_code = None
        if totp_secret:
            totp_code = pyotp.TOTP(totp_secret).now()
        if totp_code:
            client.login(username, password, verification_code=totp_code)
        else:
            client.login(username, password)
        return json.dumps(client.get_settings())

    def _log_action(self, session, account_id: int, target_user_id: Optional[int], action: str, message: str, status: str):
        log = CollectionLog(
            account_id=account_id,
            target_user_id=target_user_id,
            action=action,
            message=message,
            status=status,
        )
        session.add(log)
        session.commit()

    def get_available_account(self, session) -> Optional[InstagramAccount]:
        accounts = session.query(InstagramAccount).filter_by(is_active=True).all()
        if not accounts:
            logger.error("没有可用的 Instagram 账号")
            return None

        available_accounts = []
        for account in accounts:
            last_used = self.last_used.get(account.id)
            if not last_used or datetime.utcnow() - last_used > timedelta(minutes=5):
                available_accounts.append(account)

        if not available_accounts:
            return min(accounts, key=lambda x: self.last_used.get(x.id, datetime.min))

        return random.choice(available_accounts)

    def collect_user_data(self, session, target_username: str, account: Optional[InstagramAccount] = None) -> bool:
        if not account:
            account = self.get_available_account(session)
            if not account:
                return False

        try:
            client = self.get_client(account, session)
            user_info = client.user_info_by_username(target_username)

            target_user = session.query(TargetUser).filter_by(username=target_username).first()
            if not target_user:
                target_user = TargetUser(username=target_username)
                session.add(target_user)

            target_user.user_id = str(user_info.pk)
            target_user.full_name = user_info.full_name
            target_user.biography = user_info.biography
            target_user.follower_count = user_info.follower_count
            target_user.following_count = user_info.following_count
            target_user.posts_count = user_info.media_count
            profile_pic_url = str(user_info.profile_pic_url) if user_info.profile_pic_url else None
            local_profile = self._download_profile_pic(client, profile_pic_url, target_user.username)
            target_user.profile_pic_url = local_profile or profile_pic_url
            target_user.last_collected = datetime.utcnow()
            session.commit()

            task = CollectionTask(
                account_id=account.id,
                target_user_id=target_user.id,
                status="running",
                task_type="collect",
                started_at=datetime.utcnow(),
            )
            session.add(task)
            session.commit()

            logger.info("开始采集用户 %s 的数据", target_username)
            self._log_action(session, account.id, target_user.id, "collect_user_info", f"开始采集用户 {target_username}", "success")

            media_count = self._collect_medias(session, client, target_user, account)

            task.status = "completed"
            task.completed_at = datetime.utcnow()
            task.media_count = media_count
            session.commit()

            logger.info("完成采集用户 %s 的数据，共采集 %s 个媒体", target_username, media_count)
            self._log_action(session, account.id, target_user.id, "collect_media", f"完成采集，共 {media_count} 个媒体", "success")
            return True

        except Exception as exc:
            logger.error("采集用户 %s 数据失败: %s", target_username, exc)
            if "task" in locals():
                task.status = "failed"
                task.error_message = str(exc)
                task.completed_at = datetime.utcnow()
                session.commit()
            self._log_action(
                session,
                account.id,
                target_user.id if "target_user" in locals() else None,
                "error",
                f"采集失败: {exc}",
                "error",
            )
            return False

    def _collect_medias(self, session, client: Client, target_user: TargetUser, account: InstagramAccount) -> int:
        media_count = 0
        commit_every = 5
        try:
            medias = client.user_medias(target_user.user_id, amount=Config.MAX_POSTS_PER_USER)
            for media in medias:
                resources = media.resources if media.media_type == 8 and media.resources else []
                if resources:
                    for idx, resource in enumerate(resources):
                        resource_id = getattr(resource, "pk", None) or f"{media.pk}_{idx}"
                        existing_media = session.query(Media).filter_by(media_id=str(resource_id)).first()
                        if existing_media:
                            continue

                        media_record = Media(
                            media_id=str(resource_id),
                            user_id=target_user.id,
                            media_type=self._get_media_type(resource.media_type),
                            caption=media.caption_text or "",
                            like_count=media.like_count,
                            comment_count=media.comment_count,
                            view_count=getattr(media, "view_count", 0),
                            taken_at=media.taken_at,
                            album_id=str(media.pk),
                        )

                        thumbnail_url = getattr(resource, "thumbnail_url", None)
                        try:
                            media_path = self._download_media(client, resource, target_user.username)
                            if media_path:
                                media_record.media_url = media_path
                            if resource.media_type == 2:
                                if thumbnail_url:
                                    thumbnail_path = self._download_thumbnail(
                                        client, thumbnail_url, target_user.username, str(resource_id)
                                    )
                                    if thumbnail_path:
                                        media_record.thumbnail_url = thumbnail_path
                                if not media_record.thumbnail_url and media_path:
                                    thumbnail_path = self._generate_thumbnail(media_path)
                                    if thumbnail_path:
                                        media_record.thumbnail_url = thumbnail_path
                        except Exception as exc:
                            logger.warning("下载媒体 %s 失败: %s", resource_id, exc)

                        if not media_record.thumbnail_url and thumbnail_url:
                            media_record.thumbnail_url = str(thumbnail_url)
                        if not media_record.media_url:
                            if getattr(resource, "video_url", None):
                                media_record.media_url = str(resource.video_url)
                            elif getattr(resource, "thumbnail_url", None):
                                media_record.media_url = str(resource.thumbnail_url)

                        session.add(media_record)
                        media_count += 1
                        if media_count % commit_every == 0:
                            session.commit()
                        time.sleep(Config.DELAY_BETWEEN_REQUESTS)
                    continue

                existing_media = session.query(Media).filter_by(media_id=str(media.pk)).first()
                if existing_media:
                    continue

                media_record = Media(
                    media_id=str(media.pk),
                    user_id=target_user.id,
                    media_type=self._get_media_type(media.media_type, media.product_type),
                    caption=media.caption_text or "",
                    like_count=media.like_count,
                    comment_count=media.comment_count,
                    view_count=getattr(media, "view_count", 0),
                    taken_at=media.taken_at,
                )

                thumbnail_url = getattr(media, "thumbnail_url", None)
                try:
                    media_path = self._download_media(client, media, target_user.username)
                    if media_path:
                        media_record.media_url = media_path
                    if media.media_type == 2:
                        if thumbnail_url:
                            thumbnail_path = self._download_thumbnail(
                                client, thumbnail_url, target_user.username, str(media.pk)
                            )
                            if thumbnail_path:
                                media_record.thumbnail_url = thumbnail_path
                        if not media_record.thumbnail_url and media_path:
                            thumbnail_path = self._generate_thumbnail(media_path)
                            if thumbnail_path:
                                media_record.thumbnail_url = thumbnail_path
                except Exception as exc:
                    logger.warning("下载媒体 %s 失败: %s", media.pk, exc)

                if not media_record.thumbnail_url and thumbnail_url:
                    media_record.thumbnail_url = str(thumbnail_url)
                if not media_record.media_url:
                    if getattr(media, "video_url", None):
                        media_record.media_url = str(media.video_url)
                    elif getattr(media, "thumbnail_url", None):
                        media_record.media_url = str(media.thumbnail_url)

                session.add(media_record)
                media_count += 1
                if media_count % commit_every == 0:
                    session.commit()
                time.sleep(Config.DELAY_BETWEEN_REQUESTS)

            session.commit()
        except PrivateError:
            logger.warning("用户 %s 的账号是私密的", target_user.username)
        except Exception as exc:
            logger.error("采集媒体内容失败: %s", exc)
            raise

        return media_count

    def _get_media_type(self, media_type: int, product_type: str = None) -> str:
        if media_type == 1:
            return "photo"
        if media_type == 2:
            if product_type == "feed":
                return "video"
            if product_type == "igtv":
                return "igtv"
            if product_type == "clips":
                return "reel"
            return "video"
        if media_type == 8:
            return "album"
        return "unknown"

    def _download_profile_pic(self, client: Client, url: Optional[str], username: str) -> Optional[str]:
        if not url:
            return None
        user_folder = os.path.join(Config.MEDIA_FOLDER, username)
        os.makedirs(user_folder, exist_ok=True)
        filename = f"{username}_profile"
        try:
            path = client.photo_download_by_url(url, filename, user_folder)
            return str(path)
        except Exception as exc:
            logger.warning("下载头像失败: %s", exc)
            return None

    def _download_media(self, client: Client, media, username: str) -> Optional[str]:
        user_folder = os.path.join(Config.MEDIA_FOLDER, username)
        os.makedirs(user_folder, exist_ok=True)
        filename = f"{username}_{getattr(media, 'pk', 'media')}"

        if media.media_type == 1:
            url = getattr(media, "thumbnail_url", None)
            if url:
                path = client.photo_download_by_url(url, filename, user_folder)
            else:
                path = client.photo_download(media.pk, folder=user_folder)
        elif media.media_type == 2:
            url = getattr(media, "video_url", None)
            if url:
                path = client.video_download_by_url(url, filename, user_folder)
            else:
                path = client.video_download(media.pk, folder=user_folder)
        else:
            return None

        return str(path) if path else None

    def _download_thumbnail(self, client: Client, url: Optional[str], username: str, media_id: str) -> Optional[str]:
        if not url:
            return None
        thumbnail_folder = os.path.join(Config.MEDIA_FOLDER, "thumbnails")
        os.makedirs(thumbnail_folder, exist_ok=True)
        filename = f"thumb_{username}_{media_id}"
        try:
            path = client.photo_download_by_url(url, filename, thumbnail_folder)
            return str(path) if path else None
        except Exception as exc:
            logger.warning("下载缩略图失败: %s", exc)
            return None

    def _generate_thumbnail(self, video_path: str) -> Optional[str]:
        try:
            import cv2

            thumbnail_folder = os.path.join(Config.MEDIA_FOLDER, "thumbnails")
            os.makedirs(thumbnail_folder, exist_ok=True)

            cap = cv2.VideoCapture(video_path)
            ret, frame = cap.read()
            if ret:
                filename = f"thumb_{os.path.basename(video_path)}.jpg"
                thumbnail_path = os.path.join(thumbnail_folder, filename)
                cv2.imwrite(thumbnail_path, frame)
                cap.release()
                return thumbnail_path
            cap.release()
        except ImportError:
            logger.warning("未安装 opencv-python，无法生成缩略图")
        except Exception as exc:
            logger.error("生成缩略图失败: %s", exc)
        return None


def build_client_manager(secret_key: str) -> InstagramClientManager:
    cipher = CredentialCipher(secret_key)
    return InstagramClientManager(cipher)
