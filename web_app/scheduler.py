import logging
from datetime import datetime, timedelta
from typing import Callable

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from config import Config
from models import CollectionTask, TargetUser

logger = logging.getLogger(__name__)


class CollectionScheduler:
    def __init__(self, session_factory: Callable):
        self.scheduler = AsyncIOScheduler()
        self.is_running = False
        self.session_factory = session_factory

    def start(self):
        if not self.is_running:
            self.scheduler.start()
            self.is_running = True
            logger.info("调度器已启动")
            self.add_collection_jobs()
            self.add_maintenance_jobs()

    def stop(self):
        if self.is_running:
            self.scheduler.shutdown(wait=False)
            self.is_running = False
            logger.info("调度器已停止")

    def add_collection_jobs(self):
        self.scheduler.add_job(
            func=self.collect_all_users,
            trigger=IntervalTrigger(minutes=Config.COLLECTION_INTERVAL_MINUTES),
            id="collect_all_users",
            name="采集所有活跃用户数据",
            replace_existing=True,
        )
        self.scheduler.add_job(
            func=self.update_all_user_info,
            trigger=CronTrigger(hour=2, minute=0),
            id="update_user_info",
            name="更新用户基本信息",
            replace_existing=True,
        )

    def set_collection_interval(self, minutes: int):
        """调整采集间隔并立即重置定时任务"""
        minutes = max(1, minutes)
        Config.COLLECTION_INTERVAL_MINUTES = minutes
        try:
            self.scheduler.reschedule_job("collect_all_users", trigger=IntervalTrigger(minutes=minutes))
            logger.info("已更新采集间隔为 %s 分钟", minutes)
        except Exception as exc:
            logger.warning("更新采集间隔失败，将尝试重新添加任务: %s", exc)
            self.scheduler.add_job(
                func=self.collect_all_users,
                trigger=IntervalTrigger(minutes=minutes),
                id="collect_all_users",
                name="采集所有活跃用户数据",
                replace_existing=True,
            )

    def add_maintenance_jobs(self):
        self.scheduler.add_job(
            func=self.cleanup_old_tasks,
            trigger=IntervalTrigger(hours=1),
            id="cleanup_tasks",
            name="清理过期任务",
            replace_existing=True,
        )

    def collect_all_users(self):
        with self.session_factory() as session:
            try:
                active_users = session.query(TargetUser).filter_by(is_active=True).all()
                logger.info("开始采集 %s 个用户的数据", len(active_users))
                success_count = 0
                from instagram_client import build_client_manager

                manager = build_client_manager(Config.SECRET_KEY)
                for user in active_users:
                    try:
                        success = manager.collect_user_data(session, user.username)
                        if success:
                            success_count += 1
                    except Exception as exc:
                        logger.error("采集用户 %s 失败: %s", user.username, exc)
                logger.info("批量采集完成，成功 %s/%s", success_count, len(active_users))
            except Exception as exc:
                logger.error("批量采集失败: %s", exc)

    def update_all_user_info(self):
        with self.session_factory() as session:
            try:
                users = session.query(TargetUser).all()
                logger.info("开始更新 %s 个用户的基本信息", len(users))
                success_count = 0
                from instagram_client import build_client_manager

                manager = build_client_manager(Config.SECRET_KEY)
                for user in users:
                    try:
                        account = manager.get_available_account(session)
                        if not account:
                            break
                        client = manager.get_client(account, session)
                        user_info = client.user_info_by_username(user.username)
                        user.full_name = user_info.full_name
                        user.biography = user_info.biography
                        user.follower_count = user_info.follower_count
                        user.following_count = user_info.following_count
                        user.posts_count = user_info.media_count
                        user.profile_pic_url = user_info.profile_pic_url
                        session.commit()
                        success_count += 1
                    except Exception as exc:
                        logger.error("更新用户 %s 失败: %s", user.username, exc)
                logger.info("用户信息更新完成，成功 %s/%s", success_count, len(users))
            except Exception as exc:
                logger.error("批量更新用户信息失败: %s", exc)

    def cleanup_old_tasks(self):
        with self.session_factory() as session:
            try:
                cutoff = datetime.utcnow() - timedelta(days=7)
                old_tasks = (
                    session.query(CollectionTask)
                    .filter(CollectionTask.status.in_(["completed", "failed"]), CollectionTask.completed_at < cutoff)
                    .all()
                )
                for task in old_tasks:
                    session.delete(task)
                session.commit()
                logger.info("清理了 %s 条过期任务", len(old_tasks))
            except Exception as exc:
                logger.error("清理过期任务失败: %s", exc)
