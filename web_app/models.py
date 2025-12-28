from datetime import datetime
from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    Text,
    Boolean,
    ForeignKey,
)
from sqlalchemy.orm import relationship

from database import Base

class InstagramAccount(Base):
    __tablename__ = 'instagram_accounts'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(100), unique=True, nullable=False)
    password = Column(String(200), nullable=False)
    proxy = Column(String(200))
    totp_secret = Column(Text)  # 可选的TOTP密钥（加密后存储）
    is_active = Column(Boolean, default=True)
    last_used = Column(DateTime)
    session_data = Column(Text)  # 存储session信息
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # 关联的采集任务
    collection_tasks = relationship("CollectionTask", back_populates="account", cascade="all, delete-orphan")

class TargetUser(Base):
    __tablename__ = 'target_users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(100), unique=True, nullable=False)
    user_id = Column(String(50))  # Instagram用户ID
    full_name = Column(String(200))
    biography = Column(Text)
    follower_count = Column(Integer, default=0)
    following_count = Column(Integer, default=0)
    posts_count = Column(Integer, default=0)
    profile_pic_url = Column(String(500))
    is_active = Column(Boolean, default=True)
    last_collected = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # 关联的媒体内容
    medias = relationship("Media", back_populates="user", cascade="all, delete-orphan")
    # 关联的采集任务
    collection_tasks = relationship("CollectionTask", back_populates="target_user", cascade="all, delete-orphan")

class Media(Base):
    __tablename__ = 'medias'
    
    id = Column(Integer, primary_key=True)
    media_id = Column(String(50), unique=True, nullable=False)
    user_id = Column(Integer, ForeignKey('target_users.id'), nullable=False)
    media_type = Column(String(20))  # photo, video, album, reel
    caption = Column(Text)
    like_count = Column(Integer, default=0)
    comment_count = Column(Integer, default=0)
    view_count = Column(Integer, default=0)
    media_url = Column(String(500))  # 本地存储路径
    thumbnail_url = Column(String(500))  # 缩略图路径
    album_id = Column(String(50))  # 图集分组ID
    taken_at = Column(DateTime)
    collected_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # 关联的用户
    user = relationship("TargetUser", back_populates="medias")

class CollectionTask(Base):
    __tablename__ = 'collection_tasks'
    
    id = Column(Integer, primary_key=True)
    account_id = Column(Integer, ForeignKey('instagram_accounts.id'), nullable=False)
    target_user_id = Column(Integer, ForeignKey('target_users.id'), nullable=False)
    status = Column(String(20), default='pending')  # pending, running, completed, failed
    task_type = Column(String(20), default='collect')  # collect, update
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    error_message = Column(Text)
    media_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # 关联的账号和目标用户
    account = relationship("InstagramAccount", back_populates="collection_tasks")
    target_user = relationship("TargetUser", back_populates="collection_tasks")

class CollectionLog(Base):
    __tablename__ = 'collection_logs'
    
    id = Column(Integer, primary_key=True)
    account_id = Column(Integer, ForeignKey('instagram_accounts.id'))
    target_user_id = Column(Integer, ForeignKey('target_users.id'))
    action = Column(String(50))  # login, collect_media, collect_user_info, error
    message = Column(Text)
    status = Column(String(20))  # success, error, warning
    created_at = Column(DateTime, default=datetime.utcnow)


class Message(Base):
    __tablename__ = 'messages'

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    email = Column(String(200), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
