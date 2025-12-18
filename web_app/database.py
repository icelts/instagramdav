from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from config import Config

# 基础数据库配置与会话管理
DATABASE_URL = Config.SQLALCHEMY_DATABASE_URI

engine = create_engine(
    DATABASE_URL,
    future=True,
    pool_pre_ping=True,
    pool_recycle=3600,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

Base = declarative_base()


@contextmanager
def session_scope():
    """提供一个自动提交/回滚的会话上下文"""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
