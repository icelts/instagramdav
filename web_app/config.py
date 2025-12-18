import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or (
        'mysql+pymysql://douyinstagram:GatHER5CGmjCxeeA@125.212.244.39:3306/douyinstagram?charset=utf8mb4'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME') or 'admin'
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD') or 'admin'
    
    # Redis配置
    REDIS_URL = os.environ.get('REDIS_URL') or 'redis://localhost:6379/0'
    
    # Instagram账号配置
    INSTAGRAM_ACCOUNTS = os.environ.get('INSTAGRAM_ACCOUNTS', '[]')
    
    # 采集配置
    COLLECTION_INTERVAL_MINUTES = int(os.environ.get('COLLECTION_INTERVAL_MINUTES', 30))
    MAX_POSTS_PER_USER = int(os.environ.get('MAX_POSTS_PER_USER', 50))
    DELAY_BETWEEN_REQUESTS = int(os.environ.get('DELAY_BETWEEN_REQUESTS', 5))
    
    # 媒体文件存储路径
    MEDIA_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'media')
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
