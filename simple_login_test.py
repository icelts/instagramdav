#!/usr/bin/env python3
"""
简化的 Instagram 登录测试脚本
"""

import logging
from instagrapi import Client
from instagrapi.exceptions import TwoFactorRequired, ChallengeRequired, BadCredentials

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_login():
    """测试登录功能"""
    # 测试凭据
    username = "ruth87283"
    password = "r?Vcc7#NH1"
    totp_secret = "SGPOGESJNAA6TV4PEQGVJCAN6KTPJ24R"
    
    client = Client()
    
    try:
        logger.info(f"开始测试登录用户: {username}")
        
        # 尝试登录
        try:
            success = client.login(username, password)
            if success:
                logger.info("✅ 登录成功！（无需 2FA）")
        except TwoFactorRequired:
            logger.info("🔐 需要 2FA，生成 TOTP 代码...")
            totp_code = client.totp_generate_code(totp_secret)
            logger.info(f"🔢 TOTP 代码: {totp_code}")
            
            success = client.login(username, password, verification_code=totp_code)
            if success:
                logger.info("✅ 使用 TOTP 登录成功！")
        
        if success:
            logger.info(f"🆔 用户 ID: {client.user_id}")
            
            # 获取用户信息
            try:
                user_info = client.user_info(client.user_id)
                logger.info("✅ 用户信息获取成功:")
                logger.info(f"   用户名: {user_info.username}")
                logger.info(f"   全名: {user_info.full_name}")
                logger.info(f"   粉丝: {user_info.follower_count}")
                logger.info(f"   关注: {user_info.following_count}")
                logger.info(f"   帖子: {user_info.media_count}")
            except Exception as e:
                logger.warning(f"⚠️ 获取用户信息失败: {e}")
            
            logger.info("🎉 登录测试完成！")
            return True
        
    except BadCredentials:
        logger.error("❌ 用户名或密码错误")
    except ChallengeRequired as e:
        logger.warning(f"⚠️ 需要挑战验证: {e}")
    except Exception as e:
        logger.error(f"❌ 登录失败: {e}")
    
    return False

if __name__ == "__main__":
    test_login()
