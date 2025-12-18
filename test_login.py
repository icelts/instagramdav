#!/usr/bin/env python3
"""
测试 Instagram 登录脚本
使用提供的凭据测试登录功能
"""

import os
import sys
import time
import logging
from instagrapi import Client
from instagrapi.exceptions import TwoFactorRequired, ChallengeRequired, BadCredentials

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 测试凭据
CREDENTIALS = {
    "username": "ruth87283",
    "password": "r?Vcc7#NH1",
    "totpSecret": "SGPOGESJNAA6TV4PEQGVJCAN6KTPJ24R"
}

class InstagramLoginTester:
    def __init__(self):
        self.client = Client()
        self.setup_logging()
    
    def setup_logging(self):
        """设置客户端日志"""
        self.client.logger = logger
    
    def test_login_with_totp(self):
        """测试带 TOTP 的登录"""
        logger.info("开始测试 Instagram 登录...")
        
        try:
            # 尝试登录
            logger.info(f"尝试使用用户名 {CREDENTIALS['username']} 登录...")
            
            # 第一次登录尝试（可能需要 2FA）
            try:
                success = self.client.login(
                    username=CREDENTIALS['username'],
                    password=CREDENTIALS['password']
                )
                if success:
                    logger.info("✅ 登录成功！（无需 2FA）")
                    return True
            except TwoFactorRequired as e:
                logger.info("🔐 需要双因素认证 (2FA)")
                logger.info(f"2FA 详细信息: {e}")
                
                # 生成 TOTP 代码
                totp_code = self.client.totp_generate_code(CREDENTIALS['totpSecret'])
                logger.info(f"🔢 生成的 TOTP 代码: {totp_code}")
                
                # 使用 TOTP 代码重新登录
                try:
                    success = self.client.login(
                        username=CREDENTIALS['username'],
                        password=CREDENTIALS['password'],
                        verification_code=totp_code
                    )
                    if success:
                        logger.info("✅ 使用 TOTP 登录成功！")
                        return True
                    else:
                        logger.error("❌ 使用 TOTP 登录失败")
                        return False
                except Exception as e:
                    logger.error(f"❌ TOTP 登录过程中出错: {e}")
                    return False
            
            except ChallengeRequired as e:
                logger.warning("⚠️ 需要完成挑战验证")
                logger.info(f"挑战信息: {e}")
                logger.info("这可能需要手动干预或更复杂的挑战处理")
                return False
            
            except BadCredentials as e:
                logger.error("❌ 用户名或密码错误")
                logger.error(f"错误详情: {e}")
                return False
            
            except Exception as e:
                logger.error(f"❌ 登录过程中发生未知错误: {e}")
                return False
        
        except Exception as e:
            logger.error(f"❌ 初始化登录测试时出错: {e}")
            return False
    
    def test_account_info(self):
        """测试获取账户信息"""
        if not self.client.user_id:
            logger.error("❌ 无法获取用户 ID，可能未正确登录")
            return False
        
        try:
            logger.info(f"✅ 用户 ID: {self.client.user_id}")
            
            # 获取用户信息
            user_info = self.client.user_info(self.client.user_id)
            logger.info("✅ 成功获取用户信息:")
            logger.info(f"   用户名: {user_info.username}")
            logger.info(f"   全名: {user_info.full_name}")
            logger.info(f"   粉丝数: {user_info.follower_count}")
            logger.info(f"   关注数: {user_info.following_count}")
            logger.info(f"   帖子数: {user_info.media_count}")
            logger.info(f"   私密账户: {user_info.is_private}")
            logger.info(f"   验证账户: {user_info.is_verified}")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ 获取账户信息时出错: {e}")
            return False
    
    def test_timeline(self):
        """测试获取时间线"""
        try:
            logger.info("📱 测试获取时间线...")
            timeline_feed = self.client.get_timeline_feed(reason="cold_start_fetch")
            
            if timeline_feed and "feed_items" in timeline_feed:
                feed_count = len(timeline_feed["feed_items"])
                logger.info(f"✅ 成功获取时间线，包含 {feed_count} 个项目")
                return True
            else:
                logger.warning("⚠️ 时间线为空或格式异常")
                return False
                
        except Exception as e:
            logger.error(f"❌ 获取时间线时出错: {e}")
            return False
    
    def run_tests(self):
        """运行所有测试"""
        logger.info("=" * 50)
        logger.info("🚀 开始 Instagram 登录测试")
        logger.info("=" * 50)
        
        # 测试登录
        login_success = self.test_login_with_totp()
        
        if not login_success:
            logger.error("❌ 登录失败，跳过后续测试")
            return False
        
        # 测试账户信息
        account_success = self.test_account_info()
        
        # 测试时间线
        timeline_success = self.test_timeline()
        
        # 总结
        logger.info("=" * 50)
        logger.info("📊 测试结果总结:")
        logger.info(f"   登录测试: {'✅ 通过' if login_success else '❌ 失败'}")
        logger.info(f"   账户信息: {'✅ 通过' if account_success else '❌ 失败'}")
        logger.info(f"   时间线获取: {'✅ 通过' if timeline_success else '❌ 失败'}")
        
        if login_success and account_success:
            logger.info("🎉 核心功能测试成功！")
            return True
        else:
            logger.error("❌ 部分测试失败")
            return False
    
    def cleanup(self):
        """清理资源"""
        try:
            if self.client:
                logger.info("🧹 清理客户端资源...")
                # 可以选择是否登出
                # self.client.logout()
                logger.info("✅ 清理完成")
        except Exception as e:
            logger.warning(f"⚠️ 清理过程中出现警告: {e}")

def main():
    """主函数"""
    tester = None
    try:
        tester = InstagramLoginTester()
        success = tester.run_tests()
        return 0 if success else 1
    except KeyboardInterrupt:
        logger.info("\n⚠️ 用户中断测试")
        return 1
    except Exception as e:
        logger.error(f"❌ 测试过程中发生严重错误: {e}")
        return 1
    finally:
        if tester:
            tester.cleanup()

if __name__ == "__main__":
    sys.exit(main())
