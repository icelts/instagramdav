#!/usr/bin/env python3
"""
Instagram 数据采集和保存演示脚本
展示如何使用 instagrapi 采集用户资料和媒体信息并保存到本地
"""

import os
import json
import csv
import time
from datetime import datetime
from pathlib import Path
from instagrapi import Client
from instagrapi.exceptions import TwoFactorRequired, ChallengeRequired

class InstagramDataCollector:
    def __init__(self, username, password, totp_secret=None):
        self.client = Client()
        self.username = username
        self.password = password
        self.totp_secret = totp_secret
        self.output_dir = Path("instagram_data")
        self.output_dir.mkdir(exist_ok=True)
        
    def login(self):
        """登录Instagram"""
        try:
            print(f"正在登录用户: {self.username}")
            self.client.login(self.username, self.password)
            print("✅ 登录成功！")
            return True
        except TwoFactorRequired:
            if not self.totp_secret:
                print("❌ 需要TOTP验证码，但未提供密钥")
                return False
            
            totp_code = self.client.totp_generate_code(self.totp_secret)
            print(f"🔢 生成TOTP验证码: {totp_code}")
            
            try:
                self.client.login(self.username, self.password, verification_code=totp_code)
                print("✅ 使用TOTP登录成功！")
                return True
            except Exception as e:
                print(f"❌ TOTP登录失败: {e}")
                return False
        except Exception as e:
            print(f"❌ 登录失败: {e}")
            return False
    
    def collect_user_info(self, target_username):
        """采集用户信息"""
        try:
            print(f"📊 正在采集用户信息: {target_username}")
            user_info = self.client.user_info_by_username(target_username)
            
            # 转换为字典格式
            user_data = {
                "采集时间": datetime.now().isoformat(),
                "用户ID": user_info.pk,
                "用户名": user_info.username,
                "全名": user_info.full_name,
                "简介": user_info.biography,
                "粉丝数": user_info.follower_count,
                "关注数": user_info.following_count,
                "帖子数": user_info.media_count,
                "私密账户": user_info.is_private,
                "验证账户": user_info.is_verified,
                "头像URL": user_info.profile_pic_url,
                "外部URL": user_info.external_url,
                "商业账户": user_info.is_business,
                "专业账户": user_info.is_professional_account,
            }
            
            # 保存为JSON
            json_file = self.output_dir / f"user_{target_username}_{int(time.time())}.json"
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(user_data, f, ensure_ascii=False, indent=2)
            print(f"✅ 用户信息已保存到: {json_file}")
            
            return user_data
            
        except Exception as e:
            print(f"❌ 采集用户信息失败: {e}")
            return None
    
    def collect_user_medias(self, target_username, max_amount=20):
        """采集用户媒体信息"""
        try:
            user_id = self.client.user_id_from_username(target_username)
            print(f"📱 正在采集用户媒体: {target_username} (最多{max_amount}个)")
            
            medias = self.client.user_medias(user_id, amount=max_amount)
            media_list = []
            
            for media in medias:
                media_data = {
                    "媒体ID": media.pk,
                    "代码": media.code,
                    "类型": self.get_media_type_name(media.media_type),
                    "标题": media.title or "",
                    "说明文字": media.caption_text or "",
                    "点赞数": media.like_count,
                    "评论数": media.comment_count,
                    "观看数": getattr(media, 'view_count', 0),
                    "发布时间": media.taken_at.isoformat() if media.taken_at else "",
                    "位置": media.location.name if media.location else None,
                    "标签用户": [tag.user.username for tag in (media.usertags or [])],
                    "URL": f"https://www.instagram.com/p/{media.code}/"
                }
                media_list.append(media_data)
                
                print(f"  📸 {media.code} ({media_data['类型']}) - {media.like_count}赞 {media.comment_count}评论")
            
            # 保存媒体列表
            media_file = self.output_dir / f"medias_{target_username}_{int(time.time())}.json"
            with open(media_file, 'w', encoding='utf-8') as f:
                json.dump(media_list, f, ensure_ascii=False, indent=2)
            print(f"✅ 媒体信息已保存到: {media_file}")
            
            # 保存为CSV格式
            csv_file = self.output_dir / f"medias_{target_username}_{int(time.time())}.csv"
            if media_list:
                with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=media_list[0].keys())
                    writer.writeheader()
                    writer.writerows(media_list)
                print(f"✅ 媒体信息CSV已保存到: {csv_file}")
            
            return media_list
            
        except Exception as e:
            print(f"❌ 采集媒体信息失败: {e}")
            return None
    
    def collect_user_followers(self, target_username, max_amount=100):
        """采集用户粉丝信息"""
        try:
            user_id = self.client.user_id_from_username(target_username)
            print(f"👥 正在采集粉丝信息: {target_username} (最多{max_amount}个)")
            
            followers = self.client.user_followers(user_id, amount=max_amount)
            follower_list = []
            
            for user_id, user in followers.items():
                follower_data = {
                    "用户ID": user.pk,
                    "用户名": user.username,
                    "全名": user.full_name,
                    "简介": user.biography or "",
                    "粉丝数": user.follower_count,
                    "关注数": user.following_count,
                    "私密账户": user.is_private,
                    "验证账户": user.is_verified,
                    "头像URL": user.profile_pic_url
                }
                follower_list.append(follower_data)
                
                if len(follower_list) % 20 == 0:
                    print(f"  已采集 {len(follower_list)} 个粉丝...")
            
            # 保存粉丝列表
            followers_file = self.output_dir / f"followers_{target_username}_{int(time.time())}.json"
            with open(followers_file, 'w', encoding='utf-8') as f:
                json.dump(follower_list, f, ensure_ascii=False, indent=2)
            print(f"✅ 粉丝信息已保存到: {followers_file}")
            
            return follower_list
            
        except Exception as e:
            print(f"❌ 采集粉丝信息失败: {e}")
            return None
    
    def download_media_files(self, target_username, max_amount=10):
        """下载媒体文件"""
        try:
            user_id = self.client.user_id_from_username(target_username)
            print(f"💾 正在下载媒体文件: {target_username} (最多{max_amount}个)")
            
            medias = self.client.user_medias(user_id, amount=max_amount)
            download_dir = self.output_dir / f"downloads_{target_username}_{int(time.time())}"
            download_dir.mkdir(exist_ok=True)
            
            downloaded_files = []
            
            for i, media in enumerate(medias):
                try:
                    file_path = None
                    
                    if media.media_type == 1:  # Photo
                        file_path = self.client.photo_download(media.pk, download_dir)
                        print(f"  📷 下载照片: {file_path}")
                        
                    elif media.media_type == 2:  # Video
                        file_path = self.client.video_download(media.pk, download_dir)
                        print(f"  🎥 下载视频: {file_path}")
                        
                    elif media.media_type == 8:  # Album
                        paths = self.client.album_download(media.pk, download_dir)
                        file_path = paths
                        print(f"  🖼️ 下载相册: {len(paths)}个文件")
                    
                    if file_path:
                        media_info = {
                            "媒体ID": media.pk,
                            "代码": media.code,
                            "类型": self.get_media_type_name(media.media_type),
                            "本地路径": str(file_path) if isinstance(file_path, str) else [str(p) for p in file_path],
                            "URL": f"https://www.instagram.com/p/{media.code}/"
                        }
                        downloaded_files.append(media_info)
                    
                    # 添加延迟避免被限制
                    time.sleep(2)
                    
                except Exception as e:
                    print(f"  ❌ 下载失败 {media.pk}: {e}")
            
            # 保存下载记录
            download_log = self.output_dir / f"download_log_{target_username}_{int(time.time())}.json"
            with open(download_log, 'w', encoding='utf-8') as f:
                json.dump(downloaded_files, f, ensure_ascii=False, indent=2)
            print(f"✅ 下载记录已保存到: {download_log}")
            print(f"✅ 共下载 {len(downloaded_files)} 个媒体文件到: {download_dir}")
            
            return downloaded_files
            
        except Exception as e:
            print(f"❌ 下载媒体文件失败: {e}")
            return None
    
    def get_media_type_name(self, media_type):
        """获取媒体类型名称"""
        types = {
            1: "照片",
            2: "视频", 
            8: "相册"
        }
        return types.get(media_type, f"未知类型({media_type})")
    
    def full_profile_analysis(self, target_username, download_files=False, max_medias=20, max_followers=50):
        """完整的用户资料分析"""
        print(f"\n🚀 开始完整分析用户: {target_username}")
        print("=" * 50)
        
        # 1. 采集基本信息
        user_info = self.collect_user_info(target_username)
        if not user_info:
            return False
        
        # 2. 采集媒体信息
        medias = self.collect_user_medias(target_username, max_medias)
        
        # 3. 采集粉丝信息（如果是公开账户）
        if user_info and not user_info.get("私密账户", True):
            followers = self.collect_user_followers(target_username, max_followers)
        else:
            print("⚠️ 账户为私密或无法获取粉丝信息")
        
        # 4. 下载媒体文件（可选）
        if download_files and medias:
            downloaded = self.download_media_files(target_username, min(len(medias), 10))
        
        print("\n📊 分析完成！")
        print(f"📁 数据保存在: {self.output_dir}")
        return True

def main():
    """主函数"""
    # 测试凭据
    username = "ruth87283"
    password = "r?Vcc7#NH1"
    totp_secret = "SGPOGESJNAA6TV4PEQGVJCAN6KTPJ24R"
    
    # 创建数据采集器
    collector = InstagramDataCollector(username, password, totp_secret)
    
    # 登录
    if not collector.login():
        print("❌ 登录失败，退出程序")
        return
    
    # 示例：分析自己的账户
    collector.full_profile_analysis(
        target_username=username,
        download_files=True,  # 是否下载媒体文件
        max_medias=10,      # 最多采集多少个媒体
        max_followers=30     # 最多采集多少个粉丝
    )
    
    # 示例：分析其他公开账户（需要替换为实际的用户名）
    # collector.full_profile_analysis("instagram", download_files=False, max_medias=5)
    
    print("\n🎉 数据采集演示完成！")

if __name__ == "__main__":
    main()
