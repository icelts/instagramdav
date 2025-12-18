# Instagram 数据抓取能力完整指南

基于 instagrapi 项目的功能分析，以下是完整的数据抓取能力清单。

## 📊 数据抓取能力概览

instagrapi 是一个功能强大的 Instagram API 库，支持全面的数据抓取功能，涵盖了 Instagram 平台的几乎所有公开和半公开数据类型。

## 👤 用户相关数据

### 基本用户信息
```python
# 可获取的数据字段
user_info = {
    "pk": 77589054985,                    # 用户唯一ID
    "username": "ruth87283",              # 用户名
    "full_name": "Ruth Scott",            # 全名
    "biography": "Bio text here...",      # 个人简介
    "profile_pic_url": "https://...",     # 头像URL
    "profile_pic_id": "1234567890",       # 头像ID
    "is_private": False,                  # 是否私密账户
    "is_verified": False,                 # 是否验证账户
    "is_business": False,                 # 是否商业账户
    "external_url": "https://...",        # 外部链接
    "followers_count": 1000,              # 粉丝数量
    "following_count": 500,               # 关注数量
    "media_count": 50,                    # 帖子数量
    "usertags_count": 10,                 # 被标签数量
    "has_highlight_reels": True,          # 是否有Story高亮
    "has_guides": False,                  # 是否有指南
    "has_channel": False,                 # 是否有频道
    "total_igtv_videos": 5,              # IGTV视频数量
    "total_clips_count": 8,               # Reels数量
    "country_code": "US",                 # 国家代码
    "latitude": 40.7128,                  # 纬度（如果公开）
    "longitude": -74.0060,                # 经度（如果公开）
    "address": "New York, NY",            # 地址（如果公开）
    "city_id": 12345,                     # 城市ID
    "city_name": "New York",              # 城市名称
    "contact_phone_number": "+1234567890", # 电话号码（商业账户）
    "public_phone_country_code": "1",      # 电话国家代码
    "public_phone_number": "2345678900",   # 公开电话号码
    "category": "Personal Blog",          # 账户分类
    "page_name": "Ruth's Blog"            # 页面名称（商业账户）
}
```

### 社交关系数据
```python
# 粉丝列表
followers = client.user_followers(user_id, amount=1000)
# 每个粉丝包含：
{
    "pk": 123456789,
    "username": "follower1",
    "full_name": "Follower One",
    "profile_pic_url": "https://...",
    "is_private": False,
    "is_verified": False,
    "followed_by_viewer": True,
    "requested_by_viewer": False
}

# 关注列表
following = client.user_following(user_id, amount=1000)

# 互相关注
mutual_following = client.user_mutual_followers(user_id, amount=500)

# 被标签的媒体
tagged_medias = client.usertag_medias(user_id, amount=100)
```

### 用户搜索
```python
# 按用户名搜索
users = client.search_users("ruth87283", count=10)

# 按位置搜索用户
users_by_location = client.top_search("New York")

# Facebook 搜索
fb_search_results = client.fbsearch_users("search term")
```

## 📱 媒体内容数据

### 媒体基本信息
```python
media_info = {
    "pk": 1234567890123456789,          # 媒体唯一ID
    "id": "1234567890123456789_77589054985", # 完整ID
    "taken_at": 1672531200,              # 发布时间戳
    "media_type": 1,                     # 媒体类型 (1=照片, 2=视频, 8=相册)
    "code": "C123ABC456",                # 媒体代码
    "caption_text": "Amazing sunset...", # 说明文字
    "like_count": 150,                   # 点赞数
    "comment_count": 25,                 # 评论数
    "view_count": 500,                   # 观看数（视频）
    "play_count": 300,                   # 播放数（Reels）
    "has_liked": False,                  # 当前用户是否点赞
    "has_saved": False,                  # 当前用户是否收藏
    "has_commented": False,              # 当前用户是否评论
    "accessibility_caption": "Photo of...", # 无障碍描述
    "thumbnail_url": "https://...",      # 缩略图URL
    "video_url": "https://...",          # 视频URL
    "video_duration": 30.5,              # 视频时长
    "video_view_count": 1000,            # 视频观看数
    "image_versions2": {...},            # 图片版本信息
    "user": {...},                       # 发布者信息
    "location": {...},                   # 位置信息
    "tagged_users": [...],               # 被标签的用户
    "product_tags": [...],               # 产品标签
    "sponsor_tags": [...],               # 赞助标签
    "story_locations": [...],            # Story位置
    "music_metadata": {...},             # 音乐元数据
    "sharing_friction_info": {...}       # 分享信息
}
```

### 用户媒体列表
```python
# 用户的所有媒体
user_medias = client.user_medias(user_id, amount=50)

# 用户照片
user_photos = client.user_medias(user_id, amount=20)  # 过滤 media_type == 1

# 用户视频
user_videos = client.user_medias(user_id, amount=20)  # 过滤 media_type == 2

# 用户相册
user_albums = client.user_medias(user_id, amount=20)  # 过滤 media_type == 8

# 用户IGTV
user_igtv = client.user_igtv(user_id, amount=20)

# 用户Reels
user_clips = client.user_clips(user_id, amount=20)
```

### 媒体下载功能
```python
# 下载照片
photo_path = client.photo_download(media_pk)

# 下载视频
video_path = client.video_download(media_pk)

# 下载相册
album_paths = client.album_download(media_pk)

# 下载IGTV
igtv_path = client.igtv_download(media_pk)

# 下载Reels
clip_path = client.clip_download(media_pk)
```

## 🏷️ 标签(Hashtag)数据

### 标签信息
```python
hashtag_info = {
    "pk": 123456789,                     # 标签ID
    "name": "travel",                    # 标签名称
    "allow_following": True,             # 是否允许关注
    "allow_muting_story": True,          # 是否允许静音Story
    "following": False,                  # 当前用户是否关注
    "contextual_name": "",               # 上下文名称
    "description": "Travel related posts", # 标签描述
    "is_editable": True,                 # 是否可编辑
    "is_following": False,               # 是否已关注
    "is_top_media_only": False,          # 是否只显示热门
    "media_count": 1000000,              # 媒体数量
    "non_muting": False,                 # 非静音状态
    "profile_pic_url": "https://...",    # 标签头像
    "related_hashtags": [...],           # 相关标签
    "show_follow_drop_down": True,       # 显示关注下拉
    "title": "Travel",                   # 标题
    "type": "hashtag"                    # 类型
}
```

### 标签媒体数据
```python
# 热门媒体
top_medias = client.hashtag_medias_top("travel", amount=20)

# 最新媒体
recent_medias = client.hashtag_medias_recent("travel", amount=50)

# Reels媒体
reels_medias = client.hashtag_medias_reels("travel", amount=20)

# 相关标签
related_hashtags = client.hashtag_related_hashtags("travel")

# 关注标签
client.hashtag_follow("travel")
client.hashtag_unfollow("travel")
```

## 📍 位置数据

### 位置信息
```python
location_info = {
    "pk": 123456789,                     # 位置ID
    "name": "Central Park",              # 位置名称
    "address": "New York, NY 10024",     # 地址
    "city": "New York",                  # 城市
    "short_name": "Central Park",        # 简称
    "lng": -73.9654,                     # 经度
    "lat": 40.7829,                      # 纬度
    "external_source": "facebook_places", # 外部源
    "facebook_places_id": 123456789,     # Facebook位置ID
    "profile_pic_url": "https://...",    # 位置头像
    "media_count": 50000,                # 媒体数量
    "is_group_page": False,             # 是否群组页面
    "is_ad_page": False,                # 是否广告页面
    "is_city_page": True,               # 是否城市页面
    "is_top_pick": True,                # 是否精选
    "blurb": "Famous park in NYC",      # 简介
    "directory": "parks",               # 分类
    "phone": "+1-212-123-4567",         # 电话
    "website": "https://centralpark.org" # 网站
}
```

### 位置相关数据
```python
# 位置搜索
locations = client.location_search("Central Park", lat=40.7829, lng=-73.9654)

# 位置媒体
location_medias = client.location_medias(location_pk, amount=50)

# 位置信息
location_info = client.location_info(location_pk)

# 按位置搜索相关内容
top_search = client.top_search("Central Park")
```

## 💬 评论数据

### 评论信息
```python
comment_info = {
    "pk": 1234567890123456789,          # 评论ID
    "text": "Amazing photo!",            # 评论内容
    "user": {...},                       # 评论用户信息
    "created_at": 1672531200,            # 创建时间
    "content_type": "comment",          # 内容类型
    "has_liked_comment": False,          # 是否点赞评论
    "like_count": 5,                    # 评论点赞数
    "parent_comment_id": 0,              # 父评论ID（回复）
    "is_author_liked": False,           # 作者是否点赞
    "bit_flags": 0,                      # 位标志
    "did_report_as_spam": False,         # 是否举报垃圾
    "child_comment_count": 2,            # 子评论数量
    "inline_composer_display_condition": "never", # 内联显示条件
    "other_preview_users": [...],        # 其他预览用户
    "reply_author_username": "",         # 回复作者用户名
    "replied_to_comment_id": 0,          # 回复的评论ID
    "timezone_offset": -14400,           # 时区偏移
    "server_time": 1672531200,           # 服务器时间
    "is_forecasted_deleted": False       # 是否预测删除
}
```

### 评论操作
```python
# 媒体评论
media_comments = client.media_comments(media_pk)

# 媒体评论V2
comments_v2 = client.media_comments_v2(media_pk, amount=50)

# 媒体评论线程
comment_thread = client.media_comment(media_pk, comment_pk)

# 评论操作
client.comment_like(media_pk, comment_pk)
client.comment_unlike(media_pk, comment_pk)
client.comment_delete(media_pk, comment_pk)
```

## 🔍 搜索数据

### 综合搜索
```python
# 顶部搜索（包含用户、标签、位置）
top_search_results = client.top_search("travel")

# 用户搜索
user_search_results = client.search_users("travel")

# 标签搜索
hashtag_search_results = client.search_hashtags("travel")

# 位置搜索
location_search_results = client.location_search("New York")

# Facebook搜索
fb_search_users = client.fbsearch_users("travel")
fb_search_hashtags = client.fbsearch_hashtags("travel")
fbsearch_places = client.fbsearch_places("New York")
```

## 📚 收藏和集合数据

### 收藏数据
```python
# 用户收藏
liked_medias = client.liked_medias(amount=100)

# 集合列表
collections = client.collections()

# 集合媒体
collection_medias = client.collection_medias(collection_pk)

# 按名称获取集合
collection_medias_by_name = client.collection_medias_by_name("Favorites")

# 收藏操作
client.media_save(media_id, collection_pk)
client.media_unsave(media_id, collection_pk)
```

## 📊 分析数据（商业账户）

### 账户分析数据
```python
# 账户洞察
account_insights = client.insights_account()
# 包含：
{
    "account_activity": {
        "impressions": 10000,            # 展示次数
        "reach": 8000,                   # 触达人数
        "website_clicks": 100,           # 网站点击
        "profile_views": 500,             # 资料查看
        "follower_count": 1000,          # 粉丝数
        "email_contacts": 50,            # 邮箱联系
        "phone_call_clicks": 20           # 电话点击
    },
    "audience": {
        "followers_graph": [...],         # 粉丝增长图表
        "top_locations": [...],           # 主要地区
        "age_range": [...],              # 年龄分布
        "gender": [...],                 # 性别分布
        "cities": [...],                 # 城市分布
        "countries": [...]              # 国家分布
    },
    "content": {
        "total_posts": 50,               # 总帖子数
        "total_media_count": 50,         # 总媒体数
        "content_activity": [...]       # 内容活动数据
    }
}
```

### 媒体分析数据
```python
# 媒体洞察
media_insights = client.insights_media(media_pk)
# 包含：
{
    "impressions": 5000,                # 展示次数
    "reach": 4000,                      # 触达人数
    "likes": 150,                       # 点赞数
    "comments": 25,                     # 评论数
    "shares": 10,                       # 分享数
    "saves": 20,                        # 收藏数
    "profile_visits": 30,               # 资料访问
    "follows": 5,                       # 关注转化
    "video_views": 1000,                # 视频观看
    "video_thruplay": 800,              # 视频完整观看
    "video_average_duration": 15.5,     # 平均观看时长
    "carousel_engagement": [...],       # 轮播互动
    "story_interactions": [...],        # Story互动
    "demographics": [...],              # 人口统计
    "locations": [...],                 # 地理分布
    "sources": [...]                    # 来源分析
}

# 媒体分析列表
media_insights_feed = client.insights_media_feed_all(
    post_type="ALL",           # ALL, CAROUSEL_V2, IMAGE, SHOPPING, VIDEO
    time_frame="TWO_YEARS",    # ONE_WEEK, ONE_MONTH, THREE_MONTHS, SIX_MONTHS, ONE_YEAR, TWO_YEARS
    data_ordering="REACH_COUNT", # REACH_COUNT, LIKE_COUNT, FOLLOW, SHARE_COUNT, BIO_LINK_CLICK, COMMENT_COUNT, IMPRESSION_COUNT, PROFILE_VIEW, VIDEO_VIEW_COUNT, SAVE_COUNT
    count=100
)
```

## 📱 Story数据

### Story信息
```python
story_info = {
    "pk": 1234567890123456789,          # Story唯一ID
    "id": "1234567890123456789_77589054985", # 完整ID
    "taken_at": 1672531200,              # 创建时间
    "media_type": 1,                     # 媒体类型
    "product_type": "story",             # 产品类型
    "code": "",                          # 代码（Story通常为空）
    "caption": None,                     # 说明文字
    "like_count": 0,                     # 点赞数（Story不适用）
    "has_liked": False,                  # 是否点赞（Story不适用）
    "comment_count": 0,                  # 评论数（Story不适用）
    "has_more_comments": False,          # 是否有更多评论
    "view_count": 100,                   # 观看数
    "can_viewer_reshare": True,          # 查看者是否可分享
    "caption_is_edited": False,          # 说明是否已编辑
    "is_commercial": False,              # 是否商业内容
    "expiring_at": 1672617600,           # 过期时间
    "imported_taken_at": 1672531200,     # 导入时间
    "story_is_app_reposted": False,      # 是否应用转发
    "story_is_saved_to_archive": True,   # 是否保存到存档
    "story_cta": [...],                  # Story行动号召
    "story_locations": [...],            # Story位置
    "story_hashtags": [...],             # Story标签
    "story_polls": [...],                # Story投票
    "story_sliders": [...],              # Story滑块
    "story_questions": [...],            # Story问题
    "story_quizs": [...],                # Story问答
    "story_media_list_id": "1234567890", # Story媒体列表ID
    "story_feeds": [...],                # Story信息流
    "user": {...},                       # 发布者信息
    "viewer_count": 100,                 # 查看者数量
    "viewer_cursor": "",                 # 查看者游标
    "media": {...},                      # 媒体内容
    "creative_config": {...},            # 创意配置
    "reel_mentions": [...],             # Reels提及
    "ranked_position": 0,                # 排名位置
    "max_seen_counts_seen": 50,          # 最大观看计数
    "original_media_has_thumbnails": False, # 原媒体是否有缩略图
    "text_to_appeal_label": None,        # 申诉标签文本
    "appeal_code": None,                 # 申诉代码
    "appeal_description": None,          # 申诉描述
    "appeal_privacy_policy": None,       # 申诉隐私政策
    "appeal_term": None                  # 申诉条款
}
```

### Story相关功能
```python
# 用户Story
user_stories = client.user_stories(user_id)

# Story查看者
story_viewers = client.story_viewers(story_pk)

# Story媒体下载
story_path = client.story_download(story_pk)

# Story高亮
user_highlights = client.user_highlights(user_id)
highlight_medias = client.highlight_medias(highlight_pk)
```

## 🎯 高级功能数据

### 探索页面数据
```python
# 探索页面信息
explore_data = client.explore()

# 探索标签
explore_hashtags = client.explore_hashtags()

# 探索用户
explore_users = client.explore_users()

# 探索媒体
explore_medias = client.explore_posts()
```

### 时间线数据
```python
# 时间线信息流
timeline_feed = client.get_timeline_feed()

# Reels信息流
reels_tray_feed = client.get_reels_tray_feed()

# 推荐用户
discover_people = client.discover_people()
```

## 📨 私信数据

### 私信信息
```python
# 私信线程列表
threads = client.direct_threads()

# 私信消息
messages = client.direct_messages(thread_id)

# 发送私信
client.direct_send(text="Hello!", user_ids=[user_id])

# 发送媒体私信
client.direct_send_photo(photo_path, user_ids=[user_id])
client.direct_send_video(video_path, user_ids=[user_id])
```

## 🔔 通知数据

### 通知信息
```python
# 通知列表
notifications = client.notifications()

# 活动通知
activity_notifications = client.activity()
```

## 🎵 音乐数据

### 音乐信息
```python
# 音乐搜索
music_search_results = client.music_search("song name")

# 音乐信息
music_info = client.music_info(music_id)
```

## 📋 数据抓取限制和注意事项

### API限制
```python
# 速率限制
- 每小时请求限制：约200-500次（根据账户类型）
- 批量操作限制：每次最多获取200个项目
- 关注/取消关注限制：每小时约100-200次
- 点赞限制：每小时约300-500次
- 评论限制：每小时约60-100条
```

### 权限要求
```python
# 公开数据（无需登录）
- 公开用户基本信息
- 公开媒体内容
- 标签信息
- 位置信息

# 需要登录的数据
- 私密账户内容
- 关注列表
- 私信
- 收藏
- 个人故事

# 需要商业账户的数据
- 详细分析数据
- 高级洞察
- 受众分析
```

### 最佳实践
```python
# 1. 使用会话持久化
client.load_settings("session.json")

# 2. 实施速率限制
import time
time.sleep(1)  # 请求间延迟

# 3. 错误处理
try:
    data = client.user_medias(user_id)
except Exception as e:
    print(f"获取失败: {e}")

# 4. 数据验证
def validate_media_data(media):
    required_fields = ['pk', 'taken_at', 'media_type']
    return all(hasattr(media, field) for field in required_fields)
```

## 📊 数据抓取示例

### 完整用户分析示例
```python
def complete_user_analysis(username):
    try:
        # 获取用户信息
        user = client.user_info_by_username(username)
        user_id = user.pk
        
        # 基本信息采集
        basic_info = {
            "username": user.username,
            "full_name": user.full_name,
            "followers": user.followers_count,
            "following": user.following_count,
            "posts": user.media_count,
            "is_private": user.is_private,
            "is_verified": user.is_verified,
            "biography": user.biography,
            "external_url": user.external_url
        }
        
        # 媒体数据采集
        medias = client.user_medias(user_id, amount=50)
        media_data = []
        for media in medias:
            media_data.append({
                "pk": media.pk,
                "type": media.media_type,
                "caption": media.caption_text,
                "likes": media.like_count,
                "comments": media.comment_count,
                "taken_at": media.taken_at
            })
        
        # 粉丝数据采样
        followers = client.user_followers(user_id, amount=100)
        follower_data = [{"username": f.username, "pk": f.pk} for f in followers]
        
        return {
            "basic_info": basic_info,
            "media_analysis": media_data,
            "follower_sample": follower_data,
            "timestamp": time.time()
        }
        
    except Exception as e:
        print(f"分析失败: {e}")
        return None
```

## 📸 媒体发布功能（发图发Reels）

### ✅ 图片上传功能
```python
# 基本图片上传
media = client.photo_upload(
    path=Path("photo.jpg"),
    caption="Amazing sunset! 🌅 #sunset #nature",
    usertags=[
        Usertag(user=user_obj, x=0.5, y=0.5)  # 标记用户
    ],
    location=Location(
        pk=123456789,
        name="Central Park",
        address="New York, NY"
    )
)

# 支持的图片格式
- JPG/JPEG: 主要格式，推荐使用
- PNG: 支持透明背景
- WEBP: 现代Web格式

# 图片处理功能
- 自动压缩和优化
- 尺寸调整（最大边长1080px）
- 质量控制（默认80%）
- EXIF数据处理
```

### 🎬 Reels发布功能
```python
# 基本Reels上传
reel = client.clip_upload(
    path=Path("reel.mp4"),
    caption="Check out this amazing moment! 🎬 #reels #viral",
    thumbnail=Path("thumbnail.jpg"),  # 可选，自动生成
    usertags=[...],
    location=location_obj,
    feed_show="1"  # 是否显示在信息流中
)

# 带音乐的Reels
track = client.search_music("Popular Song")[0]
reel_with_music = client.clip_upload_as_reel_with_music(
    path=Path("reel.mp4"),
    caption="Music video 🎵",
    track=track
)

# Reels特性
- 自动缩略图生成
- 音乐集成
- 视频转码处理
- 高宽比适配
- 时长控制（建议15-60秒）
```

### 🎥 视频上传功能
```python
# 常规视频上传
video = client.video_upload(
    path=Path("video.mp4"),
    caption="New video uploaded! 📹",
    thumbnail=Path("thumb.jpg"),
    usertags=[...],
    location=location_obj,
    extra_data={
        "share_to_facebook": "1"  # 分享到Facebook
    }
)

# 支持的视频格式
- MP4: 主要格式，推荐H.264编码
- MOV: 支持但可能需要转码
- 自动缩略图生成
- 视频压缩优化
```

### 📱 Story发布功能
```python
# 图片Story
story_photo = client.photo_upload_to_story(
    path=Path("story.jpg"),
    caption="Daily story! 📸",
    mentions=[StoryMention(user=user_obj, x=0.5, y=0.5)],
    locations=[StoryLocation(location=loc_obj, x=0.3, y=0.7)],
    links=[StoryLink(webUri="https://example.com", x=0.8, y=0.2)],
    hashtags=[StoryHashtag(hashtag=hashtag_obj, x=0.5, y=0.8)],
    stickers=[StorySticker(type="gif", x=0.7, y=0.3)],
    polls=[StoryPoll(question="Choose one", options=["A", "B"])],
    medias=[StoryMedia(media_pk=123456789, x=0.4, y=0.6)]
)

# 视频Story
story_video = client.video_upload_to_story(
    path=Path("story_video.mp4"),
    caption="Video story! 🎬",
    mentions=[...],
    links=[...],
    polls=[...],
    extra_data={
        "share_to_facebook": "1"
    }
)

# Story互动功能
- 提及用户(@用户名)
- 位置标签
- 链接分享（需要验证账户）
- 话题标签
- GIF贴纸
- 投票功能
- 媒体分享
- 问答功能
- 滑块功能
```

### 📚 相册发布功能
```python
# 相册上传（多张图片/视频）
album = client.album_upload(
    paths=[
        Path("photo1.jpg"),
        Path("photo2.jpg"), 
        Path("video1.mp4")
    ],
    caption="Multi-media post 📸📹",
    usertags=[...],
    location=location_obj
)

# 相册特性
- 支持混合媒体（图片+视频）
- 最多10个文件
- 自动排序
- 统一描述和标签
- 独立的用户标记
```

### 🎵 音乐集成功能
```python
# 音乐搜索
tracks = client.search_music("song title")
track = tracks[0]

# 音乐元数据
music_info = {
    "title": track.title,
    "artist": track.display_artist,
    "duration": track.duration,
    "cover_art_url": track.cover_art_url,
    "preview_url": track.preview_url,
    "audio_cluster_id": track.audio_cluster_id,
    "highlight_start_times_in_ms": track.highlight_start_times_in_ms
}

# 音乐下载
audio_path = client.track_download_by_url(track.uri, "audio.m4a")
```

### 📍 位置标签功能
```python
# 位置搜索
locations = client.location_search("Central Park", lat=40.7829, lng=-73.9654)
location = locations[0]

# 位置信息结构
location_info = {
    "pk": 123456789,
    "name": "Central Park",
    "address": "New York, NY 10024",
    "city": "New York",
    "lat": 40.7829,
    "lng": -73.9654,
    "external_source": "facebook_places"
}

# 完整位置信息
complete_location = client.location_complete(location_obj)
```

### 👥 用户标签功能
```python
# 用户标记
usertag = Usertag(
    user=user_obj,           # 用户对象
    x=0.5,                # X坐标 (0.0-1.0)
    y=0.5                  # Y坐标 (0.0-1.0)
)

# Story提及
story_mention = StoryMention(
    user=user_obj,
    x=0.5,
    y=0.5,
    width=0.3,              # 宽度
    height=0.1              # 高度
)
```

### 🔧 高级发布选项
```python
# 额外配置参数
extra_data = {
    "share_to_facebook": "1",          # 分享到Facebook
    "share_to_twitter": "1",            # 分享到Twitter
    "share_to_tumblr": "1",            # 分享到Tumblr
    "is_unified_video": "1",           # 统一视频格式
    "camera_position": "back",           # 相机位置
    "source_type": "4",                # 来源类型
    "filter_type": "0",                # 滤镜类型
    "audio_muted": False,               # 音频静音
    "clips_share_preview_to_feed": "1",  # Reels预览分享到信息流
    "allow_multi_configures": "1"       # 允许多重配置
}

# 时间安排和调度
# 可以设置发布时间为过去时间（模拟延迟发布）
import time
past_timestamp = int(time.time() - 3600)  # 1小时前
```

### 📊 发布后分析
```python
# 获取发布结果
media_info = client.media_info(media.pk)

# 发布统计
stats = {
    "media_id": media_info.pk,
    "media_type": media_info.media_type,
    "like_count": media_info.like_count,
    "comment_count": media_info.comment_count,
    "view_count": media_info.view_count,
    "share_count": getattr(media_info, 'share_count', 0),
    "save_count": getattr(media_info, 'save_count', 0),
    "engagement_rate": (
        (media_info.like_count + media_info.comment_count) / 
        max(media_info.user.followers_count, 1) * 100
    )
}
```

## 📝 总结

instagrapi 提供了全面的 Instagram 数据抓取和媒体发布能力，包括：

### ✅ 支持的数据类型
1. **用户数据**: 基本信息、社交关系、统计数据
2. **媒体数据**: 照片、视频、相册、Reels、IGTV
3. **内容数据**: 评论、标签、位置、描述
4. **社交数据**: 关注、粉丝、互动
5. **分析数据**: 洞察统计、受众分析（商业账户）
6. **实时数据**: Story、时间线、通知
7. **搜索数据**: 用户、标签、位置、内容搜索

### ✅ 媒体发布能力
1. **图片发布**: JPG、PNG、WEBP格式，支持标签和位置
2. **视频发布**: MP4格式，自动缩略图，支持音乐
3. **Reels发布**: 短视频功能，音乐集成，特效支持
4. **Story发布**: 24小时内容，丰富的互动功能
5. **相册发布**: 多媒体组合，最多10个文件
6. **位置标签**: 地理位置标记和搜索
7. **用户标记**: @提及功能和标签系统
8. **音乐集成**: 搜索、添加和音乐元数据

### ✅ 技术特性
1. **协议模拟**: 完整的Android应用行为模拟
2. **反检测**: 真实设备指纹和请求模式
3. **会话管理**: 持久化登录状态
4. **错误处理**: 完善的异常处理机制
5. **批量操作**: 支持大规模数据采集和发布

### ✅ 发布功能特性
1. **多媒体支持**: 图片、视频、相册、Reels、Story全覆盖
2. **互动功能**: 标签、位置、提及、投票、链接等
3. **音乐集成**: 音乐搜索、添加、元数据处理
4. **自动处理**: 缩略图生成、压缩、格式转换
5. **跨平台**: Facebook、Twitter等社交平台分享
6. **高级选项**: 筛镜、时间安排、多重配置

### ⚠️ 使用限制
1. **API限制**: 请求频率和数量限制
2. **权限要求**: 某些数据需要特定权限
3. **合规要求**: 需遵守Instagram使用条款
4. **技术门槛**: 需要一定的编程基础
5. **发布限制**: 某些功能需要验证账户

通过合理使用这些功能，可以实现从基础用户信息采集到高级商业数据分析，以及从简单内容发布到复杂多媒体创作的各种需求。**是的，完全支持发图和发Reels功能！**
