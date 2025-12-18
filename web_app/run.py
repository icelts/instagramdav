#!/usr/bin/env python3
"""
FastAPI 启动脚本
用法: python run.py
"""
import os
import uvicorn


def main():
    port = int(os.environ.get("PORT", 5000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)


if __name__ == "__main__":
    main()
