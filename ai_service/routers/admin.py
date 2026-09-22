# -*- coding: utf-8 -*-
"""用户与组织管理 路由模块 —— Phase 6 清理

用户/部门 CRUD 管理端点已迁至 Spring Boot biz 服务（cn.safeagent.biz.admin），
本模块保留 router 装配入口（main.py include_router(admin.router) 仍引用），不注册任何已迁端点。
"""
from fastapi import APIRouter


router = APIRouter()