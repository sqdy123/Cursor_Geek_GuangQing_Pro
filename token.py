#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 文件名: cursor_auth_tool.py

import sqlite3
import os
import sys

class CursorAuth:
    """Cursor认证信息管理器（独立版）"""

    def __init__(self):
        # 根据操作系统确定数据库路径
        if os.name == "nt":  # Windows
            self.db_path = os.path.join(
                os.getenv("APPDATA"), "Cursor", "User", "globalStorage", "state.vscdb"
            )
        else:  # macOS
            self.db_path = os.path.expanduser(
                "~/Library/Application Support/Cursor/User/globalStorage/state.vscdb"
            )

    def update_auth(self, email=None, access_token=None, refresh_token=None):
        """
        更新Cursor的认证信息
        :param email: 新的邮箱地址
        :param access_token: 新的访问令牌
        :param refresh_token: 新的刷新令牌
        :return: bool 是否成功更新
        """
        updates = []
        # 登录状态
        updates.append(("cursorAuth/cachedSignUpType", "Auth_0"))

        if email is not None:
            updates.append(("cursorAuth/cachedEmail", email))
        if access_token is not None:
            updates.append(("cursorAuth/accessToken", access_token))
        if refresh_token is not None:
            updates.append(("cursorAuth/refreshToken", refresh_token))

        if not updates:
            return False

        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            for key, value in updates:
                # 检查键是否存在
                check_query = "SELECT COUNT(*) FROM itemTable WHERE key = ?"
                cursor.execute(check_query, (key,))
                if cursor.fetchone()[0] == 0:
                    insert_query = "INSERT INTO itemTable (key, value) VALUES (?, ?)"
                    cursor.execute(insert_query, (key, value))
                else:
                    update_query = "UPDATE itemTable SET value = ? WHERE key = ?"
                    cursor.execute(update_query, (value, key))

            conn.commit()
            return True

        except sqlite3.Error:
            return False
        except Exception:
            return False
        finally:
            if conn:
                conn.close()


def manual_update_cursor_auth():
    """手动更新Cursor认证信息的工具"""
    
    print("\n欢迎使用Cursor认证工具\n")
    
    # 获取用户输入
    email = input("请输入您的Cursor账号邮箱: ").strip()
    token = input("请输入WorkosCursorSessionToken的值: ").strip()
    
    # 验证输入
    if not email or '@' not in email:
        print("错误: 邮箱格式不正确")
        return False
        
    if not token:
        print("错误: 令牌不能为空")
        return False
    
    # 检查数据库文件是否存在
    auth_manager = CursorAuth()
    if not os.path.exists(auth_manager.db_path):
        print(f"错误: Cursor数据库文件不存在")
        return False
    
    # 更新认证信息
    try:
        result = auth_manager.update_auth(
            email=email,
            access_token=token,
            refresh_token=token
        )
        
        if result:
            print("\n✅ 认证信息更新成功!")
            return True
        else:
            print("\n❌ 认证信息更新失败")
            return False
            
    except Exception:
        print("\n❌ 更新失败")
        return False


def get_token_help():

    print("======================================\n")


if __name__ == "__main__":
    try:
        # 显示帮助信息
        if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help', 'help']:
            get_token_help()
            sys.exit(0)
            
        # 执行认证更新
        manual_update_cursor_auth()
        
    except KeyboardInterrupt:
        print("\n操作已取消")
    except Exception:
        print("\n程序异常")
    finally:
        input("\n按回车键退出...")
