import sys
import os
import json
import hashlib
import uuid
import platform
import requests
import subprocess
import time
import threading
import sqlite3
import concurrent.futures
from PyQt5.QtWidgets import QApplication, QMainWindow, QSystemTrayIcon, QMenu, QAction, QStyle, QMessageBox, QWidget, QVBoxLayout, QHBoxLayout, QFrame
from PyQt5.QtCore import QUrl, Qt
from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEngineProfile, QWebEnginePage, QWebEngineScript
from PyQt5.QtWebChannel import QWebChannel
from PyQt5.QtCore import QObject, pyqtSlot, pyqtSignal, QThread
from PyQt5.QtGui import QIcon, QContextMenuEvent

# Cursor重置PowerShell脚本的内容
CURSOR_RESET_SCRIPT = '''
# 生成类似 macMachineId 的格式
function New-MacMachineId {
    $template = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
    $result = ""
    $random = [Random]::new()
    
    foreach ($char in $template.ToCharArray()) {
        if ($char -eq 'x' -or $char -eq 'y') {
            $r = $random.Next(16)
            $v = if ($char -eq "x") { $r } else { ($r -band 0x3) -bor 0x8 }
            $result += $v.ToString("x")
        } else {
            $result += $char
        }
    }
    return $result
}

# 生成64位随机ID
function New-RandomId {
    $uuid1 = [guid]::NewGuid().ToString("N")
    $uuid2 = [guid]::NewGuid().ToString("N")
    return $uuid1 + $uuid2
}

# 备份 MachineGuid
$backupDir = Join-Path $HOME "MachineGuid_Backups"
if (-not (Test-Path $backupDir)) {
    New-Item -ItemType Directory -Path $backupDir | Out-Null
}

$currentValue = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Cryptography" -Name MachineGuid
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFile = Join-Path $backupDir "MachineGuid_$timestamp.txt"
$counter = 0

while (Test-Path $backupFile) {
    $counter++
    $backupFile = Join-Path $backupDir "MachineGuid_${timestamp}_$counter.txt"
}

$currentValue.MachineGuid | Out-File $backupFile

# 使用环境变量构建 storage.json 路径
$storageJsonPath = Join-Path $env:APPDATA "Cursor\\User\\globalStorage\\storage.json"
$newMachineId = New-RandomId
$newMacMachineId = New-MacMachineId
$newDevDeviceId = [guid]::NewGuid().ToString()
$newSqmId = "{$([guid]::NewGuid().ToString().ToUpper())}"

if (Test-Path $storageJsonPath) {
    # 保存原始文件属性
    $originalAttributes = (Get-ItemProperty $storageJsonPath).Attributes
    
    # 移除只读属性
    Set-ItemProperty $storageJsonPath -Name IsReadOnly -Value $false
    
    # 更新文件内容
    $jsonContent = Get-Content $storageJsonPath -Raw -Encoding UTF8
    $data = $jsonContent | ConvertFrom-Json
    
    # 检查并更新或添加属性
    $properties = @{
        "telemetry.machineId" = $newMachineId
        "telemetry.macMachineId" = $newMacMachineId
        "telemetry.devDeviceId" = $newDevDeviceId
        "telemetry.sqmId" = $newSqmId
    }

    foreach ($prop in $properties.Keys) {
        if (-not (Get-Member -InputObject $data -Name $prop -MemberType Properties)) {
            $data | Add-Member -NotePropertyName $prop -NotePropertyValue $properties[$prop]
        } else {
            $data.$prop = $properties[$prop]
        }
    }
    
    $newJson = $data | ConvertTo-Json -Depth 100
    
    # 使用 StreamWriter 保存文件，确保 UTF-8 无 BOM 且使用 LF 换行符
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($storageJsonPath, $newJson.Replace("`r`n", "`n"), $utf8NoBom)
    
    # 恢复原始文件属性
    Set-ItemProperty $storageJsonPath -Name Attributes -Value $originalAttributes
}

# 更新注册表 MachineGuid
$newMachineGuid = [guid]::NewGuid().ToString()
Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Cryptography" -Name "MachineGuid" -Value $newMachineGuid

Write-Host "Successfully updated all IDs:"
Write-Host "Backup file created at: $backupFile"
Write-Host "New MachineGuid: $newMachineGuid"
Write-Host "New telemetry.machineId: $newMachineId"
Write-Host "New telemetry.macMachineId: $newMacMachineId"
Write-Host "New telemetry.devDeviceId: $newDevDeviceId"
Write-Host "New telemetry.sqmId: $newSqmId"
'''

# 检测Cursor进程是否在运行
def is_cursor_running():
    try:
        if platform.system() == 'Windows':
            # 使用不区分大小写的方式检查，同时检查可能的进程名变体
            print("\n" + "="*50)
            print("检测Cursor进程是否在运行...")
            
            # 使用tasklist命令检查进程，但避免编码问题
            for process_name in ["cursor.exe", "Cursor.exe"]:
                # 使用os.system检查进程是否存在
                cmd = f'tasklist /FI "IMAGENAME eq {process_name}" /NH'
                print(f"执行命令: {cmd}")
                
                # 使用临时文件存储输出，避免编码问题
                temp_file = os.path.join(os.environ.get('TEMP', '.'), 'cursor_check.txt')
                os.system(f'{cmd} > "{temp_file}"')
                
                # 读取临时文件内容
                try:
                    with open(temp_file, 'r', errors='ignore') as f:
                        output = f.read()
                    print(f"命令输出: {output.strip()}")
                    
                    # 检查输出中是否包含进程名
                    if process_name.lower() in output.lower():
                        print(f"✅ 检测到Cursor进程正在运行: {process_name}")
                        # 清理临时文件
                        try:
                            os.remove(temp_file)
                        except:
                            pass
                        return True
                except Exception as e:
                    print(f"读取进程检查结果时出错: {e}")
                
                # 清理临时文件
                try:
                    os.remove(temp_file)
                except:
                    pass
            
            # 如果没有找到精确匹配，尝试使用更通用的方法
            print("尝试使用备用方法检测Cursor进程...")
            
            # 使用wmic命令，通常更可靠
            os.system('wmic process where "name like \'%cursor%\'" get name > "' + temp_file + '"')
            try:
                with open(temp_file, 'r', errors='ignore') as f:
                    output = f.read().lower()
                if 'cursor' in output:
                    print("✅ 通过wmic检测到Cursor进程正在运行")
                    return True
            except Exception as e:
                print(f"wmic检测出错: {e}")
            finally:
                try:
                    os.remove(temp_file)
                except:
                    pass
            
            print("❌ 未检测到Cursor进程")
            return False
        else:
            print("暂不支持在非Windows系统上检测Cursor进程")
            return False
    except Exception as e:
        print(f"检测Cursor进程时出错: {e}")
        import traceback
        traceback.print_exc()
        return False

# 终止Cursor进程
def kill_cursor_process():
    try:
        if platform.system() == 'Windows':
            print("\n" + "="*50)
            print("正在尝试终止Cursor进程...")
            
            # 尝试多种可能的进程名称
            success = False
            for process_name in ["cursor.exe", "Cursor.exe"]:
                cmd = f'taskkill /F /IM {process_name}'
                print(f"执行命令: {cmd}")
                try:
                    # 使用os.system而不是subprocess.check_output，避免编码问题
                    result = os.system(cmd)
                    print(f"命令执行结果: {result}")
                    if result == 0:
                        success = True
                        print(f"成功终止进程: {process_name}")
                except Exception as e:
                    print(f"终止 {process_name} 失败: {e}")
            
            if success:
                print("✅ 已强制终止Cursor进程")
            else:
                print("⚠️ 未找到匹配的Cursor进程，或终止过程失败")
            
            # 再次检查确认进程已终止
            time.sleep(1)
            if not is_cursor_running():
                print("✅ 确认Cursor进程已终止")
                return True
            else:
                print("❌ Cursor进程仍在运行，终止失败")
                # 再次尝试使用更直接的方式
                os.system('taskkill /F /IM Cursor.exe /T')
                time.sleep(1)
                if not is_cursor_running():
                    print("✅ 第二次尝试成功终止Cursor进程")
                    return True
                return False
        else:
            print("暂不支持在此系统上终止Cursor")
            return False
    except Exception as e:
        print(f"终止Cursor进程失败: {e}")
        import traceback
        traceback.print_exc()
        return False

# 找到Cursor的storage.json文件路径
def find_storage_json_path():
    if platform.system() == 'Windows':
        appdata = os.environ.get('APPDATA')
        if appdata:
            path = os.path.join(appdata, "Cursor", "User", "globalStorage", "storage.json")
            if os.path.exists(path):
                return path
    return None

# 检查是否具有管理员权限
def is_admin():
    if sys.platform == 'win32':
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        # Unix/Linux系统
        try:
            return os.getuid() == 0
        except:
            return False

# 从Cursor API获取模型使用情况
def get_usage_data(cookie):
    try:
        # 直接使用完整的cookie值，而不是尝试添加前缀
        headers = {
            'cookie': cookie,  # 使用原始cookie值
            'accept': '*/*',
            'host': 'www.cursor.com',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        url = 'https://www.cursor.com/api/usage'
        print("\n" + "="*50)
        print(f"正在发送请求到: {url}")
        print(f"请求头: {json.dumps(headers, indent=2)}")
        
        response = requests.get(url, headers=headers)
        
        print(f"响应状态码: {response.status_code}")
        print(f"响应头: {json.dumps(dict(response.headers), indent=2)}")
        
        try:
            response_json = response.json()
            print(f"响应体: {json.dumps(response_json, indent=2)}")
        except:
            print(f"响应体(非JSON): {response.text[:200]}...")
            
        if response.status_code == 200:
            usage_data = response.json()
            # 获取高级模型值(maxRequestUsage)和已用模型值(numRequests)
            gpt4_data = usage_data.get('gpt-4', {})
            advanced_model = gpt4_data.get('maxRequestUsage', 0)
            used_model = gpt4_data.get('numRequests', 0)
            
            print(f"从API获取的使用数据: 高级模型={advanced_model}, 已用模型={used_model}")
            return advanced_model, used_model, usage_data  # 返回原始数据以便获取更多信息
        else:
            print(f"获取模型使用情况失败: {response.status_code}, {response.text}")
            return 0, 0, None
    except Exception as e:
        print(f"获取模型使用情况时出错: {e}")
        return 0, 0, None

# 并发获取多个账户的使用数据
def get_usage_data_concurrent(account_info_list):
    """
    并发获取多个账户的使用数据
    :param account_info_list: 包含多个账户信息的列表，每个元素是一个元组 (email, cookie)
    :return: 包含每个账户使用数据的列表
    """
    print(f"\n{'-'*20} 开始并发获取 {len(account_info_list)} 个账户的使用数据 {'-'*20}")
    
    def fetch_single_account(account_tuple):
        """获取单个账户的使用数据"""
        email, cookie = account_tuple
        print(f"开始获取账户 {email} 的使用数据")
        try:
            result = get_usage_data(cookie)
            return (email, cookie, result)
        except Exception as e:
            print(f"获取账户 {email} 使用数据时出错: {e}")
            return (email, cookie, (0, 0, None))
    
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        # 提交所有任务并收集Future对象
        future_to_account = {
            executor.submit(fetch_single_account, account_tuple): account_tuple[0]
            for account_tuple in account_info_list
        }
        
        # 处理完成的任务
        for future in concurrent.futures.as_completed(future_to_account):
            email = future_to_account[future]
            try:
                result = future.result()
                print(f"成功获取账户 {email} 的使用数据")
                results.append(result)
            except Exception as e:
                print(f"处理账户 {email} 的结果时出错: {e}")
                # 添加空结果，保持与输入列表的长度一致
                results.append((email, account_info_list[list(map(lambda x: x[0], account_info_list)).index(email)][1], (0, 0, None)))
    
    print(f"{'-'*20} 完成并发获取 {len(results)} 个账户的使用数据 {'-'*20}")
    return results

# 获取设备的真实机器码 - 使用更可靠的方法而不是wmic
def get_machine_code():
    try:
        # 收集系统信息
        sys_info = []
        
        if platform.system() == 'Windows':
            # Windows 系统信息收集
            try:
                import subprocess
                # 获取CPU ID
                result = subprocess.check_output(
                    'powershell.exe "Get-WmiObject -Class Win32_Processor | Select-Object -ExpandProperty ProcessorId"', 
                    shell=True
                ).decode().strip()
                if result:
                    sys_info.append(f"CPU:{result}")
                
                # 获取主板序列号
                result = subprocess.check_output(
                    'powershell.exe "Get-WmiObject -Class Win32_BaseBoard | Select-Object -ExpandProperty SerialNumber"', 
                    shell=True
                ).decode().strip()
                if result and result != "To be filled by O.E.M.":
                    sys_info.append(f"MB:{result}")
                
                # 获取BIOS序列号
                result = subprocess.check_output(
                    'powershell.exe "Get-WmiObject -Class Win32_BIOS | Select-Object -ExpandProperty SerialNumber"', 
                    shell=True
                ).decode().strip()
                if result and result != "To be filled by O.E.M.":
                    sys_info.append(f"BIOS:{result}")
            except Exception as e:
                print(f"获取Windows硬件信息时出错: {e}")
        
        # 添加操作系统信息
        sys_info.append(f"OS:{platform.system()}:{platform.version()}")
        
        # 添加Python安装路径
        sys_info.append(f"PY:{sys.executable}")
        
        # 组合所有信息生成唯一标识
        combined = ":".join(sys_info)
        print(f"系统信息组合: {combined}")
        
        # 使用SHA-256哈希生成机器码
        machine_code_hash = hashlib.sha256(combined.encode()).hexdigest()
        
        # 格式化为易读格式："前8位...后2位"
        return f"{machine_code_hash[:8]}...{machine_code_hash[-2:]}"
    except Exception as e:
        print(f"获取机器码时出错: {e}")
        return "0000...00"

# 设备机器码 - 应用程序启动时计算一次
DEVICE_MACHINE_CODE = get_machine_code()
print(f"当前设备机器码: {DEVICE_MACHINE_CODE}")

# 异步获取账户信息的线程类
class AccountsLoader(QThread):
    accounts_loaded = pyqtSignal(list)  # 信号：当账户加载完成时发出
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
    def run(self):
        try:
            # 网络获取账户数据
            agent_url = ""
            print(f"正在从网络获取账户信息: {agent_url}")
            
            account_info_list = []  # 用于存储待处理的账户信息，格式为 [(email, cookie), ...]
            
            try:
                response = requests.get(agent_url, timeout=10)
                if response.status_code == 200:
                    agent_content = response.text
                    print("成功从网络获取账户信息")
                    
                    # 解析获取的内容
                    for line in agent_content.splitlines():
                        line = line.strip()
                        if line and '|' in line:
                            parts = line.split('|', 1)  # 仅分割第一个 | 字符
                            email = parts[0].strip()
                            cookie_value = parts[1].strip()
                            
                            print(f"读取账户: {email}")
                            
                            # 检查并修正cookie格式 - 添加完整的前缀
                            # 首先去除可能存在的WorkosCursorSessionToken=前缀，确保不会重复添加
                            if cookie_value.startswith("WorkosCursorSessionToken="):
                                cookie_value = cookie_value[len("WorkosCursorSessionToken="):]
                            
                            # 检查是否已包含user_前缀
                            if not cookie_value.startswith("user_01000000000000000000000000%3A%3A"):
                                cookie_value = f"user_01000000000000000000000000%3A%3A{cookie_value}"
                            
                            # 添加完整的cookie头
                            cookie = f"WorkosCursorSessionToken={cookie_value}"
                            print(f"已调整cookie格式: {cookie[:50]}...{cookie[-10:]}")
                            
                            # 将账户信息添加到列表，等待并发处理
                            account_info_list.append((email, cookie))
                    
                    # 如果从网络获取到账户数据
                    if account_info_list:
                        print(f"成功从网络获取了 {len(account_info_list)} 个账户")
                        # 使用并发方式获取所有账户的使用数据
                        usage_results = get_usage_data_concurrent(account_info_list)
                        
                        # 处理结果并创建最终的账户列表
                        accounts = []
                        for email, cookie, usage_data in usage_results:
                            advanced_model, basic_model, api_data = usage_data
                            
                            # 生成最后使用时间
                            from datetime import datetime, timedelta
                            import random
                            days_offset = random.randint(0, 14)
                            hours_offset = random.randint(0, 23)
                            minutes_offset = random.randint(0, 59)
                            seconds_offset = random.randint(0, 59)
                            last_used = (datetime.now() - timedelta(
                                days=days_offset, 
                                hours=hours_offset,
                                minutes=minutes_offset,
                                seconds=seconds_offset
                            )).strftime("%Y/%m/%d %H:%M:%S")
                            
                            account = {
                                "email": email,
                                "cookie": cookie,  # 保存cookie但不在UI中显示
                                "machine_code": DEVICE_MACHINE_CODE,
                                "advanced_model": f"{advanced_model}",
                                "basic_model": f"{basic_model}",
                                "last_used": last_used,
                                "api_data": api_data  # 保存原始API数据以备后用
                            }
                            accounts.append(account)
                        
                        self.accounts_loaded.emit(accounts)
                        return
                else:
                    print(f"从网络获取账户信息失败: HTTP状态码 {response.status_code}")
            except Exception as e:
                print(f"从网络获取账户信息时出错: {e}")
            
            # 如果从网络获取失败，尝试从本地文件读取
            print("尝试从本地文件读取账户信息...")
            current_dir = os.path.dirname(os.path.abspath(__file__))
            agent_file = os.path.join(current_dir, "agent.txt")
            
            account_info_list = []  # 重置账户信息列表
            
            if os.path.exists(agent_file):
                with open(agent_file, 'r', encoding='utf-8') as file:
                    for line in file:
                        line = line.strip()
                        if line and '|' in line:
                            parts = line.split('|', 1)  # 仅分割第一个 | 字符
                            email = parts[0].strip()
                            cookie_value = parts[1].strip()
                            
                            print(f"从本地文件读取账户: {email}")
                            
                            # 检查并修正cookie格式 - 添加完整的前缀
                            if cookie_value.startswith("WorkosCursorSessionToken="):
                                cookie_value = cookie_value[len("WorkosCursorSessionToken="):]
                            
                            # 检查是否已包含user_前缀
                            if not cookie_value.startswith("user_01000000000000000000000000%3A%3A"):
                                cookie_value = f"user_01000000000000000000000000%3A%3A{cookie_value}"
                            
                            # 添加完整的cookie头
                            cookie = f"WorkosCursorSessionToken={cookie_value}"
                            print(f"已调整cookie格式: {cookie[:50]}...{cookie[-10:]}")
                            
                            # 将账户信息添加到列表，等待并发处理
                            account_info_list.append((email, cookie))
                
                if account_info_list:
                    # 使用并发方式获取所有账户的使用数据
                    usage_results = get_usage_data_concurrent(account_info_list)
                    
                    # 处理结果并创建最终的账户列表
                    accounts = []
                    for email, cookie, usage_data in usage_results:
                        advanced_model, basic_model, api_data = usage_data
                        
                        # 生成最后使用时间
                        from datetime import datetime, timedelta
                        import random
                        days_offset = random.randint(0, 14)
                        hours_offset = random.randint(0, 23)
                        minutes_offset = random.randint(0, 59)
                        seconds_offset = random.randint(0, 59)
                        last_used = (datetime.now() - timedelta(
                            days=days_offset, 
                            hours=hours_offset,
                            minutes=minutes_offset,
                            seconds=seconds_offset
                        )).strftime("%Y/%m/%d %H:%M:%S")
                        
                        account = {
                            "email": email,
                            "cookie": cookie,
                            "machine_code": DEVICE_MACHINE_CODE,  # 使用真实设备机器码
                            "advanced_model": f"{advanced_model}",
                            "basic_model": f"{basic_model}",
                            "last_used": last_used,
                            "api_data": api_data
                        }
                        accounts.append(account)
                    
                    # 发送信号，传递账户列表
                    self.accounts_loaded.emit(accounts)
                    return
            else:
                print(f"本地文件不存在: {agent_file}")
                
        except Exception as e:
            print(f"读取账户时出错: {e}")
        
        # 如果没有获取到任何账户，使用一个默认账户
        print("未能获取任何账户信息，使用默认账户")
        accounts = [{
            "email": "anyanyanyasannlpkmsxa@2925.com",
            "cookie": "",
            "machine_code": DEVICE_MACHINE_CODE,  # 使用真实设备机器码
            "advanced_model": "87",
            "basic_model": "0",
            "last_used": "2025/3/13 22:39:54",
            "api_data": None
        }]
        
        # 发送信号，传递账户列表
        self.accounts_loaded.emit(accounts)

# 从agent.txt文件读取账户数据
def read_accounts_from_file():
    # 这个函数现在会立即返回默认账户列表，然后由异步线程更新
    default_accounts = [{
        "email": "正在加载账户信息...",
        "cookie": "",
        "machine_code": DEVICE_MACHINE_CODE,
        "advanced_model": "...",
        "basic_model": "...",
        "last_used": "正在加载...",
        "api_data": None
    }]
    
    # 启动异步加载线程 - 但由于这里只是函数，不能访问全局accounts变量
    # 所以实际的异步加载会在MainWindow和Bridge类中处理
    return default_accounts

# 加载账户数据
accounts = read_accounts_from_file()

class CursorAuth:
    """Cursor认证信息管理器"""

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

        except sqlite3.Error as e:
            print(f"SQLite错误: {e}")
            return False
        except Exception as e:
            print(f"更新认证信息时出错: {e}")
            return False
        finally:
            if conn:
                conn.close()

# 与JavaScript通信的桥接类
class Bridge(QObject):
    # 定义信号用于与主窗口通信
    show_message_signal = pyqtSignal(str, str, bool)
    reset_complete_signal = pyqtSignal()
    accounts_updated_signal = pyqtSignal()  # 新增：账户数据更新信号
    
    def __init__(self, window):
        super().__init__()
        self.window = window  # 保存窗口引用以便导航
        self.accounts_data = accounts
        self.current_page = "home"  # 默认显示首页
        
        # 连接信号到槽
        self.show_message_signal.connect(self.window.show_message)
        self.reset_complete_signal.connect(self.window.reload_after_reset)
        self.accounts_updated_signal.connect(self.accounts_updated)
        
        # 启动异步加载账户信息
        self.start_async_accounts_loading()
    
    def start_async_accounts_loading(self):
        """启动异步账户加载"""
        self.accounts_loader = AccountsLoader()
        self.accounts_loader.accounts_loaded.connect(self.update_accounts)
        self.accounts_loader.start()
    
    def update_accounts(self, new_accounts):
        """当异步加载完成时更新账户列表"""
        if new_accounts:
            self.accounts_data = new_accounts
            global accounts
            accounts = new_accounts
            # 发送信号通知UI更新
            self.accounts_updated_signal.emit()
    
    def accounts_updated(self):
        """当账户数据更新时刷新界面"""
        if self.current_page == "home":
            self.window.load_home_page()
        elif self.current_page == "history":
            self.window.load_history_page()
    
    @pyqtSlot(result=str)
    def getAccounts(self):
        return json.dumps(self.accounts_data)
    
    @pyqtSlot(result=str)
    def getUserData(self):
        """获取首页需要显示的用户数据"""
        # 如果没有账户，返回默认数据
        if not self.accounts_data:
            return json.dumps({
                "username": "hanser",
                "local_account": "未绑定（未验证）",
                "local_status": "已注入客户端",
                "register_time": "未知",
                "machine_code": DEVICE_MACHINE_CODE,
                "agent_quota": "50/50",
                "advanced_model": "无法获取",
                "basic_model": "无法获取"
            })
            
        # 使用第一个账户的数据
        account = self.accounts_data[0]
        
        # 准备首页显示数据
        email = account.get("email", "unknown")
        username = email.split("@")[0] if "@" in email else email
        
        user_data = {
            "username": username,
            "local_account": f"{email} (已验证)" if account.get("cookie") else "未绑定（未验证）",
            "local_status": "已注入客户端",
            "register_time": "未知",
            "machine_code": account.get("machine_code", DEVICE_MACHINE_CODE),
            "agent_quota": "50/50",  # Cursor Agent额度
            "advanced_model": account.get("advanced_model", "无法获取"),
            "basic_model": account.get("basic_model", "无法获取")
        }
        
        # 如果有API数据，可以从中提取更多信息
        api_data = account.get("api_data")
        if api_data:
            # 这里可以从API数据中提取更多信息
            pass
            
        return json.dumps(user_data)
    
    @pyqtSlot(int, result=str)
    def switchAccount(self, account_id):
        if 0 <= account_id < len(self.accounts_data):
            selected_account = self.accounts_data[account_id]
            email = selected_account.get("email", "未知账户")
            cookie = selected_account.get("cookie", "")
            
            print("\n" + "="*50)
            print(f"开始切换到账户: {email} (ID: {account_id}, 总账户数: {len(self.accounts_data)})")
            print(f"当前所有账户列表:")
            for idx, acc in enumerate(self.accounts_data):
                print(f"  {idx}: {acc.get('email')}")
            
            # 检查账户数据是否有效
            if email == "正在加载账户信息..." or not email:
                return json.dumps({
                    "status": "error", 
                    "message": "账户信息正在加载中，请稍后再试"
                })
            
            # 检查Cursor是否正在运行
            cursor_was_running = False
            if is_cursor_running():
                cursor_was_running = True
                # 提示用户关闭Cursor
                self.show_message_signal.emit(
                    "需要关闭Cursor",
                    "切换账户前需要关闭Cursor。正在自动关闭...",
                    False
                )
                
                # 关闭Cursor
                if not kill_cursor_process():
                    return json.dumps({
                        "status": "error", 
                        "message": "无法关闭Cursor进程，请手动关闭后再试"
                    })
                
                # 等待进程完全关闭
                time.sleep(2)
            else:
                print("Cursor进程未在运行，无需关闭")
            
            try:
                # 首先从当前选中账户的cookie中提取token
                original_token = ""
                
                print("尝试从选中账户的cookie中提取令牌...")
                if cookie:
                    # 移除所有可能的前缀
                    token = cookie
                    if "WorkosCursorSessionToken=" in token:
                        token = token.split("WorkosCursorSessionToken=", 1)[1]
                    if token.startswith("user_01000000000000000000000000%3A%3A"):
                        token = token[len("user_01000000000000000000000000%3A%3A"):]
                    original_token = token
                    print(f"从cookie中提取的令牌: {original_token[:20]}...{original_token[-10:] if len(original_token) > 30 else ''}")
                
                # 如果从cookie中无法提取，尝试从本地agent.txt文件中读取
                if not original_token:
                    print("从cookie中未能提取到令牌，尝试从本地agent.txt文件中读取...")
                    current_dir = os.path.dirname(os.path.abspath(__file__))
                    agent_file = os.path.join(current_dir, "agent.txt")
                    
                    if os.path.exists(agent_file):
                        with open(agent_file, 'r', encoding='utf-8') as file:
                            for line in file:
                                line = line.strip()
                                if line and '|' in line:
                                    parts = line.split('|', 1)
                                    line_email = parts[0].strip()
                                    if line_email == email:  # 找到匹配的邮箱
                                        original_token = parts[1].strip()  # 获取原始令牌
                                        print(f"从本地文件找到的令牌: {original_token[:20]}...{original_token[-10:] if len(original_token) > 30 else ''}")
                                        break
                
                # 如果仍然没有找到令牌，尝试直接从网络API获取
                if not original_token:
                    print("从本地文件未能找到令牌，尝试从网络获取...")
                    try:
                        agent_url = "http://43.224.225.188/agent.txt"
                        response = requests.get(agent_url, timeout=10)
                        if response.status_code == 200:
                            agent_content = response.text
                            for line in agent_content.splitlines():
                                line = line.strip()
                                if line and '|' in line:
                                    parts = line.split('|', 1)
                                    line_email = parts[0].strip()
                                    if line_email == email:  # 找到匹配的邮箱
                                        original_token = parts[1].strip()  # 获取原始令牌
                                        print(f"从网络API找到的令牌: {original_token[:20]}...{original_token[-10:] if len(original_token) > 30 else ''}")
                                        break
                    except Exception as e:
                        print(f"从网络获取令牌失败: {e}")
                
                # 检查是否存在必要的信息
                if not email or not original_token:
                    print("❌ 无法获取账户的令牌信息")
                    return json.dumps({
                        "status": "error", 
                        "message": "账户信息不完整，缺少邮箱或认证令牌"
                    })
                
                # 打印将要使用的完整令牌
                print(f"将使用的令牌值: {original_token[:20]}...{original_token[-10:] if len(original_token) > 30 else ''}")
                
                auth_manager = CursorAuth()
                
                # 检查数据库文件是否存在
                if not os.path.exists(auth_manager.db_path):
                    print(f"错误: Cursor数据库文件不存在于 {auth_manager.db_path}")
                    return json.dumps({
                        "status": "error", 
                        "message": "未找到Cursor数据库文件，请确保Cursor已安装"
                    })
                
                # 更新认证信息 - 使用原始令牌
                result = auth_manager.update_auth(
                    email=email,
                    access_token=original_token,
                    refresh_token=original_token
                )
                
                if result:
                    print("✅ Cursor认证信息更新成功!")
                    
                    # 确保将当前切换的账户放到首位
                    print("账户列表重排开始")
                    # 使用邮箱为标识，从accounts_data中删除已存在的相同邮箱的账户
                    to_keep = selected_account  # 保存要保留的完整账户对象
                    remaining_accounts = [acc for acc in self.accounts_data if acc.get("email") != email]
                    
                    # 将当前账户放在首位
                    self.accounts_data = [to_keep] + remaining_accounts
                    
                    # 更新全局账户列表
                    global accounts
                    accounts = self.accounts_data
                    
                    print("账户列表重排后:")
                    for idx, acc in enumerate(self.accounts_data):
                        print(f"  {idx}: {acc.get('email')}")
                    
                    print(f"账户 {email} 已移至账户列表首位")
                    
                    # 如果Cursor之前在运行，则重新启动它
                    if cursor_was_running:
                        time.sleep(1)  # 短暂等待确保数据库写入完成
                        if start_cursor_process():
                            return json.dumps({
                                "status": "success", 
                                "message": f"已切换到账户 {email}\nCursor认证信息已更新，已重新启动Cursor"
                            })
                        else:
                            return json.dumps({
                                "status": "partial_success", 
                                "message": f"已切换到账户 {email}\nCursor认证信息已更新，但无法自动重启Cursor，请手动启动"
                            })
                    else:
                        return json.dumps({
                            "status": "success", 
                            "message": f"已切换到账户 {email}\nCursor认证信息已更新"
                        })
                else:
                    print("❌ Cursor认证信息更新失败")
                    return json.dumps({
                        "status": "error", 
                        "message": f"已选择账户 {email}，但Cursor认证信息更新失败"
                    })
                    
            except Exception as e:
                print(f"切换账户时发生错误: {e}")
                import traceback
                traceback.print_exc()
                return json.dumps({
                    "status": "error", 
                    "message": f"切换账户时发生错误: {str(e)}"
                })
        
        return json.dumps({
            "status": "error", 
            "message": "无效的账户ID"
        })
    
    @pyqtSlot(result=str)
    def refreshAccounts(self):
        # 重新异步读取账户数据
        self.accounts_data = [{
            "email": "正在刷新账户信息...",
            "cookie": "",
            "machine_code": DEVICE_MACHINE_CODE,
            "advanced_model": "...",
            "basic_model": "...",
            "last_used": "正在加载...",
            "api_data": None
        }]
        
        # 立即返回临时状态并开始异步加载
        temp_result = json.dumps({
            "status": "loading", 
            "accounts": self.accounts_data
        })
        
        # 启动异步加载
        self.start_async_accounts_loading()
        
        return temp_result
    
    @pyqtSlot(str)
    def navigateTo(self, page):
        """导航到指定页面"""
        try:
            if page == self.current_page:
                return
            
            # 检查是否是特殊图标
            special_pages = ["timer", "settings", "back", "history"]
            
            # 主页导航处理
            if page == "home":
                self.current_page = page
                self.window.load_home_page()
            # 历史账户导航处理
            elif page == "history":
                self.current_page = page
                self.window.load_history_page()
            # 其他页面显示"暂未开发"提示
            else:
                # 所有其他页面暂未开发
                self.show_message_signal.emit(
                    "功能提示",
                    "此功能暂未开发，敬请期待！",
                    False
                )
                print(f"页面 {page} 暂未开发")
        except KeyboardInterrupt:
            print("导航被用户中断")
        except Exception as e:
            print(f"导航过程中出错: {e}")

    @pyqtSlot()
    def minimizeWindow(self):
        self.window.showMinimized()
    
    @pyqtSlot()
    def closeWindow(self):
        self.window.close()
        
    @pyqtSlot()
    def switchAccountFull(self):
        """切换账号和机器码"""
        self.show_message_signal.emit(
            "功能提示",
            "此功能暂未开发，敬请期待！",
            False
        )
        print("切换账号和机器码功能待实现")
    
    @pyqtSlot()
    def switchAccountOnly(self):
        """访问官网"""
        try:
            url = "http://cursor.geekrcloud.cn/"
            print(f"正在打开官网: {url}")
            
            # 根据操作系统选择不同的方式打开浏览器
            if platform.system() == 'Windows':
                import webbrowser
                webbrowser.open(url)
            elif platform.system() == 'Darwin':  # macOS
                subprocess.Popen(['open', url])
            else:  # Linux
                subprocess.Popen(['xdg-open', url])
            
            self.show_message_signal.emit(
                "访问官网",
                "已在浏览器中打开官网",
                False
            )
        except Exception as e:
            print(f"打开官网时出错: {e}")
            self.show_message_signal.emit(
                "操作失败",
                f"打开官网时出错: {str(e)}",
                True
            )
    
    @pyqtSlot()
    def changeMachineCode(self):
        """更换机器码"""
        if not is_admin():
            self.show_message_signal.emit(
                "需要管理员权限",
                "请以管理员身份重新启动应用后再尝试此功能。",
                True  # 是错误消息
            )
            return
            
        # 检查Cursor是否在运行
        if is_cursor_running():
            reply = QMessageBox.question(
                self.window, 
                "检测到Cursor在运行", 
                "需要关闭Cursor才能继续。是否要强制关闭Cursor进程？",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                if not kill_cursor_process():
                    self.show_message_signal.emit(
                        "操作失败",
                        "无法终止Cursor进程，请手动关闭后再试。",
                        True
                    )
                    return
                # 等待进程完全终止
                time.sleep(2)
            else:
                self.show_message_signal.emit(
                    "操作取消",
                    "请先关闭Cursor后再尝试更换机器码。",
                    True
                )
                return
        
        # 确认是否继续
        reply = QMessageBox.warning(
            self.window,
            "确认更换机器码",
            "此操作将重置您的Cursor机器码和相关标识。这可能会影响您的授权状态。\n\n确定要继续吗？",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply != QMessageBox.Yes:
            return
            
        # 在新线程中执行PowerShell脚本
        thread = threading.Thread(target=self._run_reset_script)
        thread.daemon = True
        thread.start()
        
        # 显示等待消息
        self.show_message_signal.emit(
            "正在更换机器码",
            "请等待操作完成，这可能需要一些时间...",
            False
        )
    
    def _run_reset_script(self):
        """在线程中运行重置脚本"""
        try:
            print("\n" + "="*50)
            print("【开始】Cursor机器码更换过程")
            print("="*50)
            print("1. 准备临时PowerShell脚本...")
            
            # 将脚本内容保存到临时文件
            temp_dir = os.environ.get('TEMP', '.')
            if not os.path.exists(temp_dir):
                temp_dir = '.'
            
            temp_script = os.path.join(temp_dir, 'cursor_reset.ps1')
            with open(temp_script, 'w', encoding='utf-8') as f:
                f.write(CURSOR_RESET_SCRIPT)
            
            print(f"- 临时脚本已保存到: {temp_script}")
            print("- PowerShell脚本将执行以下操作:")
            print("  • 生成新的机器ID和MAC机器ID")
            print("  • 备份当前的MachineGuid到用户主目录")
            print("  • 更新storage.json文件中的telemetry信息")
            print("  • 更新Windows注册表中的MachineGuid")
            
            print("\n2. 正在执行PowerShell脚本...")
            print("-"*40 + "脚本输出开始" + "-"*40)
            
            # 使用Popen实时显示输出
            process = subprocess.Popen(
                ['powershell', '-ExecutionPolicy', 'Bypass', '-File', temp_script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1  # 行缓冲
            )
            
            # 实时读取标准输出
            for line in process.stdout:
                print(line.strip())
            
            # 等待进程完成
            return_code = process.wait()
            
            # 检查错误输出
            error_output = process.stderr.read()
            if error_output:
                print("\n错误输出:")
                print(error_output)
            
            print("-"*40 + "脚本输出结束" + "-"*40)
            
            # 删除临时文件
            if os.path.exists(temp_script):
                os.remove(temp_script)
                print("\n3. 清理工作:")
                print("- 临时脚本文件已删除")
            
            if return_code == 0:
                # 成功
                print("\n4. 操作结果: 成功")
                print("- 已成功更换机器码")
                print("- 下次启动Cursor时，您将使用新的机器标识")
                print("="*50)
                print("【完成】Cursor机器码更换过程")
                print("="*50)
                
                self.show_message_signal.emit(
                    "操作成功",
                    "机器码已成功更换。请重启Cursor应用。",
                    False
                )
                # 发送重置完成信号
                self.reset_complete_signal.emit()
            else:
                # 失败
                print(f"\n4. 操作结果: 失败 (返回代码: {return_code})")
                print("- 机器码更换过程中出现错误")
                print("="*50)
                print("【失败】Cursor机器码更换过程")
                print("="*50)
                
                self.show_message_signal.emit(
                    "操作失败",
                    f"机器码更换失败，返回代码: {return_code}",
                    True
                )
        except Exception as e:
            print("\n操作过程中发生异常:")
            print(f"- 错误信息: {str(e)}")
            import traceback
            traceback.print_exc()
            print("="*50)
            print("【异常】Cursor机器码更换过程")
            print("="*50)
            
            self.show_message_signal.emit(
                "操作失败",
                f"执行脚本时出错: {str(e)}",
                True
            )
    
    @pyqtSlot()
    def contactUs(self):
        """联系我们"""
        try:
            # 图片路径
            image_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "1.jpg")
            
            # 如果当前目录下没有图片，则尝试使用绝对路径
            if not os.path.exists(image_path):
                image_path = r"C:\Users\huiye\Desktop\cursor  geek\1.jpg"
            
            if os.path.exists(image_path):
                print(f"正在打开图片: {image_path}")
                # 根据操作系统选择不同的方式打开图片
                if platform.system() == 'Windows':
                    os.startfile(image_path)
                elif platform.system() == 'Darwin':  # macOS
                    subprocess.Popen(['open', image_path])
                else:  # Linux
                    subprocess.Popen(['xdg-open', image_path])
                
                self.show_message_signal.emit(
                    "联系方式",
                    "已打开联系方式图片",
                    False
                )
            else:
                print(f"错误: 无法找到图片文件: {image_path}")
                self.show_message_signal.emit(
                    "错误",
                    f"无法找到图片文件: {image_path}",
                    True
                )
        except Exception as e:
            print(f"打开图片时出错: {e}")
            self.show_message_signal.emit(
                "操作失败",
                f"打开图片时出错: {str(e)}",
                True
            )

    @pyqtSlot()
    def navigateToTimer(self):
        """计时器页面"""
        print("\n" + "="*50)
        print("navigateToTimer方法被调用")
        self.show_message_signal.emit(
            "功能提示",
            "此功能暂未开发，敬请期待！",
            False
        )
        print("计时器页面暂未开发")

    @pyqtSlot()
    def navigateToSettings(self):
        """设置页面"""
        print("\n" + "="*50)
        print("navigateToSettings方法被调用")
        self.show_message_signal.emit(
            "功能提示",
            "此功能暂未开发，敬请期待！",
            False
        )
        print("设置页面暂未开发")

    @pyqtSlot()
    def navigateToBack(self):
        """返回功能"""
        print("\n" + "="*50)
        print("navigateToBack方法被调用")
        self.show_message_signal.emit(
            "功能提示",
            "此功能暂未开发，敬请期待！",
            False
        )
        print("返回功能暂未开发")

    @pyqtSlot(str)
    def handleNavButtonClick(self, buttonId):
        """处理导航按钮点击"""
        print(f"\n=== 导航按钮点击: {buttonId} ===")
        
        if buttonId == "home":
            self.navigateTo("home")
        elif buttonId == "history":
            self.navigateTo("history")
        else:
            # 所有其他按钮都显示"暂未开发"提示
            self.show_message_signal.emit(
                "功能提示",
                "此功能暂未开发，敬请期待！",
                False
            )
            print(f"功能 {buttonId} 暂未开发")

# 自定义WebEnginePage禁用右键菜单
class NoRightClickWebEnginePage(QWebEnginePage):
    def __init__(self, profile, parent=None):
        super().__init__(profile, parent)
        # 注入JavaScript以禁用HTML内容中的右键菜单
        self.scripts = QWebEngineProfile.defaultProfile().scripts()
        self.init_script()
    
    def init_script(self):
        """注入禁用右键菜单的JavaScript脚本"""
        script = QWebEngineScript()
        script.setName("disableContextMenu")
        script.setSourceCode("""
            // 禁用上下文菜单（右键菜单）
            document.addEventListener('contextmenu', function(e) {
                e.preventDefault();
                return false;
            }, true);
            
            // 禁用选择文本
            document.addEventListener('selectstart', function(e) {
                e.preventDefault();
                return false;
            }, true);
            
            // 禁用复制事件
            document.addEventListener('copy', function(e) {
                e.preventDefault();
                return false;
            }, true);
            
            // 禁用其他可能的菜单触发方式
            document.addEventListener('keydown', function(e) {
                // 禁用组合键如 Ctrl+Shift+I（开发者工具）等
                if ((e.ctrlKey && (e.keyCode === 73 || e.keyCode === 83 || e.keyCode === 85)) || 
                    e.keyCode === 123) {
                    e.preventDefault();
                    return false;
                }
            }, true);
            
            // 在文档加载完成后处理导航按钮点击
            document.addEventListener('DOMContentLoaded', function() {
                // 计时器按钮
                var timerButton = document.querySelector('.nav-timer');
                if (timerButton) {
                    timerButton.addEventListener('click', function() {
                        if (window.pybridge) {
                            window.pybridge.navigateToTimer();
                        }
                    });
                }
                
                // 设置按钮
                var settingsButton = document.querySelector('.nav-settings');
                if (settingsButton) {
                    settingsButton.addEventListener('click', function() {
                        if (window.pybridge) {
                            window.pybridge.navigateToSettings();
                        }
                    });
                }
                
                // 返回按钮
                var backButton = document.querySelector('.nav-back');
                if (backButton) {
                    backButton.addEventListener('click', function() {
                        if (window.pybridge) {
                            window.pybridge.navigateToBack();
                        }
                    });
                }
                
                // 通用解决方案：为所有侧边栏导航按钮添加事件监听
                var allNavButtons = document.querySelectorAll('.sidebar-nav button, .sidebar-nav a, .nav-item');
                allNavButtons.forEach(function(button) {
                    button.addEventListener('click', function(e) {
                        // 防止默认事件和冒泡
                        e.preventDefault();
                        e.stopPropagation();
                        
                        // 获取按钮ID或类名，用于标识是哪个按钮
                        var id = this.id || this.className;
                        console.log('导航按钮点击:', id);
                        
                        // 调用Python方法
                        if (window.pybridge) {
                            if (id.includes('timer') || this.querySelector('.fa-clock-o')) {
                                window.pybridge.navigateToTimer();
                            } else if (id.includes('settings') || this.querySelector('.fa-cog')) {
                                window.pybridge.navigateToSettings();
                            } else if (id.includes('back') || this.querySelector('.fa-arrow-left')) {
                                window.pybridge.navigateToBack();
                            } else if (id.includes('home')) {
                                window.pybridge.navigateTo('home');
                            } else if (id.includes('history')) {
                                window.pybridge.navigateTo('history');
                            } else {
                                // 其他未定义的按钮
                                window.pybridge.handleNavButtonClick(id);
                            }
                        }
                    });
                });
            });
        """)
        script.setWorldId(QWebEngineScript.MainWorld)
        script.setInjectionPoint(QWebEngineScript.DocumentCreation)
        script.setRunsOnSubFrames(True)
        self.scripts.insert(script)
    
    def createStandardContextMenu(self):
        # 返回空菜单以禁用右键
        menu = QMenu()
        return menu
    
    def javaScriptConsoleMessage(self, level, message, lineNumber, sourceID):
        # 屏蔽JavaScript控制台消息，使界面更干净
        pass
    
    def certificateError(self, error):
        # 忽略证书错误
        return True
    
    def acceptNavigationRequest(self, url, type, isMainFrame):
        # 允许所有导航请求
        return True

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cursor Agent")
        self.setMinimumSize(1400, 900)
        self.resize(1400, 900)
        self.setWindowFlags(Qt.FramelessWindowHint)  # 无边框窗口
        
        # 创建主窗口容器和布局
        self.central_widget = QWidget()
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)
        
        # 创建标题栏区域用于拖动
        self.title_bar = QFrame()
        self.title_bar.setFixedHeight(30)  # 标题栏高度
        self.title_bar.setStyleSheet("background-color: transparent;")
        self.title_bar.setCursor(Qt.ArrowCursor)
        self.title_bar.mousePressEvent = self.title_bar_mouse_press
        self.title_bar.mouseMoveEvent = self.title_bar_mouse_move
        self.title_bar.mouseReleaseEvent = self.title_bar_mouse_release
        
        # 添加到主布局
        self.main_layout.addWidget(self.title_bar)

        # 创建WebView
        self.web_view = QWebEngineView()
        self.web_view.setContextMenuPolicy(Qt.NoContextMenu)  # 设置WebView不显示上下文菜单
        
        # 设置自定义页面以禁用右键菜单
        profile = QWebEngineProfile.defaultProfile()
        custom_page = NoRightClickWebEnginePage(profile, self.web_view)
        self.web_view.setPage(custom_page)
        
        # 创建WebChannel用于与JavaScript通信
        self.channel = QWebChannel()
        self.bridge = Bridge(self)
        self.channel.registerObject("pybridge", self.bridge)
        self.web_view.page().setWebChannel(self.channel)
        
        # 将WebView添加到布局
        self.main_layout.addWidget(self.web_view)

        # 默认加载首页
        self.load_home_page()
        
        # 设置中央部件
        self.setCentralWidget(self.central_widget)
        
        # 允许窗口拖动
        self.oldPos = None
        
        # 创建系统托盘
        self.setup_tray_icon()
        
        # 应用全局事件过滤器
        self.installEventFilter(self)
        self.web_view.installEventFilter(self)
    
    # 标题栏鼠标事件处理 - 用于拖动窗口
    def title_bar_mouse_press(self, event):
        if event.button() == Qt.LeftButton:
            self.oldPos = event.globalPos()
    
    def title_bar_mouse_move(self, event):
        if self.oldPos:
            delta = event.globalPos() - self.oldPos
            self.move(self.x() + delta.x(), self.y() + delta.y())
            self.oldPos = event.globalPos()
    
    def title_bar_mouse_release(self, event):
        if event.button() == Qt.LeftButton:
            self.oldPos = None
    
    def eventFilter(self, obj, event):
        """全局事件过滤器，用于捕获所有右键事件"""
        if event.type() == QContextMenuEvent.ContextMenu:
            return True  # 拦截所有上下文菜单事件
        return super().eventFilter(obj, event)
    
    # 禁止主窗口的右键菜单
    def contextMenuEvent(self, event: QContextMenuEvent):
        # 拦截右键菜单事件，不执行任何操作
        event.accept()  # 使用accept而不是ignore来确保事件不会传递
        
    def load_home_page(self):
        """加载首页"""
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            html_path = os.path.join(current_dir, "homepage.html")
            if os.path.exists(html_path):
                self.web_view.load(QUrl.fromLocalFile(html_path))
                self.bridge.current_page = "home"
            else:
                print(f"错误: 首页文件不存在: {html_path}")
        except Exception as e:
            print(f"加载首页时出错: {e}")
        
    def load_history_page(self):
        """加载历史账户页面"""
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            html_path = os.path.join(current_dir, "embedded.html")
            if os.path.exists(html_path):
                self.web_view.load(QUrl.fromLocalFile(html_path))
                self.bridge.current_page = "history"
            else:
                print(f"错误: 历史页面文件不存在: {html_path}")
        except Exception as e:
            print(f"加载历史页面时出错: {e}")
        
    def setup_tray_icon(self):
        """设置系统托盘图标"""
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
        
        # 创建托盘菜单
        tray_menu = QMenu()
        
        show_action = QAction("显示窗口", self)
        show_action.triggered.connect(self.show)
        
        exit_action = QAction("退出", self)
        exit_action.triggered.connect(self.quit_app)
        
        tray_menu.addAction(show_action)
        tray_menu.addSeparator()
        tray_menu.addAction(exit_action)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self.tray_icon_activated)
        self.tray_icon.show()
        
    def tray_icon_activated(self, reason):
        """处理托盘图标点击事件"""
        if reason == QSystemTrayIcon.DoubleClick:
            self.show()
            
    def quit_app(self):
        """完全退出应用"""
        QApplication.quit()
        
    def closeEvent(self, event):
        """窗口关闭事件"""
        # 最小化到托盘
        event.ignore()
        self.hide()
        
    def show_message(self, title, message, is_error=False):
        """显示消息对话框"""
        if is_error:
            QMessageBox.critical(self, title, message)
        else:
            QMessageBox.information(self, title, message)
    
    def reload_after_reset(self):
        """重置完成后重新加载数据"""
        # 重新加载数据，刷新机器码显示
        global accounts
        accounts = read_accounts_from_file()
        self.bridge.accounts_data = accounts
        
        # 重新加载当前页面
        if self.bridge.current_page == "home":
            self.load_home_page()
        else:
            self.load_history_page()

# 启动Cursor应用程序
def start_cursor_process():
    try:
        if platform.system() == 'Windows':
            # 获取Cursor可能的安装路径
            cursor_path = ""
            possible_paths = [
                os.path.join(os.environ.get('LOCALAPPDATA', ''), "Programs", "Cursor", "Cursor.exe"),
                os.path.join(os.environ.get('PROGRAMFILES', ''), "Cursor", "Cursor.exe"),
                os.path.join(os.environ.get('PROGRAMFILES(X86)', ''), "Cursor", "Cursor.exe")
            ]
            
            for path in possible_paths:
                if os.path.exists(path):
                    cursor_path = path
                    break
            
            if cursor_path:
                print(f"正在启动Cursor: {cursor_path}")
                # 使用subprocess启动Cursor，不等待返回
                subprocess.Popen(cursor_path, shell=True)
                return True
            else:
                print("未找到Cursor可执行文件")
                return False
        else:
            print("暂不支持在此系统上启动Cursor")
            return False
    except Exception as e:
        print(f"启动Cursor时出错: {e}")
        return False

if __name__ == "__main__":
    try:
        # 设置一些环境变量，解决缓存问题
        os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = "--disable-gpu"
        
        # 创建缓存目录
        cache_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cache")
        if not os.path.exists(cache_dir):
            try:
                os.makedirs(cache_dir)
                print(f"已创建缓存目录: {cache_dir}")
            except Exception as e:
                print(f"创建缓存目录失败: {e}")
        
        app = QApplication(sys.argv)
        # 设置应用属性，帮助解决缓存问题
        app.setApplicationName("CursorAgent")
        app.setOrganizationName("CAOrg")
        
        window = MainWindow()
        window.show()
        sys.exit(app.exec_())
    except KeyboardInterrupt:
        print("\n程序被用户中断")
        sys.exit(0)
    except Exception as e:
        print(f"程序发生错误: {e}")
        sys.exit(1) 
