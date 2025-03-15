import os
import sys
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager
import ssl
import time
import subprocess
import platform
import warnings

# 禁用SSL警告
warnings.filterwarnings("ignore", category=Warning)

# 强制使用TLS 1.2并允许禁用SSL验证
class TLSAdapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        self.verify = kwargs.pop('verify', True)
        super(TLSAdapter, self).__init__(*args, **kwargs)
    
    def init_poolmanager(self, *args, **kwargs):
        context = ssl.create_default_context()
        context.set_ciphers('DEFAULT:@SECLEVEL=1')
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        # 如果verify为False，禁用证书验证和主机名检查
        if not self.verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
        kwargs['ssl_context'] = context
        return super(TLSAdapter, self).init_poolmanager(*args, **kwargs)

# 检测Cursor进程是否在运行
def is_cursor_running():
    try:
        if platform.system() == 'Windows':
            output = subprocess.check_output('tasklist /FI "IMAGENAME eq cursor.exe" /NH', shell=True).decode()
            return "cursor.exe" in output
        else:
            return False  # 暂不支持其他系统
    except:
        return False

# 终止Cursor进程
def kill_cursor_process():
    try:
        if platform.system() == 'Windows':
            os.system('taskkill /F /IM cursor.exe')
            print("已强制终止Cursor进程")
            return True
        else:
            print("暂不支持在此系统上终止Cursor")
            return False
    except Exception as e:
        print(f"终止Cursor进程失败: {e}")
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

# 执行脚本，直接使用内置的PowerShell脚本
def execute_script():
    print("="*60)
    print("Cursor重置工具 - 用于重置Cursor的机器码和唯一标识")
    print("="*60)
    print("\n警告: 此工具会修改您的系统设置。使用前请确保:")
    print("1. Cursor已完全关闭")
    print("2. 您的数据已备份")
    print("3. 您正在以管理员身份运行此脚本")
    print("\n使用此工具的风险由您自行承担\n")
    
    # 检查storage.json是否存在
    storage_path = find_storage_json_path()
    if not storage_path:
        print("警告: 未找到Cursor的storage.json文件，您可能没有安装Cursor")
        choice = input("是否继续? (y/n): ").lower()
        if choice != 'y':
            return False
    
    print("使用本地保存的PowerShell脚本执行...")
    temp_script = None
    try:
        # 检查Cursor是否在运行
        if is_cursor_running():
            print("\n检测到Cursor正在运行!")
            choice = input("是否要强制终止Cursor进程? (y/n): ").lower()
            if choice == 'y':
                if not kill_cursor_process():
                    print("无法终止Cursor进程，脚本执行可能会卡住")
                    choice = input("是否继续? (y/n): ").lower()
                    if choice != 'y':
                        return False
                # 等待进程完全终止
                time.sleep(2)
            else:
                print("脚本可能会卡住直到Cursor进程关闭")
                choice = input("是否继续? (y/n): ").lower()
                if choice != 'y':
                    return False
        
        # 将脚本内容保存到临时文件
        temp_dir = os.environ.get('TEMP', '.')
        if not os.path.exists(temp_dir):
            temp_dir = '.'
        
        temp_script = os.path.join(temp_dir, 'cursor_reset.ps1')
        with open(temp_script, 'w', encoding='utf-8') as f:
            f.write(CURSOR_RESET_SCRIPT)
        
        print(f"脚本已保存到: {temp_script}")
        print("注意: 如果脚本卡住，可能是因为Cursor正在运行，请关闭Cursor后继续")
        print("按Ctrl+C可以随时中断执行")
        
        # 使用PowerShell执行脚本，实时显示输出
        import subprocess
        print("\n正在执行PowerShell脚本...\n" + "="*50)
        
        # 使用实时输出模式
        process = subprocess.Popen(
            ['powershell', '-ExecutionPolicy', 'Bypass', '-File', temp_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            bufsize=1  # 行缓冲
        )
        
        # 实时输出
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                print(output.strip())
                
        # 获取返回值
        return_code = process.poll()
        
        # 检查错误
        if return_code != 0:
            print("\n脚本执行出错:")
            for line in process.stderr:
                print(line.strip())
            return False
        
        print("="*50 + "\n")
        
        # 执行完成后删除临时文件
        if os.path.exists(temp_script):
            os.remove(temp_script)
            print("临时脚本文件已删除")
        
        return True
        
    except KeyboardInterrupt:
        print("\n\n操作已被用户中断")
        # 清理临时文件
        if temp_script and os.path.exists(temp_script):
            try:
                os.remove(temp_script)
                print("临时脚本文件已删除")
            except:
                pass
        return False
    except Exception as e:
        print(f"执行失败: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def is_admin():
    """检查是否具有管理员权限"""
    if sys.platform == 'win32':
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        # Unix/Linux系统
        return os.getuid() == 0

if __name__ == "__main__":
    # 检查管理员权限
    if not is_admin():
        print("需要管理员权限运行")
        print("请右键点击并选择'以管理员身份运行'重新启动脚本")
        input("按任意键退出...")
        sys.exit(1)
    
    success = execute_script()
    if success:
        print("Cursor重置完成！")
        print("\n请注意: 下次启动Cursor时，您可能需要重新登录")
    
    input("按任意键退出...")
