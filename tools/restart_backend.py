# P0-1 工程收敛注入：统一路径引导（原脚本逻辑根目录）
import os as _os, sys as _sys
_BASE_DIR = r"x:\ZuoYe\揭榜挂帅26\Gov-Com-safeagent\ai_service"
_sys.path.insert(0, _BASE_DIR)
"""
重启后端服务脚本
"""
import psutil
import os
import sys
import time

def find_process_on_port(port):
    """查找占用指定端口的进程"""
    for conn in psutil.net_connections():
        if conn.laddr.port == port and conn.status == 'LISTEN':
            return conn.pid
    return None

def kill_process(pid):
    """终止进程"""
    try:
        process = psutil.Process(pid)
        print(f"找到进程 PID={pid}, 名称={process.name()}")
        process.terminate()
        
        # 等待进程结束
        try:
            process.wait(timeout=5)
            print(f"✅ 进程 {pid} 已成功终止")
            return True
        except psutil.TimeoutExpired:
            print(f"进程 {pid} 未响应，强制结束...")
            process.kill()
            process.wait(timeout=3)
            print(f"✅ 进程 {pid} 已强制终止")
            return True
    except psutil.NoSuchProcess:
        print(f"进程 {pid} 不存在")
        return False
    except Exception as e:
        print(f"❌ 终止进程失败: {e}")
        return False

def main():
    print("=" * 60)
    print("后端服务重启脚本")
    print("=" * 60)
    
    # 查找占用8080端口的进程
    print("\n[1] 检查端口 8080...")
    pid = find_process_on_port(8080)
    
    if pid:
        print(f"⚠️  发现进程正在使用端口 8080 (PID={pid})")
        print(f"[2] 停止旧服务...")
        if kill_process(pid):
            print("✅ 旧服务已停止")
            time.sleep(2)  # 等待端口释放
        else:
            print("❌ 无法停止旧服务，请手动终止")
            sys.exit(1)
    else:
        print("✅ 端口 8080 未被占用")
    
    print("\n[3] 准备启动新服务...")
    print("提示：新服务将在独立进程中启动")
    print("\n请在命令行执行：")
    print("  cd Gov-Com-safeagent/ai_service")
    print("  python -X utf8 main.py")
    print("\n或者让Kiro帮您启动服务")
    print("=" * 60)

if __name__ == "__main__":
    main()
