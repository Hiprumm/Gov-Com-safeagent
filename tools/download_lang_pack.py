# P0-1 工程收敛注入：统一路径引导（原脚本逻辑根目录）
import os as _os, sys as _sys
_BASE_DIR = r"x:\ZuoYe\揭榜挂帅26\Gov-Com-safeagent\ai_service"
_sys.path.insert(0, _BASE_DIR)
#!/usr/bin/env python3
"""
下载Tesseract中文语言包脚本
由于网络环境限制，可能需要在有外网访问权限的环境下运行
"""

import urllib.request
import os
import sys

def download_language_pack():
    # Tesseract安装路径（自动检测）
    tess_paths = [
        r'C:\Program Files\Tesseract-OCR\tesseract.exe',
        r'C:\Program Files (x86)\Tesseract-OCR\tesseract.exe',
        r'D:\Program Files\Tesseract-OCR\tesseract.exe',
    ]
    
    tesseract_cmd = None
    for path in tess_paths:
        if os.path.exists(path):
            tesseract_cmd = path
            break
    
    if not tesseract_cmd:
        print("错误：未找到Tesseract-OCR安装路径")
        print("请手动指定路径：")
        tesseract_cmd = input("输入tesseract.exe路径: ").strip()
        if not os.path.exists(tesseract_cmd):
            print("路径不存在，退出")
            sys.exit(1)
    
    tessdata_dir = os.path.join(os.path.dirname(tesseract_cmd), 'tessdata')
    save_path = os.path.join(tessdata_dir, 'chi_sim.traineddata')
    
    print(f"\n语言包保存路径: {save_path}")
    print(f"Tesseract路径: {tesseract_cmd}")
    
    # 镜像源列表（按成功率排序）
    mirrors = [
        'https://raw.githubusercontent.com/tesseract-ocr/tessdata/main/chi_sim.traineddata',
        'https://ghproxy.com/https://raw.githubusercontent.com/tesseract-ocr/tessdata/main/chi_sim.traineddata',
        'https://cdn.jsdelivr.net/gh/tesseract-ocr/tessdata@main/chi_sim.traineddata',
        'https://raw.fastgit.org/tesseract-ocr/tessdata/main/chi_sim.traineddata',
        'https://gitee.com/mirrors/tessdata/raw/main/chi_sim.traineddata',
        'https://gitee.com/knowyourself/ocr_models/raw/master/tessdata/chi_sim.traineddata',
    ]
    
    print("\n开始尝试下载中文语言包...")
    success = False
    
    for i, url in enumerate(mirrors, 1):
        try:
            print(f"\n[{i}/{len(mirrors)}] 尝试: {url}")
            
            # 设置超时时间
            opener = urllib.request.build_opener()
            opener.addheaders = [('User-agent', 'Mozilla/5.0')]
            urllib.request.install_opener(opener)
            
            urllib.request.urlretrieve(url, save_path, reporthook=progress_callback)
            
            if os.path.exists(save_path):
                file_size = os.path.getsize(save_path)
                if file_size > 1000000:  # 至少1MB才可能是有效的语言包
                    print(f"\n✓ 下载成功! 文件大小: {file_size / 1024 / 1024:.2f} MB")
                    success = True
                else:
                    print(f"✗ 文件太小，可能是错误页面 ({file_size} bytes)")
                    os.remove(save_path)
            break
            
        except Exception as e:
            print(f"✗ 下载失败: {str(e)[:100]}")
    
    if success:
        print("\n" + "="*50)
        print("中文语言包安装成功!")
        print("请重启FastAPI服务后测试图片OCR功能")
        print("="*50)
    else:
        print("\n" + "="*50)
        print("所有镜像源下载失败，请尝试以下方法：")
        print("1. 手动下载 chi_sim.traineddata")
        print("   地址: https://github.com/tesseract-ocr/tessdata/blob/main/chi_sim.traineddata")
        print("2. 复制到以下目录:")
        print(f"   {tessdata_dir}")
        print("3. 重启FastAPI服务")
        print("="*50)

def progress_callback(block_num, block_size, total_size):
    """下载进度回调"""
    if total_size > 0:
        percent = min(100, int(block_num * block_size / total_size * 100))
        sys.stdout.write(f"\r进度: {percent}% ({(block_num * block_size)/1024/1024:.1f}MB / {total_size/1024/1024:.1f}MB)")
        sys.stdout.flush()

if __name__ == "__main__":
    download_language_pack()
