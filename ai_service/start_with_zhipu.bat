@echo off
set ZHIPUAI_API_KEY=3f21bc1fa53d4d06b576b45611e9283d.CznNwmWNlVN2cbWT
echo ZHIPU_API_KEY is set
echo Starting server...
C:\Users\lenovo\AppData\Local\Programs\Python\Python314\python.exe -m uvicorn main:app --host 0.0.0.0 --port 8000