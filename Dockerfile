# 使用 Python 基础镜像
FROM python:3.9-slim

# 设置工作目录
WORKDIR /app

# 复制依赖文件
COPY requirements.txt .

# 安装依赖
RUN pip install --no-cache-dir -r requirements.txt

# 复制项目文件
COPY zspace.py .
COPY func.py .
COPY ugreen.py .
COPY run_scheduler.py .

# 设置默认环境变量
ENV ZSPACE_CONFIGS='[]'
ENV UGREEN_CONFIGS='[]'
ENV WXPUSH_SPT=''
ENV INTERVAL_MINUTES=5

# 运行定时任务脚本
CMD ["python", "start.py"]