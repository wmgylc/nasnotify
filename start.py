import os
import time
from zspace import process_zspace
from ugreen import process_ugreen

# 从环境变量获取间隔时间，单位：分钟
INTERVAL_MINUTES = int(os.getenv('INTERVAL_MINUTES', 5))

while True:
    process_zspace()
    process_ugreen()
    time.sleep(INTERVAL_MINUTES * 60)