from func import *

# 从环境变量获取配置
UGREEN_CONFIGS = json.loads(os.getenv('UGREEN_CONFIGS', '[]'))

def process_ugreen():
    if not UGREEN_CONFIGS:
        return  print("无绿联配置")# 没有配置则不执行
    log_dir = "log"
    os.makedirs(log_dir, exist_ok=True)
    for config in UGREEN_CONFIGS:
        username = config.get('username')
        ip = config.get('ip')
        password = config.get('password')
        file_path = os.path.join(log_dir, f"{ip}.log")
        notify_type_name = "绿联云"+ip
        token = get_token(username, ip)
        login_result = login(username, ip, jiami(token, password))
        public_key = login_result['data']['public_key']
        token = login_result['data']['token']
        token = jiami(public_key, token)
        token_id = login_result['data']['token_id']
        response_data = ugreen_notify(token_id, token, ip)
        notice_list = response_data.get('data', {}).get('List', [])
        last_timestamp = get_last_timestamp(file_path)
        new_notices = []

        if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
            # 不存在文件或者文件为空，插入所有数据
            save_notifications(notice_list, file_path)
            log_content, line_count = read_notification(file_path)
            if log_content:
                # 调用 wxpush 发送内容
                lly_wxpush(log_content, line_count, notify_type_name, WXPUSH_SPT)
                print("新增通知")
        else:
            for item in notice_list:
                timestamp = item.get('time', 0)
                if timestamp > last_timestamp:
                    new_notices.append(item)
            if new_notices:
                # 有更新数据，清空文件并插入更新部分
                save_notifications(new_notices, file_path)
                log_content, line_count = read_notification(file_path)
                if log_content:
                    # 调用 wxpush 发送内容
                    lly_wxpush(log_content, line_count, notify_type_name, WXPUSH_SPT)
                    print("清空文件，新增通知。")
            else:
                print("没有新的通知。")
if __name__ == "__main__":
    process_ugreen()