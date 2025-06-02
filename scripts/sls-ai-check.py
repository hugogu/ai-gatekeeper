import re
import json
import os
import logging
import requests
import hashlib
from datetime import datetime, timedelta
from aliyun.log import LogClient

# Apache日志解析正则表达式
APACHE_LOG_REGEX = r'(\S+) (\S+) (\S+) \[(.*?)\] "(\S+) (\S+) (\S+)" (\d+) (\d+) "([^"]*)" "([^"]*)"'

logger = logging.getLogger()

# 缓存配置
REQUEST_CACHE = {}
CACHE_EXPIRATION = timedelta(minutes=30)
MAX_CACHE_SIZE = 1000

def parse_apache_log(log_content):
    match = re.match(APACHE_LOG_REGEX, log_content)
    if not match:
        return None
    
    return {
        'ip': match.group(1),
        'time': match.group(4),
        'method': match.group(5),
        'path': match.group(6),
        'protocol': match.group(7),
        'status': int(match.group(8)),
        'bytes_sent': int(match.group(9)),
        'referer': match.group(10),
        'user_agent': match.group(11)
    }

def get_request_signature(log):
    signature_str = f"{log['ip']}_{log['method']}_{log['path']}_{log['user_agent']}"
    return hashlib.md5(signature_str.encode()).hexdigest()

def extract_json_from_response(content):
    """从API响应中提取JSON内容，处理可能的Markdown包装"""
    try:
        # 尝试直接解析JSON
        return json.loads(content)
    except json.JSONDecodeError:
        # 如果失败，尝试提取被```json ... ```包裹的内容
        match = re.search(r'```json\s*({.*?})\s*```', content, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                logger.error(f"无法解析提取的JSON: {match.group(1)}")
        
        # 尝试提取纯JSON对象（无代码块标记）
        match = re.search(r'{\s*"is_abnormal".*?}', content, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                logger.error(f"无法解析提取的JSON: {match.group(0)}")
    
    # 如果所有尝试都失败，记录原始响应
    logger.error(f"无法解析API响应: {content}")
    return {
        "is_abnormal": False,
        "reason": f"无法解析API响应: {content[:200]}{'...' if len(content) > 200 else ''}"
    }

def analyze_with_deepseek(log):
    # 构建更严格的提示词
    prompt = f"""
你是一个网络安全分析系统，请判断以下访问行为是否异常（如暴力破解、SQL注入、爬虫等）：
[日志详情]
时间: {log['time']}
IP: {log['ip']}
方法: {log['method']}
路径: {log['path']}
状态码: {log['status']}
用户代理: {log['user_agent']}

请只返回JSON格式，不要包含任何其他文本或标记：
{{"is_abnormal": true/false, "reason": "分析原因"}}
"""
    headers = {
        "Authorization": f"Bearer {os.getenv('DEEPSEEK_API_KEY')}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "deepseek-chat",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1,
        "max_tokens": 300,
        "response_format": {"type": "json_object"}  # 明确要求JSON格式
    }
    
    try:
        logger.info(f"DeepSeek API调用，请求: {payload}")
        response = requests.post(
            "https://api.deepseek.com/chat/completions",
            json=payload,
            headers=headers,
            timeout=60
        )
        response.raise_for_status()
        result = response.json()
        logger.info(f"DeepSeek API调用成功，返回结果: {result}")
        
        # 提取并处理内容
        content = result['choices'][0]['message']['content'].strip()
        return extract_json_from_response(content)
    except Exception as e:
        logger.error(f"DeepSeek API调用失败: {str(e)}")
        return {
            "is_abnormal": False,
            "reason": f"API调用失败: {str(e)}"
        }

def process_log_entry(log):
    signature = get_request_signature(log)
    current_time = datetime.now()
    
    if signature in REQUEST_CACHE:
        cached_entry = REQUEST_CACHE[signature]
        if current_time - cached_entry['timestamp'] < CACHE_EXPIRATION:
            logger.info(f"使用缓存结果: {signature}")
            return cached_entry['result']
    
    # 缓存未命中或过期
    result = analyze_with_deepseek(log)
    
    # 清理缓存
    cleanup_cache()
    
    # 存储新结果
    REQUEST_CACHE[signature] = {
        'result': result,
        'timestamp': current_time
    }
    logger.info(f"新增缓存条目: {signature}，结果: {result}")
    
    return result

def cleanup_cache():
    current_time = datetime.now()
    expired_keys = [key for key, entry in REQUEST_CACHE.items() 
                   if current_time - entry['timestamp'] > CACHE_EXPIRATION]
    
    # 删除过期条目
    for key in expired_keys:
        del REQUEST_CACHE[key]
    
    # 控制缓存大小
    if len(REQUEST_CACHE) > MAX_CACHE_SIZE:
        # 删除最旧的10%条目
        sorted_entries = sorted(REQUEST_CACHE.items(), key=lambda x: x[1]['timestamp'])
        remove_count = max(1, int(len(REQUEST_CACHE) * 0.1))
        for key, _ in sorted_entries[:remove_count]:
            del REQUEST_CACHE[key]
        logger.info(f"缓存清理: 移除了{remove_count}个旧条目")

# 主处理函数
def handler(event, context):
    creds = context.credentials
    access_key_id = creds.access_key_id
    access_key_secret = creds.access_key_secret
    security_token = creds.security_token

    event_obj = json.loads(event.decode())

    source = event_obj['source']
    log_project = source['projectName']
    log_store = source['logstoreName']
    endpoint = source['endpoint']
    begin_cursor = source['beginCursor']
    end_cursor = source['endCursor']
    shard_id = source['shardId']

    client = LogClient(endpoint=endpoint, accessKeyId=access_key_id, 
                      accessKey=access_key_secret, securityToken=security_token)

    while True:
        response = client.pull_logs(project_name=log_project, logstore_name=log_store,
                                  shard_id=shard_id, cursor=begin_cursor, count=100,
                                  end_cursor=end_cursor, compress=False)
        log_group_cnt = response.get_loggroup_count()
        
        if log_group_cnt == 0:
            break
            
        logger.info(f"从 {log_store} 获取 {log_group_cnt} 个日志组")
        
        log_group_list = response.get_loggroup_list().LogGroups
        for log_group in log_group_list:
            for log in log_group.Logs:
                log_dict = {}
                for content in log.Contents:
                    log_dict[content.Key] = content.Value
                
                # 过滤非Apache日志
                if log_dict.get('_container_name_') != "blog-apache":
                    continue
                
                logger.info(f"处理Apache访问日志: {log_dict['content']}")
                parsed_log = parse_apache_log(log_dict['content'])
                
                if parsed_log:
                    result = process_log_entry(parsed_log)
                    logger.info(f"安全分析结果: {result}")
                    # 这里可以添加结果处理逻辑
    
        begin_cursor = response.get_next_cursor()

    return 'success'
