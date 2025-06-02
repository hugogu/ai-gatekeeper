import re
import json
import os
import logging
import requests as http_requests  # 重命名以避免冲突
import hashlib
from datetime import datetime, timedelta, timezone
from aliyun.log import LogClient
from collections import defaultdict

# Apache日志解析正则表达式
APACHE_LOG_REGEX = r'(\S+) (\S+) (\S+) \[(.*?)\] "(\S+) (\S+) (\S+)" (\d+) (\d+) "([^"]*)" "([^"]*)"'

logger = logging.getLogger()
logger.setLevel(logging.INFO)  # 确保日志级别设置正确

# 聚合分析配置
IP_ANALYSIS_WINDOW = timedelta(minutes=5)  # IP分析时间窗口
MIN_REQUESTS_FOR_ANALYSIS = 5  # 触发分析的最小请求数
MAX_REQUESTS_PER_ANALYSIS = 20  # 单次分析的最大请求数

# 按IP聚合的缓冲区
ip_request_buffer = defaultdict(list)
ip_last_activity = {}

def parse_apache_log(log_content):
    match = re.match(APACHE_LOG_REGEX, log_content)
    if not match:
        return None
    
    # 解析时间字符串（带时区信息）
    log_time_str = match.group(4)
    try:
        # 尝试解析带时区的时间格式
        log_time = datetime.strptime(log_time_str, '%d/%b/%Y:%H:%M:%S %z')
    except ValueError:
        try:
            # 尝试解析不带时区的时间格式（假设为UTC）
            log_time = datetime.strptime(log_time_str, '%d/%b/%Y:%H:%M:%S').replace(tzinfo=timezone.utc)
        except Exception as e:
            logger.error(f"无法解析日志时间: {log_time_str}, 错误: {str(e)}")
            log_time = datetime.now(timezone.utc)
    
    return {
        'ip': match.group(1),
        'time': log_time,
        'method': match.group(5),
        'path': match.group(6),
        'protocol': match.group(7),
        'status': int(match.group(8)),
        'bytes_sent': int(match.group(9)),
        'referer': match.group(10),
        'user_agent': match.group(11)
    }

def extract_json_from_response(content):
    """从API响应中提取JSON内容"""
    try:
        # 尝试直接解析JSON
        return json.loads(content)
    except json.JSONDecodeError:
        # 尝试提取被```json ... ```包裹的内容
        match = re.search(r'```json\s*({.*?})\s*```', content, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                logger.error(f"无法解析提取的JSON: {match.group(1)}")
        
        # 尝试提取纯JSON对象
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

def analyze_ip_behavior(ip, ip_requests):  # 重命名参数以避免冲突
    """
    分析一个IP的多个请求行为
    :param ip: 客户端IP
    :param ip_requests: 该IP的请求列表（每个请求是解析后的日志字典）
    """
    # 构建提示词 - 关注多个请求的模式
    prompt = f"""
你是一个高级网络安全分析系统，请分析以下来自同一IP地址的多个访问行为是否异常（如扫描、暴力破解、爬虫等）。
重点关注请求模式、路径分布、频率等特征。

IP地址: {ip}
请求数量: {len(ip_requests)}

请求详情:
"""
    
    # 添加每个请求的摘要信息
    for i, req in enumerate(ip_requests[:MAX_REQUESTS_PER_ANALYSIS], 1):
        # 将aware datetime转换为字符串表示
        time_str = req['time'].strftime('%Y-%m-%d %H:%M:%S %Z')
        prompt += f"""
请求 #{i}:
  时间: {time_str}
  方法: {req['method']}
  路径: {req['path']}
  状态码: {req['status']}
  用户代理: {req['user_agent']}
"""
    
    if len(ip_requests) > MAX_REQUESTS_PER_ANALYSIS:
        prompt += f"\n...还有 {len(ip_requests) - MAX_REQUESTS_PER_ANALYSIS} 个请求未显示\n"
    
    # 添加统计分析
    unique_paths = len(set(req['path'] for req in ip_requests))
    status_codes = [req['status'] for req in ip_requests]
    success_rate = sum(1 for code in status_codes if 200 <= code < 300) / len(status_codes) if status_codes else 0
    
    # 获取时间范围字符串
    if ip_requests:
        first_time = ip_requests[0]['time'].strftime('%H:%M:%S %Z')
        last_time = ip_requests[-1]['time'].strftime('%H:%M:%S %Z')
        time_range = f"{first_time} - {last_time}"
    else:
        time_range = "N/A"
    
    prompt += f"""
统计分析:
- 请求总数: {len(ip_requests)}
- 唯一路径数: {unique_paths}
- 成功率: {success_rate:.1%}
- 时间范围: {time_range}

请从以下角度分析:
1. 是否存在扫描行为（如请求大量不同路径）
2. 是否存在暴力破解特征（如大量登录尝试）
3. 是否表现出爬虫行为模式
4. 其他可疑模式

返回JSON格式:
{{
  "is_abnormal": true/false,
  "risk_level": "low/medium/high",
  "reason": "详细分析原因",
  "patterns_found": ["扫描", "暴力破解", "爬虫", "其他"]  // 检测到的模式列表
}}
"""
    
    headers = {
        "Authorization": f"Bearer {os.getenv('DEEPSEEK_API_KEY')}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "deepseek-chat",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1,
        "max_tokens": 600,  # 增加token限制以适应更多内容
        "response_format": {"type": "json_object"}
    }
    
    try:
        logger.info(f"DeepSeek API调用 - 分析IP: {ip}, 请求数: {len(ip_requests)}")
        response = http_requests.post(  # 使用重命名的http_requests
            "https://api.deepseek.com/chat/completions",
            json=payload,
            headers=headers,
            timeout=90  # 增加超时时间
        )
        response.raise_for_status()
        result = response.json()
        logger.info(f"DeepSeek API调用成功，返回结果: {result}")
        
        content = result['choices'][0]['message']['content'].strip()
        return extract_json_from_response(content)
    except Exception as e:
        logger.error(f"DeepSeek API调用失败: {str(e)}")
        return {
            "is_abnormal": False,
            "risk_level": "unknown",
            "reason": f"API调用失败: {str(e)}",
            "patterns_found": []
        }

def process_log_entry(log):
    """
    按IP聚合日志条目
    :param log: 解析后的日志条目
    """
    ip = log['ip']
    
    # 添加到IP的请求缓冲区
    ip_request_buffer[ip].append(log)
    ip_last_activity[ip] = log['time']
    
    # 检查是否满足分析条件
    if len(ip_request_buffer[ip]) >= MIN_REQUESTS_FOR_ANALYSIS:
        return trigger_ip_analysis(ip)
    
    return None

def trigger_ip_analysis(ip):
    """
    触发对指定IP的分析
    :param ip: 要分析的IP地址
    :return: 分析结果或None
    """
    if ip not in ip_request_buffer or not ip_request_buffer[ip]:
        return None
    
    # 获取该IP的所有请求（按时间排序）
    ip_requests = sorted(ip_request_buffer[ip], key=lambda x: x['time'])
    
    # 执行分析
    analysis_result = analyze_ip_behavior(ip, ip_requests)
    
    # 记录分析结果
    logger.info(f"IP分析完成: {ip}, 结果: {analysis_result}")
    
    # 清空该IP的缓冲区（保留最近的几个请求以保持连续性）
    keep_count = min(3, len(ip_requests) // 2)  # 保留最近的部分请求
    ip_request_buffer[ip] = ip_requests[-keep_count:] if keep_count > 0 else []
    
    return analysis_result

def analyze_expired_ips(current_time):
    """
    分析时间窗口过期的IP
    :param current_time: 当前时间（带时区信息）
    :return: 分析结果列表
    """
    results = []
    ips_to_analyze = []
    
    # 找出需要分析的IP
    for ip, last_time in list(ip_last_activity.items()):
        # 确保两个时间都是aware（带时区）或都是naive（无时区）
        if hasattr(last_time, 'tzinfo') and last_time.tzinfo is not None:
            # 如果last_time是aware，确保current_time也是aware
            if not (hasattr(current_time, 'tzinfo') and current_time.tzinfo is not None):
                # 如果current_time是naive，转换为aware（假设为UTC）
                current_time = current_time.replace(tzinfo=timezone.utc)
            
            time_diff = current_time - last_time
        else:
            # 如果last_time是naive，确保current_time也是naive
            if hasattr(current_time, 'tzinfo') and current_time.tzinfo is not None:
                # 如果current_time是aware，转换为naive
                current_time = current_time.replace(tzinfo=None)
            time_diff = current_time - last_time
        
        if time_diff > IP_ANALYSIS_WINDOW and ip in ip_request_buffer:
            if len(ip_request_buffer[ip]) > 0:
                ips_to_analyze.append(ip)
    
    # 分析这些IP
    for ip in ips_to_analyze:
        result = trigger_ip_analysis(ip)
        if result:
            results.append((ip, result))
    
    return results

def get_current_utc_time():
    """获取带时区的当前UTC时间"""
    return datetime.now(timezone.utc)

# 主处理函数
def handler(event, context):
    global ip_request_buffer, ip_last_activity
    
    # 初始化缓冲区（考虑函数实例重用）
    if not hasattr(handler, "initialized"):
        ip_request_buffer = defaultdict(list)
        ip_last_activity = {}
        handler.initialized = True
    
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

    # 记录处理开始时间（带时区）
    processing_start = get_current_utc_time()
    
    # 处理所有日志组
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
                    # 处理日志条目（按IP聚合）
                    result = process_log_entry(parsed_log)
                    if result:
                        logger.info(f"IP行为分析结果: {result}")
                        # 这里可以添加结果处理逻辑（如存储到安全数据库）
        
        begin_cursor = response.get_next_cursor()
        
        # 定期检查过期IP（每处理100个日志组）
        if log_group_cnt > 0:
            expired_results = analyze_expired_ips(get_current_utc_time())
            for ip, result in expired_results:
                logger.info(f"过期IP分析: {ip}, 结果: {result}")
                # 处理分析结果

    # 函数结束前处理所有剩余IP
    logger.info("处理剩余IP缓冲区...")
    for ip in list(ip_request_buffer.keys()):
        if ip_request_buffer[ip]:
            result = trigger_ip_analysis(ip)
            if result:
                logger.info(f"最终IP分析: {ip}, 结果: {result}")
                # 处理分析结果

    # 记录处理时间
    processing_time = get_current_utc_time() - processing_start
    logger.info(f"处理完成，总用时: {processing_time.total_seconds():.2f}秒")
    
    return 'success'
