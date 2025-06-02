import re
import json
import os
import logging
import requests as http_requests
import hashlib
from datetime import datetime, timezone
from aliyun.log import LogClient
from collections import defaultdict

# Apache日志解析正则表达式
APACHE_LOG_REGEX = r'(\S+) (\S+) (\S+) \[(.*?)\] "(\S+) (\S+) (\S+)" (\d+) (\d+) "([^"]*)" "([^"]*)"'

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# 聚合分析配置
MIN_REQUESTS_FOR_ANALYSIS = 2  # 触发分析的最小请求数
MAX_REQUESTS_PER_ANALYSIS = 20  # 单次分析的最大请求数

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

def analyze_ip_behavior(ip, ip_requests):
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
        response = http_requests.post(
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

# 主处理函数
def handler(event, context):
    # 记录处理开始时间
    processing_start = datetime.now(timezone.utc)
    
    # 初始化按IP分组的请求字典
    ip_requests_dict = defaultdict(list)
    
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
                    # 按IP分组收集日志
                    ip = parsed_log['ip']
                    ip_requests_dict[ip].append(parsed_log)
        
        begin_cursor = response.get_next_cursor()

    # 分析收集到的IP请求
    analysis_results = []
    for ip, requests in ip_requests_dict.items():
        # 只分析达到最小请求数的IP
        if len(requests) >= MIN_REQUESTS_FOR_ANALYSIS:
            logger.info(f"分析IP: {ip}, 请求数: {len(requests)}")
            # 按时间排序请求
            sorted_requests = sorted(requests, key=lambda x: x['time'])
            result = analyze_ip_behavior(ip, sorted_requests)
            analysis_results.append((ip, result))
            logger.info(f"IP分析结果: {ip}, 结果: {result}")
        else:
            logger.info(f"跳过IP {ip} 分析，请求数不足: {len(requests)} < {MIN_REQUESTS_FOR_ANALYSIS}")

    # 记录处理时间
    processing_time = datetime.now(timezone.utc) - processing_start
    logger.info(f"处理完成，总用时: {processing_time.total_seconds():.2f}秒")
    logger.info(f"共处理 {len(ip_requests_dict)} 个IP，分析 {len(analysis_results)} 个IP")
    
    return 'success'
