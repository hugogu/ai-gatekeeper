import re
import json
import os
import logging
import requests as http_requests
import socket
import hashlib
from datetime import datetime, timezone
from aliyun.log import LogClient
from collections import defaultdict

# Apache日志解析正则表达式
APACHE_LOG_REGEX = r'(\S+) (\S+) (\S+) \[(.*?)\] "(\S+) (\S+) (\S+)" (\d+) (\d+) "([^"]*)" "([^"]*)"'

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# 配置风险日志记录器
risk_logger = logging.getLogger('security_risk')
risk_logger.setLevel(logging.WARNING)

# 获取主机名
HOSTNAME = socket.gethostname()

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

def log_security_risk(ip, risk_level, reason, patterns_found, request_count, analysis_result=None, original_requests=None):
    """
    记录安全风险日志，用于SLS告警
    :param ip: 风险IP地址
    :param risk_level: 风险等级 (low/medium/high)
    :param reason: 风险原因
    :param patterns_found: 检测到的风险模式列表
    :param request_count: 相关请求数量
    :param analysis_result: 完整分析结果(可选)
    :param original_requests: 原始请求数据列表(可选)
    """
    risk_data = {
        "__source__": HOSTNAME,
        "__tag__:risk_type": "ai_anomaly_detection",
        "risk_level": risk_level,
        "ip": ip,
        "reason": reason,
        "patterns_found": ", ".join(patterns_found) if patterns_found else "none",
        "request_count": request_count,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    
    if analysis_result:
        risk_data["analysis_result"] = str(analysis_result)
    
    # 添加原始请求数据，最多包含10个请求，以便人工审核
    if original_requests:
        # 提取请求的关键信息并格式化为易读的字符串
        request_details = []
        for i, req in enumerate(original_requests[:10]):
            time_str = req['time'].strftime('%Y-%m-%d %H:%M:%S %Z')
            request_details.append(f"#{i+1}: {req['method']} {req['path']} - {req['status']} - {time_str} - {req['user_agent'][:50]}...")
        
        # 如果有更多请求，添加提示信息
        if len(original_requests) > 10:
            request_details.append(f"...还有 {len(original_requests) - 10} 个请求未显示")
            
        risk_data["request_details"] = request_details
    
    # 使用WARNING级别记录，便于在SLS中配置告警
    risk_logger.warning(
        "SECURITY_RISK_DETECTED",
        extra={"risk_data": risk_data}
    )
    
    logger.warning(f"安全风险已记录 - IP: {ip}, 风险等级: {risk_level}, 原因: {reason}")

def analyze_ip_behavior(ip, ip_requests):
    """
    分析一个IP的多个请求行为
    :param ip: 客户端IP
    :param ip_requests: 该IP的请求列表（每个请求是解析后的日志字典）
    """
    # 构建提示词 - 关注多个请求的模式，并提供更多正常行为的指导
    prompt = f"""
你是一个高级网络安全分析系统，请分析以下来自同一IP地址的多个访问行为是否异常（如扫描、暴力破解、爬虫等）。
重点关注请求模式、路径分布、频率等特征。

请注意区分正常的网页浏览行为与恶意行为：
- 正常浏览行为：用户访问一个页面，然后加载该页面的CSS、JS、图片等资源，通常在同一时间点有多个请求
- 可疑的扫描行为：短时间内访问大量不相关的页面或资源，特别是访问大量不存在的资源(404)
- 可疑的暴力破解：对登录、管理页面进行大量重复访问，特别是返回401/403状态码
- 可疑的爬虫行为：系统性地访问网站的所有内容，但与正常浏览不同的是，爬虫通常不会加载CSS/JS等资源

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
    error_rate = sum(1 for code in status_codes if code >= 400) / len(status_codes) if status_codes else 0
    
    # 计算请求时间分布
    if ip_requests:
        request_times = [req['time'] for req in ip_requests]
        first_time = min(request_times)
        last_time = max(request_times)
        time_range_str = f"{first_time.strftime('%H:%M:%S %Z')} - {last_time.strftime('%H:%M:%S %Z')}"
        
        # 计算请求的时间跨度（秒）
        time_span_seconds = (last_time - first_time).total_seconds()
        
        # 如果所有请求都在同一秒内，这很可能是正常的页面加载
        same_second = time_span_seconds < 1
    else:
        time_range_str = "N/A"
        time_span_seconds = 0
        same_second = False
    
    # 分析请求路径模式
    paths = [req['path'] for req in ip_requests]
    # 检查是否有主页面和相关资源的模式（正常浏览行为）
    has_page_and_resources = False
    resource_extensions = [".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf"]
    
    # 计算资源请求的比例
    resource_requests = sum(1 for path in paths if any(path.endswith(ext) for ext in resource_extensions))
    resource_ratio = resource_requests / len(paths) if paths else 0
    
    # 检查是否有明显的页面和资源加载模式
    if resource_ratio > 0.5 and same_second:
        has_page_and_resources = True
    
    prompt += f"""
统计分析:
- 请求总数: {len(ip_requests)}
- 唯一路径数: {unique_paths}
- 成功率: {success_rate:.1%}
- 错误率: {error_rate:.1%}
- 时间范围: {time_range_str}
- 时间跨度: {time_span_seconds:.1f}秒
- 资源请求比例: {resource_ratio:.1%}
- 所有请求在同一秒内: {'是' if same_second else '否'}
- 疑似正常页面加载模式: {'是' if has_page_and_resources else '否'}

请从以下角度分析:
1. 是否存在扫描行为（如请求大量不同路径，特别是大量404响应）
2. 是否存在暴力破解特征（如对登录页面的大量请求，特别是401/403响应）
3. 是否表现出爬虫行为模式（系统性地访问内容但不加载资源文件）
4. 是否符合正常用户浏览网页的模式（加载页面后立即加载相关资源）

重要提示：
- 如果请求模式符合正常的网页浏览（页面加载后立即加载CSS/JS等资源），即使请求数量较多，也应判定为正常行为
- 只有在明确存在恶意模式时才标记为异常
- 高成功率、资源请求比例高、同一秒内的多个请求通常表示正常的页面加载

返回JSON格式:
{{
  "is_abnormal": true/false,  // 只有在确信是恶意行为时才设为true
  "risk_level": "low/medium/high",
  "reason": "详细分析原因",
  "patterns_found": ["扫描", "暴力破解", "爬虫", "其他"],  // 检测到的模式列表
  "suspicious_requests": [{{"path": "路径", "method": "方法", "status": "状态码", "time": "时间"}}]  // 可疑请求列表
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
        ai_result = extract_json_from_response(content)
        
        # 添加请求统计信息
        ai_result['request_stats'] = {
            "total_requests": len(ip_requests),
            "unique_paths": unique_paths,
            "success_rate": f"{success_rate:.1%}",
            "error_rate": f"{error_rate:.1%}",
            "time_span_seconds": f"{time_span_seconds:.1f}",
            "resource_ratio": f"{resource_ratio:.1%}",
            "same_second_requests": same_second,
            "likely_normal_browsing": has_page_and_resources
        }
        
        # 添加原始请求数据的引用，但不直接包含在结果中（避免结果过大）
        ai_result['has_original_requests'] = True
        
        return ai_result
    except Exception as e:
        logger.error(f"DeepSeek API调用失败: {str(e)}")
        return {
            "is_abnormal": False,
            "risk_level": "unknown",
            "reason": f"API调用失败: {str(e)}",
            "patterns_found": [],
            "suspicious_requests": [],
            "request_stats": {
                "total_requests": len(ip_requests),
                "unique_paths": unique_paths,
                "success_rate": f"{success_rate:.1%}",
                "error_rate": f"{error_rate:.1%}",
                "time_span_seconds": f"{time_span_seconds:.1f}",
                "resource_ratio": f"{resource_ratio:.1%}",
                "same_second_requests": same_second,
                "likely_normal_browsing": has_page_and_resources
            },
            "has_original_requests": True
        }

# 主处理函数
def handler(event, context):

    logger.info(f"开始处理访问日志：{event}")
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
            
            # 如果检测到异常行为，记录风险日志
            if result.get('is_abnormal', False):
                log_security_risk(
                    ip=ip,
                    risk_level=result.get('risk_level', 'medium'),
                    reason=result.get('reason', '检测到可疑行为'),
                    patterns_found=result.get('patterns_found', []),
                    request_count=len(sorted_requests),
                    analysis_result=result,
                    original_requests=sorted_requests  # 传入原始请求数据，而不是依赖AI返回值
                )
        else:
            logger.info(f"跳过IP {ip} 分析，请求数不足: {len(requests)} < {MIN_REQUESTS_FOR_ANALYSIS}")

    # 记录处理时间
    processing_time = datetime.now(timezone.utc) - processing_start
    logger.info(f"处理完成，总用时: {processing_time.total_seconds():.2f}秒")
    logger.info(f"共处理 {len(ip_requests_dict)} 个IP，分析 {len(analysis_results)} 个IP")
    
    return 'success'
