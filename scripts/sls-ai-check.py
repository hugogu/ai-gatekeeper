import re
import json
import os
import logging
import requests
from datetime import datetime
from aliyun.log import LogClient

# Apache日志解析正则表达式
APACHE_LOG_REGEX = r'(\S+) (\S+) (\S+) \[(.*?)\] "(\S+) (\S+) (\S+)" (\d+) (\d+) "([^"]*)" "([^"]*)"'

logger = logging.getLogger()

def parse_apache_log(log_content):
    """
    解析Apache格式的日志内容
    :param log_content: 日志内容字符串
    :return: 解析后的日志字典
    """
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

# 调用DeepSeek API分析
def analyze_with_deepseek(log):
    # 构建提示词
    prompt = f"""
你是一个网络安全分析系统，请判断以下访问行为是否异常（如暴力破解、SQL注入、爬虫等）：
[日志详情]
时间: {log['time']}
IP: {log['ip']}
方法: {log['method']}
路径: {log['path']}
状态码: {log['status']}
用户代理: {log['user_agent']}

返回JSON格式：{{"is_abnormal": true/false, "reason": "分析原因"}}
"""
    headers = {
        "Authorization": f"Bearer {os.getenv('DEEPSEEK_API_KEY')}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "deepseek-chat",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1,
        "max_tokens": 300
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
        # 提取返回内容
        content = result['choices'][0]['message']['content'].strip()
        # 解析JSON内容
        return json.loads(content)
    except Exception as e:
        logger.info(f"DeepSeek API调用失败: {str(e)}")
        return {"is_abnormal": False, "reason": f"分析失败: {str(e)}"}

# 主处理函数
def handler(event, context):
     # 可以通过 context.credentials 获取密钥信息
    # Access keys can be fetched through context.credentials
    creds = context.credentials
    access_key_id = creds.access_key_id
    access_key_secret = creds.access_key_secret
    security_token = creds.security_token

    # 解析 event 参数至 object 格式
    # parse event in object
    event_obj = json.loads(event.decode())

    # 从 event.source 中获取日志项目名称、日志仓库名称、日志服务访问 endpoint、日志起始游标、日志终点游标以及分区 id
    # Get the name of log project, the name of log store, the endpoint of sls, begin cursor, end cursor and shardId from event.source
    source = event_obj['source']
    log_project = source['projectName']
    log_store = source['logstoreName']
    endpoint = source['endpoint']
    begin_cursor = source['beginCursor']
    end_cursor = source['endCursor']
    shard_id = source['shardId']

    # 初始化 sls 客户端
    # Initialize client of sls
    client = LogClient(endpoint=endpoint, accessKeyId=access_key_id, accessKey=access_key_secret, securityToken=security_token)

    # 基于日志的游标从源日志库中读取日志，本示例中的游标范围包含了触发本次执行的所有日志内容
    # Read data from source logstore within cursor: [begin_cursor, end_cursor) in the example, which contains all the logs trigger the invocation
    while True:
      response = client.pull_logs(project_name=log_project, logstore_name=log_store,
                                shard_id=shard_id, cursor=begin_cursor, count=100,
                                end_cursor=end_cursor, compress=False)
      log_group_cnt = response.get_loggroup_count()
      log_group_list = response.get_loggroup_list().LogGroups
      # 检查是否有日志
      if log_group_cnt == 0:
        break
      logger.info("get %d log group from %s" % (log_group_cnt, log_store))
            # 处理每个日志组
      for log_group in log_group_list:
          # 处理组内的每条日志
          for log in log_group.Logs:
              log_dict = {}
              # 提取日志内容
              for content in log.Contents:
                  logger.debug("Find content: %s" % content)
                  log_dict[content.Key] = content.Value
            
            # 添加时间戳
              if log_dict['_container_name_'] != "blog-apache":
                  break
            
              logger.info("Find apache access log: %s" % log_dict['content'])

              log = parse_apache_log(log_dict['content'])

              analyze_with_deepseek(log)

      begin_cursor = response.get_next_cursor()

    return 'success'
