# TWeb

- 创建任意HTTP响应(自定义请求方法、路径、状态码、请求头)
- 响应内容支持自定义变量、jinja2模板语法和部分自定义过滤器
- 查看对应路径请求日志信息
- 自定义XXE Payload生成恶意文档(doc、xlsx、ppt)
- 自定义代理请求(中转服务器)
- 在线端口监听查看请求、tcpdump查看数据包(ICMP、TCP、UDP)

```
host: {{host}}
port: {{port}}
cmd: {{cmd}}

# filter
{{ cmd | upper }}
{{ cmd | lower }}
{{ cmd | title }}
{{ cmd | capitalize }}
{{ my_variable | default('my_variable is not defined') }}
{{ [1, 2, 3] | join('|') }}
{{ "Hello World"|replace("Hello", "Goodbye") }}
...

# custom request variables
request_method: {{ request.method }}
request.path: {{ request.path }}
request.args: {{ request.args }}
request.form: {{ request.form }}
request.query_string: {{ request.query_string | safe }}
request.body: {{ request.body }}
request.headers['User-Agent'] {{ request.headers['User-Agent'] }}
REQUEST_HEADERS_STR:
{%for k, v in request.headers.items()%}
{{-k}}:{{v}}
{%endfor%}

# custom hash filter (filters.py)
'admin'|md5: {{ 'admin' | md5 }}
'admin'|base64encode: {{ 'admin' | base64encode }}
'admin'|base64decode: {{ 'admin' | base64decode }}
```

## 预览
![](https://i.loli.net/2018/09/10/5b954f0cac8f0.jpg)

![](https://i.loli.net/2018/09/10/5b954fc3bc24d.jpg
)

![](https://i.loli.net/2018/09/10/5b95500f49cdd.jpg
)