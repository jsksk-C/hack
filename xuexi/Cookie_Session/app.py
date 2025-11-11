from flask import Flask, request, make_response, redirect, url_for, session, render_template_string
import secrets
import datetime

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # 用于加密session的密钥

# 简单的HTML模板
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Cookie和Session示例</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .container { background: #f5f5f5; padding: 20px; border-radius: 5px; margin: 10px 0; }
        .info { background: #e8f4fd; padding: 10px; border-left: 4px solid #2196F3; }
        .cookie { background: #fff3cd; padding: 10px; border-left: 4px solid #ffc107; }
        .session { background: #d1ecf1; padding: 10px; border-left: 4px solid #17a2b8; }
        button { padding: 8px 15px; margin: 5px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
    </style>
</head>
<body>
    <h1>Cookie和Session学习示例</h1>
    
    <div class="info">
        <h3>当前状态信息</h3>
        <p>访问次数: {{ visit_count }}</p>
        <p>首次访问: {{ first_visit }}</p>
        <p>最后访问: {{ last_visit }}</p>
        <p>用户名: {{ username }}</p>
    </div>
    
    <div class="cookie">
        <h3>Cookie信息</h3>
        <p>用户ID: {{ user_id }}</p>
        <p>主题偏好: {{ theme }}</p>
    </div>
    
    <div class="session">
        <h3>Session信息</h3>
        <p>登录状态: {{ logged_in }}</p>
        <p>购物车商品数: {{ cart_items }}</p>
    </div>
    
    <div>
        <h3>操作</h3>
        <form method="post" action="/login">
            <input type="text" name="username" placeholder="输入用户名" required>
            <button type="submit">登录</button>
        </form>
        
        <form method="post" action="/add_to_cart">
            <button type="submit">添加商品到购物车</button>
        </form>
        
        <form method="post" action="/change_theme">
            <button type="submit" name="theme" value="light">浅色主题</button>
            <button type="submit" name="theme" value="dark">深色主题</button>
        </form>
        
        <form method="post" action="/logout">
            <button type="submit">退出登录</button>
        </form>
        
        <form method="post" action="/clear">
            <button type="submit" style="background: #dc3545;">清除所有数据</button>
        </form>
    </div>
    
    <div style="margin-top: 30px;">
        <h3>Cookie和Session的区别</h3>
        <ul>
            <li><strong>Cookie</strong>: 存储在客户端，有大小限制(约4KB)，可以设置过期时间</li>
            <li><strong>Session</strong>: 存储在服务器端，更安全，可以存储更多数据</li>
            <li>Session通常依赖于Cookie来存储session ID</li>
        </ul>
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    # 处理Cookie - 存储在客户端
    user_id = request.cookies.get('user_id')
    theme = request.cookies.get('theme', 'light')  # 默认浅色主题
    
    # 如果没有user_id，创建一个
    if not user_id:
        user_id = secrets.token_hex(8)
    
    # 处理Session - 存储在服务器端
    if 'visit_count' in session:
        session['visit_count'] += 1
        session['last_visit'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    else:
        session['visit_count'] = 1
        session['first_visit'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        session['last_visit'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        session['cart_items'] = 0
    
    # 准备响应
    response = make_response(render_template_string(
        HTML_TEMPLATE,
        visit_count=session['visit_count'],
        first_visit=session.get('first_visit', 'N/A'),
        last_visit=session.get('last_visit', 'N/A'),
        username=session.get('username', '未登录'),
        user_id=user_id,
        theme=theme,
        logged_in='已登录' if session.get('username') else '未登录',
        cart_items=session.get('cart_items', 0)
    ))
    
    # 设置Cookie
    response.set_cookie('user_id', user_id, max_age=60*60*24*30)  # 30天过期
    response.set_cookie('theme', theme, max_age=60*60*24*30)
    
    return response

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    if username:
        session['username'] = username
    return redirect(url_for('index'))

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    session['cart_items'] = session.get('cart_items', 0) + 1
    return redirect(url_for('index'))

@app.route('/change_theme', methods=['POST'])
def change_theme():
    theme = request.form.get('theme', 'light')
    response = redirect(url_for('index'))
    response.set_cookie('theme', theme, max_age=60*60*24*30)
    return response

@app.route('/clear', methods=['POST'])
def clear_data():
    # 清除session
    session.clear()
    
    # 清除cookie
    response = redirect(url_for('index'))
    response.set_cookie('user_id', '', expires=0)
    response.set_cookie('theme', '', expires=0)
    
    return response

if __name__ == '__main__':
    app.run(debug=True)