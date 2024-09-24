import sqlite3

# 连接到 SQLite 数据库（如果数据库不存在，将会自动创建）
conn = sqlite3.connect('test.db')

# 创建一个游标对象
cursor = conn.cursor()

# 删除现有的 users 表（如果存在）
cursor.execute('DROP TABLE IF EXISTS users')

# 删除现有的 products 表（如果存在）
cursor.execute('DROP TABLE IF EXISTS products')



# 创建 users 表
cursor.execute('''
CREATE TABLE  IF NOT EXISTS  users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL
)
''')

# 创建 products 表
cursor.execute('''
CREATE TABLE  IF NOT EXISTS  products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL
)
''')

# 创建 评论 表
cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            content TEXT NOT NULL
        )
''')


# 插入一些示例数据到 users 表
cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('admin', 'admin123'))
cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('user1', 'password1'))

# 插入一些示例数据到 products 表
cursor.execute("INSERT INTO products (name) VALUES (?)", ('Product A',))
cursor.execute("INSERT INTO products (name) VALUES (?)", ('Product B',))

# 提交事务
conn.commit()

# 关闭连接
conn.close()

print("SQLite 数据库和表已成功创建，并插入了示例数据。")