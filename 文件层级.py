import os

def print_directory_structure(root_dir, indent=''):
    """
    递归打印目录结构，并打印文件内容
    :param root_dir: 根目录
    :param indent: 缩进字符串，用于表示层级
    """
    try:
        # 获取当前目录下的所有文件和文件夹
        items = os.listdir(root_dir)
        items.sort()  # 按字母顺序排序

        for index, item in enumerate(items):
            item_path = os.path.join(root_dir, item)
            is_last_item = (index == len(items) - 1)

            # 打印当前项
            if is_last_item:
                print(f"{indent}└── {item}")
                new_indent = indent + "    "  # 最后一项的子项缩进
            else:
                print(f"{indent}├── {item}")
                new_indent = indent + "│   "  # 非最后一项的子项缩进

            # 如果是目录，递归打印其内容
            if os.path.isdir(item_path):
                print_directory_structure(item_path, new_indent)
            # 如果是文件，打印文件内容
            elif os.path.isfile(item_path):
                try:
                    with open(item_path, 'r', encoding='utf-8') as file:
                        content = file.read()
                        print(f"{new_indent}Content of {item}:")
                        print(f"{new_indent}{content}")
                except Exception as e:
                    print(f"{new_indent}Error reading {item}: {e}")
    except PermissionError:
        print(f"{indent}└── [Permission Denied]")

# 使用示例
root_directory = 'sdlc后端'
print_directory_structure(root_directory)