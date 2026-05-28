#!/usr/bin/env python3
"""
Script to add a Quickstart section to the README file.
"""

import os
import sys

def add_quickstart_section(readme_path: str) -> None:
    """
    Add a 'Quickstart' section to the README file.

    Args:
        readme_path (str): Path to the README file.

    Raises:
        FileNotFoundError: If the README file does not exist.
        PermissionError: If the README file cannot be written.
    """
    # 检查文件是否存在
    if not os.path.exists(readme_path):
        raise FileNotFoundError(f"README file not found: {readme_path}")

    # 读取现有内容
    with open(readme_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # 定义要添加的Quickstart部分
    quickstart_section = """## Quickstart

### Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd <repository-directory>
   ```

2. Install dependencies (if any):
   ```bash
   pip install -r requirements.txt
   ```

### Running the Application

Run the following command to start Bluejay:

```bash
python -m bluejay
```

### First Command

After starting Bluejay, try the safe first command:

```bash
/status
```

> **Note:** Bluejay only responds to authorized targets. Ensure you have the necessary permissions.

"""

    # 检查是否已经存在Quickstart部分，避免重复添加
    if "## Quickstart" in content:
        print("Quickstart section already exists. Skipping.")
        return

    # 在第一个标题（通常是 # 标题）之后插入Quickstart部分
    # 找到第一个标题的位置
    lines = content.split('\n')
    insert_pos = 0
    for i, line in enumerate(lines):
        if line.startswith('# '):
            insert_pos = i + 1
            break

    # 在插入位置后添加空行和Quickstart内容
    lines.insert(insert_pos, '\n' + quickstart_section)
    new_content = '\n'.join(lines)

    # 写回文件
    try:
        with open(readme_path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"Successfully added Quickstart section to {readme_path}")
    except PermissionError:
        raise PermissionError(f"Cannot write to {readme_path}. Check permissions.")

def main():
    """
    Main entry point.
    """
    # 默认README路径
    readme_path = "README.md"
    
    # 允许通过命令行参数指定路径
    if len(sys.argv) > 1:
        readme_path = sys.argv[1]

    try:
        add_quickstart_section(readme_path)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except PermissionError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()