#!/usr/bin/env python3
"""
Test script for add_quickstart.py
"""

import os
import tempfile
import unittest
from add_quickstart import add_quickstart_section

class TestAddQuickstart(unittest.TestCase):
    def setUp(self):
        # 创建临时目录
        self.test_dir = tempfile.mkdtemp()
        self.readme_path = os.path.join(self.test_dir, "README.md")
        # 创建一个示例README
        with open(self.readme_path, 'w', encoding='utf-8') as f:
            f.write("# My Project\n\nSome description.\n")

    def tearDown(self):
        # 清理临时文件
        os.remove(self.readme_path)
        os.rmdir(self.test_dir)

    def test_add_quickstart(self):
        """Test that Quickstart section is added correctly."""
        add_quickstart_section(self.readme_path)
        with open(self.readme_path, 'r', encoding='utf-8') as f:
            content = f.read()
        self.assertIn("## Quickstart", content)
        self.assertIn("python -m bluejay", content)
        self.assertIn("/status", content)
        self.assertIn("authorized targets", content)

    def test_no_duplicate(self):
        """Test that adding twice does not duplicate."""
        add_quickstart_section(self.readme_path)
        add_quickstart_section(self.readme_path)
        with open(self.readme_path, 'r', encoding='utf-8') as f:
            content = f.read()
        # 只出现一次
        self.assertEqual(content.count("## Quickstart"), 1)

    def test_file_not_found(self):
        """Test FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            add_quickstart_section("nonexistent.md")

if __name__ == "__main__":
    unittest.main()