#!/usr/bin/env python3
"""
Test script for add_quickstart functionality.
"""
import os
import tempfile
import sys

# Add parent directory to path to import the main script
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from add_quickstart import add_quickstart

def test_add_quickstart():
    """Test adding Quickstart section."""
    # Create a temporary README file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
        f.write("# My Project\n\nSome description.\n")
        temp_path = f.name
    
    try:
        # Add Quickstart
        add_quickstart(temp_path)
        
        # Read back and verify
        with open(temp_path, 'r') as f:
            content = f.read()
        
        assert '## Quickstart' in content, "Quickstart section not found"
        assert 'pip install bluejay' in content, "Installation command missing"
        assert 'python -m bluejay' in content, "Run command missing"
        assert '/status' in content, "First command missing"
        assert 'authorized targets' in content, "Note about authorized targets missing"
        print("Test passed: Quickstart section added correctly.")
    finally:
        os.unlink(temp_path)
    
    # Test idempotency: running again should not duplicate
    with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
        f.write("# My Project\n\n## Quickstart\n\nExisting content.\n")
        temp_path2 = f.name
    
    try:
        add_quickstart(temp_path2)
        with open(temp_path2, 'r') as f:
            content = f.read()
        # Count occurrences of '## Quickstart'
        count = content.count('## Quickstart')
        assert count == 1, f"Expected 1 Quickstart section, found {count}"
        print("Test passed: No duplicate Quickstart section.")
    finally:
        os.unlink(temp_path2)
    
    print("All tests passed.")

if __name__ == '__main__':
    test_add_quickstart()