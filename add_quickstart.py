#!/usr/bin/env python3
"""
Script to add a Quickstart section to the README.
"""
import os
import sys

def add_quickstart(readme_path: str) -> None:
    """
    Add a 'Quickstart' section to the README file.
    
    Args:
        readme_path: Path to the README file.
    """
    if not os.path.exists(readme_path):
        print(f"Error: File '{readme_path}' not found.")
        sys.exit(1)
    
    # Read the existing README content
    with open(readme_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check if Quickstart section already exists
    if '## Quickstart' in content:
        print("Quickstart section already exists. No changes made.")
        return
    
    # Define the Quickstart section content
    quickstart_section = """## Quickstart

### Installation

```bash
pip install bluejay
```

### Running Bluejay

Start the Bluejay application with:

```bash
python -m bluejay
```

### First Command

Once Bluejay is running, send a safe first command to verify it's working:

```bash
/status
```

### Important Note

Bluejay only responds to commands from authorized targets. Ensure your requests come from a recognized source.
"""
    
    # Insert the Quickstart section after the first heading (usually # Title)
    # Find the position after the first line starting with '#'
    lines = content.split('\n')
    insert_pos = 0
    for i, line in enumerate(lines):
        if line.startswith('#') and not line.startswith('##'):
            insert_pos = i + 1
            break
    else:
        # If no top-level heading found, insert at the beginning
        insert_pos = 0
    
    # Rebuild content with Quickstart inserted
    new_lines = lines[:insert_pos] + [quickstart_section] + lines[insert_pos:]
    new_content = '\n'.join(new_lines)
    
    # Write back to file
    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write(new_content)
    
    print(f"Quickstart section added to '{readme_path}'.")

def main():
    """Main entry point."""
    # Default README path
    readme_path = 'README.md'
    
    # Allow command line argument for custom path
    if len(sys.argv) > 1:
        readme_path = sys.argv[1]
    
    add_quickstart(readme_path)

if __name__ == '__main__':
    main()