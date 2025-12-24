#!/usr/bin/env python3
"""
Test file to trigger GitHub Actions workflows.

Use of this code is at your own risk.
Author bears no responsibility for any damages caused by the code.
"""

def test_security_function():
    """Simple test function to validate security workflow execution."""
    return "Security workflow test successful"

if __name__ == "__main__":
    result = test_security_function()
    print(result)