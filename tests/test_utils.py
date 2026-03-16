#!/usr/bin/env python3
"""
Unit tests for utility functions.
"""

import unittest
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from secscan import utils


class TestUtilityFunctions(unittest.TestCase):
    """Test cases for utility functions."""
    
    def test_is_root(self):
        """Test root privilege detection."""
        result = utils.is_root()
        self.assertIsInstance(result, bool)
    
    def test_colors_enum(self):
        """Test Colors enumeration."""
        self.assertTrue(hasattr(utils.Colors, 'RED'))
        self.assertTrue(hasattr(utils.Colors, 'GREEN'))
        self.assertTrue(hasattr(utils.Colors, 'YELLOW'))
        self.assertTrue(hasattr(utils.Colors, 'BLUE'))
    
    def test_file_exists(self):
        """Test file existence check."""
        # Test with known existing file
        self.assertTrue(utils.file_exists("/etc/passwd"))
        
        # Test with non-existent file
        self.assertFalse(utils.file_exists("/nonexistent/file/path"))
    
    def test_read_file_lines(self):
        """Test reading file lines."""
        lines = utils.read_file_lines("/etc/hostname")
        self.assertIsInstance(lines, list)
    
    def test_run_command(self):
        """Test command execution."""
        stdout, stderr, rc = utils.run_command("echo test")
        self.assertEqual(rc, 0)
        self.assertEqual(stdout, "test")
    
    def test_run_command_failure(self):
        """Test failed command execution."""
        stdout, stderr, rc = utils.run_command("false")
        self.assertNotEqual(rc, 0)


class TestFilePermissions(unittest.TestCase):
    """Test cases for file permission checks."""
    
    def test_get_file_permissions(self):
        """Test getting file permissions."""
        # /etc/passwd should exist and be readable
        perms = utils.get_file_permissions("/etc/passwd")
        self.assertIsNotNone(perms)
        self.assertIsInstance(perms, str)
        self.assertEqual(len(perms), 3)


if __name__ == "__main__":
    unittest.main()
