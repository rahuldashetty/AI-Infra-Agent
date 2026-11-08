#!/usr/bin/env python3
"""Test MCP tools with the updated SSH connection"""

import asyncio
import os
import sys
from dotenv import load_dotenv

# Load environment
load_dotenv()

# Import the functions from server.py
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from server import check_docker_containers, check_disk_usage

async def test_tools():
    print("Testing MCP tools with updated SSH connection...\n")

    # Test 1: Check Docker containers
    print("=" * 60)
    print("TEST 1: check_docker_containers()")
    print("=" * 60)
    result = await check_docker_containers()
    print(result)
    print()

    # Test 2: Check disk usage
    print("=" * 60)
    print("TEST 2: check_disk_usage()")
    print("=" * 60)
    result = await check_disk_usage()
    print(result)
    print()

    print("✓ All tests completed successfully!")

if __name__ == "__main__":
    asyncio.run(test_tools())
