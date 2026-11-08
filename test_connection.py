#!/usr/bin/env python3
"""Test SSH connection to remote server"""

import asyncio
import os
import asyncssh
from dotenv import load_dotenv

load_dotenv()

async def test_connection():
    ssh_host = os.environ.get("SSH_HOST")
    ssh_user = os.environ.get("SSH_USER", "root")
    ssh_key = os.path.expanduser("~/.ssh/id_ed25519")

    print(f"Attempting to connect to {ssh_user}@{ssh_host}...")
    print(f"Using SSH key: {ssh_key}")

    try:
        conn = await asyncssh.connect(
            ssh_host,
            username=ssh_user,
            client_keys=[ssh_key],
            known_hosts=None
        )
        print("✓ Connection successful!")

        # Test running a simple command
        result = await conn.run("docker ps --format 'table {{.Names}}\t{{.Status}}'")
        print(f"✓ Docker containers:\n{result.stdout.strip()}")

        conn.close()

    except Exception as e:
        print(f"✗ Connection failed!")
        print(f"Error type: {type(e).__name__}")
        print(f"Error message: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_connection())
