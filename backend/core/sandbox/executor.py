"""
Kryx Sandbox — Safe Exploit Execution Environment

Provides isolated environment for:
- PoC verification
- Exploit testing
- Code analysis

Isolation methods:
- Docker containers (primary)
- Resource limits (CPU, memory, time)
- Network isolation
- Filesystem restrictions
"""
import os
import asyncio
import tempfile
import shutil
from typing import Dict, Optional, List
from pathlib import Path
from datetime import datetime

import docker
from docker.errors import DockerException


class SandboxEnvironment:
    """
    Sandboxed execution environment using Docker.
    
    Features:
    - Isolated containers
    - Automatic cleanup
    - Resource limits
    - Network isolation
    - Timeout enforcement
    """
    
    def __init__(self):
        try:
            self.docker_client = docker.from_env()
        except DockerException:
            print("[Sandbox] Warning: Docker not available")
            self.docker_client = None
    
    async def execute_code(
        self,
        code: str,
        language: str = "python",
        timeout: int = 30,
        network_enabled: bool = False,
        extra_files: Optional[Dict[str, str]] = None
    ) -> Dict:
        """
        Execute code in isolated sandbox.
        
        Args:
            code: Code to execute
            language: Programming language (python, c, javascript, etc)
            timeout: Max execution time in seconds
            network_enabled: Allow network access
            extra_files: Additional files to mount {filename: content}
        
        Returns:
            Dict with stdout, stderr, exit_code, execution_time
        """
        if not self.docker_client:
            return {
                "error": "Docker not available",
                "stdout": "",
                "stderr": "Sandbox requires Docker",
                "exit_code": -1
            }
        
        # Create temp directory for code
        temp_dir = tempfile.mkdtemp(prefix="kryx_sandbox_")
        
        try:
            # Write code to file
            code_file = self._get_code_filename(language)
            code_path = Path(temp_dir) / code_file
            code_path.write_text(code)
            
            # Write extra files
            if extra_files:
                for filename, content in extra_files.items():
                    file_path = Path(temp_dir) / filename
                    file_path.write_text(content)
            
            # Get container image for language
            image = self._get_image(language)
            
            # Run command
            command = self._get_run_command(language, code_file)
            
            # Execute in container
            result = await self._run_container(
                image=image,
                command=command,
                volumes={temp_dir: {"bind": "/workspace", "mode": "ro"}},
                working_dir="/workspace",
                timeout=timeout,
                network_mode="none" if not network_enabled else "bridge"
            )
            
            return result
        
        finally:
            # Cleanup temp directory
            shutil.rmtree(temp_dir, ignore_errors=True)
    
    async def execute_exploit(
        self,
        exploit_code: str,
        target_binary: Optional[str] = None,
        target_url: Optional[str] = None,
        timeout: int = 60
    ) -> Dict:
        """
        Execute exploit in sandbox against target.
        
        Args:
            exploit_code: Exploit PoC code
            target_binary: Path to vulnerable binary (if local)
            target_url: Target URL (if remote)
            timeout: Max execution time
        
        Returns:
            Execution result with success indicator
        """
        extra_files = {}
        
        # Add target binary if provided
        if target_binary and os.path.exists(target_binary):
            with open(target_binary, 'rb') as f:
                extra_files['target'] = f.read().decode('latin-1')
        
        # Execute exploit
        result = await self.execute_code(
            code=exploit_code,
            language="python",  # Assume Python exploit
            timeout=timeout,
            network_enabled=bool(target_url),
            extra_files=extra_files
        )
        
        # Analyze result for success indicators
        result["exploit_success"] = self._analyze_exploit_result(result)
        
        return result
    
    async def _run_container(
        self,
        image: str,
        command: str,
        volumes: Dict,
        working_dir: str,
        timeout: int,
        network_mode: str
    ) -> Dict:
        """Run Docker container and capture output"""
        
        start_time = datetime.utcnow()
        
        try:
            # Pull image if not present
            try:
                self.docker_client.images.get(image)
            except docker.errors.ImageNotFound:
                print(f"[Sandbox] Pulling image: {image}")
                self.docker_client.images.pull(image)
            
            # Create container
            container = self.docker_client.containers.run(
                image=image,
                command=command,
                volumes=volumes,
                working_dir=working_dir,
                network_mode=network_mode,
                mem_limit="256m",  # 256MB RAM limit
                cpu_period=100000,
                cpu_quota=50000,  # 50% CPU limit
                detach=True,
                remove=False,  # We'll remove manually
                security_opt=["no-new-privileges"],
                cap_drop=["ALL"]  # Drop all capabilities
            )
            
            # Wait for completion with timeout
            try:
                result = container.wait(timeout=timeout)
                exit_code = result.get("StatusCode", -1)
            except:
                # Timeout
                container.kill()
                exit_code = -2
            
            # Get logs
            logs = container.logs()
            stdout = logs.decode('utf-8', errors='replace')
            stderr = ""
            
            # Remove container
            container.remove(force=True)
            
            execution_time = (datetime.utcnow() - start_time).total_seconds()
            
            return {
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": exit_code,
                "execution_time": execution_time,
                "timed_out": exit_code == -2
            }
        
        except Exception as e:
            return {
                "error": str(e),
                "stdout": "",
                "stderr": str(e),
                "exit_code": -1,
                "execution_time": 0
            }
    
    def _get_image(self, language: str) -> str:
        """Get Docker image for language"""
        images = {
            "python": "python:3.11-slim",
            "c": "gcc:latest",
            "cpp": "gcc:latest",
            "javascript": "node:18-slim",
            "ruby": "ruby:3.2-slim",
            "go": "golang:1.21-alpine"
        }
        return images.get(language, "python:3.11-slim")
    
    def _get_code_filename(self, language: str) -> str:
        """Get filename for code"""
        extensions = {
            "python": "exploit.py",
            "c": "exploit.c",
            "cpp": "exploit.cpp",
            "javascript": "exploit.js",
            "ruby": "exploit.rb",
            "go": "exploit.go"
        }
        return extensions.get(language, "exploit.py")
    
    def _get_run_command(self, language: str, filename: str) -> str:
        """Get command to run code"""
        commands = {
            "python": f"python {filename}",
            "c": f"gcc {filename} -o /tmp/exploit && /tmp/exploit",
            "cpp": f"g++ {filename} -o /tmp/exploit && /tmp/exploit",
            "javascript": f"node {filename}",
            "ruby": f"ruby {filename}",
            "go": f"go run {filename}"
        }
        return commands.get(language, f"python {filename}")
    
    def _analyze_exploit_result(self, result: Dict) -> bool:
        """
        Analyze execution result to determine if exploit succeeded.
        
        Success indicators:
        - Exit code 0
        - "exploit successful" in output
        - "shell spawned" in output
        - No errors
        """
        if result.get("exit_code") == 0:
            return True
        
        output = result.get("stdout", "").lower()
        
        success_indicators = [
            "success",
            "exploit successful",
            "shell spawned",
            "root",
            "pwned",
            "got shell"
        ]
        
        return any(indicator in output for indicator in success_indicators)


# Simplified sandbox for environments without Docker
class SimpleSandbox:
    """
    Fallback sandbox using subprocess with restrictions.
    
    Less secure than Docker, but works without Docker daemon.
    Use only for trusted code.
    """
    
    async def execute_code(
        self,
        code: str,
        language: str = "python",
        timeout: int = 10
    ) -> Dict:
        """Execute code with subprocess restrictions"""
        
        if language != "python":
            return {
                "error": "Simple sandbox only supports Python",
                "exit_code": -1
            }
        
        # Create temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            temp_file = f.name
        
        try:
            # Run with timeout
            proc = await asyncio.create_subprocess_exec(
                "python3", temp_file,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout
                )
                
                return {
                    "stdout": stdout.decode('utf-8', errors='replace'),
                    "stderr": stderr.decode('utf-8', errors='replace'),
                    "exit_code": proc.returncode,
                    "timed_out": False
                }
            
            except asyncio.TimeoutError:
                proc.kill()
                return {
                    "stdout": "",
                    "stderr": "Execution timeout",
                    "exit_code": -2,
                    "timed_out": True
                }
        
        finally:
            os.unlink(temp_file)


# Factory function
def create_sandbox() -> SandboxEnvironment:
    """Create appropriate sandbox based on environment"""
    try:
        return SandboxEnvironment()
    except:
        print("[Sandbox] Docker not available, using simple sandbox")
        return SimpleSandbox()
