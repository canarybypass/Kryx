"""
Kryx CLI - Command-line interface for Kryx security platform

Usage:
    kryx login
    kryx scan <target>
    kryx status <scan_id>
    kryx list
    kryx report <scan_id>
"""
import sys
import os
import json
import time
from pathlib import Path
from typing import Optional

import click
import httpx
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax
from rich.panel import Panel

console = Console()

# Config file location
CONFIG_DIR = Path.home() / ".kryx"
CONFIG_FILE = CONFIG_DIR / "config.json"

# Default API endpoint
DEFAULT_API_URL = "http://localhost:8000"


class KryxClient:
    """Client for Kryx API"""
    
    def __init__(self):
        self.config = self._load_config()
        self.api_url = self.config.get("api_url", DEFAULT_API_URL)
        self.api_key = self.config.get("api_key")
        
        if not self.api_key:
            console.print("[red]Not logged in. Run 'kryx login' first.[/red]")
            sys.exit(1)
        
        self.client = httpx.Client(
            base_url=self.api_url,
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=30.0
        )
    
    def _load_config(self) -> dict:
        """Load config from file"""
        if CONFIG_FILE.exists():
            return json.loads(CONFIG_FILE.read_text())
        return {}
    
    def _save_config(self, config: dict):
        """Save config to file"""
        CONFIG_DIR.mkdir(exist_ok=True)
        CONFIG_FILE.write_text(json.dumps(config, indent=2))
    
    def login(self, api_key: str, api_url: Optional[str] = None):
        """Save API credentials"""
        config = {
            "api_key": api_key,
            "api_url": api_url or DEFAULT_API_URL
        }
        self._save_config(config)
        console.print("[green]✓ Logged in successfully[/green]")
    
    def create_scan(self, target: str, target_type: str = "repo") -> dict:
        """Create new scan"""
        response = self.client.post(
            "/api/v2/scans",
            json={"target": target, "target_type": target_type}
        )
        response.raise_for_status()
        return response.json()
    
    def get_scan(self, scan_id: int) -> dict:
        """Get scan details"""
        response = self.client.get(f"/api/v2/scans/{scan_id}")
        response.raise_for_status()
        return response.json()
    
    def list_scans(self, limit: int = 20) -> list:
        """List recent scans"""
        response = self.client.get("/api/scans", params={"limit": limit})
        response.raise_for_status()
        return response.json()


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """Kryx CLI - AI-powered security scanning"""
    pass


@cli.command()
@click.option("--api-key", prompt="API Key", hide_input=True, help="Your Kryx API key")
@click.option("--api-url", default=DEFAULT_API_URL, help="API endpoint URL")
def login(api_key: str, api_url: str):
    """Login to Kryx (save API credentials)"""
    client = KryxClient.__new__(KryxClient)
    client.login(api_key, api_url)


@cli.command()
@click.argument("target")
@click.option("--type", "target_type", default="repo", help="Target type (repo, source, web)")
@click.option("--wait/--no-wait", default=True, help="Wait for scan completion")
def scan(target: str, target_type: str, wait: bool):
    """Start a new security scan
    
    Examples:
        kryx scan /path/to/project
        kryx scan https://github.com/user/repo
        kryx scan --type web https://example.com
    """
    client = KryxClient()
    
    with console.status("[bold green]Creating scan..."):
        result = client.create_scan(target, target_type)
    
    scan_id = result["scan_id"]
    console.print(f"[green]✓ Scan created: ID {scan_id}[/green]")
    
    if wait:
        _wait_for_scan(client, scan_id)
    else:
        console.print(f"\nRun 'kryx status {scan_id}' to check progress")


def _wait_for_scan(client: KryxClient, scan_id: int):
    """Wait for scan completion with progress"""
    console.print("\n[bold]Scanning...[/bold]")
    
    stages = {
        "static_analysis": "Static Analysis",
        "fuzzing": "Fuzzing",
        "variant_hunt": "Variant Hunter",
        "exploit_build": "Exploit Builder",
        "verification": "Verification"
    }
    
    completed_stages = set()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Analyzing...", total=None)
        
        while True:
            time.sleep(2)
            
            try:
                scan = client.get_scan(scan_id)
                status = scan["status"]
                
                # Update completed stages
                pipeline = scan.get("pipeline_progress", {})
                for stage_key, stage_name in stages.items():
                    if pipeline.get(stage_key) and stage_key not in completed_stages:
                        console.print(f"[green]✓ {stage_name} complete[/green]")
                        completed_stages.add(stage_key)
                
                if status in ["completed", "failed"]:
                    break
            
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")
                break
    
    if status == "completed":
        console.print("\n[bold green]✓ Scan completed![/bold green]")
        _display_results(scan)
    else:
        console.print(f"\n[red]Scan failed: {scan.get('summary', 'Unknown error')}[/red]")


def _display_results(scan: dict):
    """Display scan results summary"""
    stats = scan.get("stats", {})
    vulns = scan.get("vulnerabilities", [])
    
    # Summary panel
    summary = scan.get("summary", "No summary")
    console.print(Panel(summary, title="Summary", border_style="blue"))
    
    # Statistics
    console.print(f"\n[bold]Statistics:[/bold]")
    console.print(f"  Total vulnerabilities: {stats.get('total_findings', 0)}")
    
    by_severity = stats.get("by_severity", {})
    if by_severity:
        console.print(f"  Critical: {by_severity.get('critical', 0)}")
        console.print(f"  High: {by_severity.get('high', 0)}")
        console.print(f"  Medium: {by_severity.get('medium', 0)}")
        console.print(f"  Low: {by_severity.get('low', 0)}")
    
    # Top vulnerabilities
    if vulns:
        console.print(f"\n[bold]Top Vulnerabilities:[/bold]")
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Severity", style="dim")
        table.add_column("Type")
        table.add_column("Name")
        table.add_column("Location", style="dim")
        
        for v in vulns[:10]:
            severity = v.get("severity", "unknown").upper()
            severity_color = {
                "CRITICAL": "[red]",
                "HIGH": "[orange1]",
                "MEDIUM": "[yellow]",
                "LOW": "[green]"
            }.get(severity, "")
            
            table.add_row(
                f"{severity_color}{severity}[/]",
                v.get("type", ""),
                v.get("name", "")[:50],
                v.get("location", "")[:40]
            )
        
        console.print(table)
    
    console.print(f"\n[dim]Run 'kryx report {scan['id']}' for full report[/dim]")


@cli.command()
@click.argument("scan_id", type=int)
def status(scan_id: int):
    """Check scan status
    
    Example:
        kryx status 123
    """
    client = KryxClient()
    
    try:
        scan = client.get_scan(scan_id)
        
        console.print(f"\n[bold]Scan #{scan_id}[/bold]")
        console.print(f"Target: {scan['target']}")
        console.print(f"Status: {scan['status']}")
        console.print(f"Created: {scan['created_at']}")
        
        # Pipeline progress
        pipeline = scan.get("pipeline_progress", {})
        if pipeline:
            console.print("\n[bold]Pipeline Progress:[/bold]")
            stages = {
                "static_analysis": "Static Analysis",
                "fuzzing": "Fuzzing",
                "variant_hunt": "Variant Hunter",
                "exploit_build": "Exploit Builder",
                "verification": "Verification"
            }
            
            for key, name in stages.items():
                done = pipeline.get(key, False)
                icon = "✓" if done else "○"
                color = "green" if done else "dim"
                console.print(f"  [{color}]{icon} {name}[/{color}]")
        
        if scan["status"] == "completed":
            _display_results(scan)
    
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            console.print(f"[red]Scan #{scan_id} not found[/red]")
        else:
            console.print(f"[red]Error: {e}[/red]")


@cli.command()
@click.option("--limit", default=20, help="Number of scans to show")
def list(limit: int):
    """List recent scans
    
    Example:
        kryx list
        kryx list --limit 50
    """
    client = KryxClient()
    
    try:
        scans = client.list_scans(limit)
        
        if not scans:
            console.print("[yellow]No scans found[/yellow]")
            return
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("ID", style="dim")
        table.add_column("Target")
        table.add_column("Status")
        table.add_column("Vulns", justify="right")
        table.add_column("Created")
        
        for scan in scans:
            status = scan["status"]
            status_color = {
                "completed": "[green]",
                "running": "[yellow]",
                "failed": "[red]",
                "queued": "[blue]"
            }.get(status, "")
            
            stats = scan.get("stats", {})
            vulns = stats.get("total_findings", "-")
            
            table.add_row(
                str(scan["id"]),
                scan["target"][:50],
                f"{status_color}{status}[/]",
                str(vulns),
                scan["created_at"][:16]
            )
        
        console.print(table)
    
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@cli.command()
@click.argument("scan_id", type=int)
@click.option("--format", "output_format", default="markdown", help="Output format (markdown, json)")
@click.option("--output", "-o", help="Save to file")
def report(scan_id: int, output_format: str, output: Optional[str]):
    """Get full scan report
    
    Examples:
        kryx report 123
        kryx report 123 --output report.md
        kryx report 123 --format json
    """
    client = KryxClient()
    
    try:
        scan = client.get_scan(scan_id)
        
        if output_format == "json":
            report_content = json.dumps(scan, indent=2)
            if output:
                Path(output).write_text(report_content)
                console.print(f"[green]✓ Report saved to {output}[/green]")
            else:
                console.print(report_content)
        
        else:  # markdown
            report_content = scan.get("report", "No report available")
            
            if output:
                Path(output).write_text(report_content)
                console.print(f"[green]✓ Report saved to {output}[/green]")
            else:
                syntax = Syntax(report_content, "markdown", theme="monokai")
                console.print(syntax)
    
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            console.print(f"[red]Scan #{scan_id} not found[/red]")
        else:
            console.print(f"[red]Error: {e}[/red]")


@cli.command()
@click.argument("scan_id", type=int)
def exploits(scan_id: int):
    """List generated exploits for scan
    
    Example:
        kryx exploits 123
    """
    client = KryxClient()
    
    try:
        scan = client.get_scan(scan_id)
        vulns = scan.get("vulnerabilities", [])
        
        # Filter vulnerabilities with exploit code
        with_exploits = [v for v in vulns if v.get("exploit_code")]
        
        if not with_exploits:
            console.print("[yellow]No exploits generated for this scan[/yellow]")
            return
        
        console.print(f"\n[bold]Generated Exploits ({len(with_exploits)}):[/bold]\n")
        
        for i, v in enumerate(with_exploits, 1):
            console.print(f"[bold cyan]{i}. {v['name']}[/bold cyan]")
            console.print(f"   Severity: {v['severity'].upper()}")
            console.print(f"   Technique: {v.get('exploit_technique', 'N/A')}")
            console.print(f"   Verified: {'✓' if v.get('verified') else '✗'}")
            console.print(f"   Location: {v.get('location', 'N/A')}\n")
    
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


if __name__ == "__main__":
    cli()
