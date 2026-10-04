import argparse
import os
import sys
import time
from pathlib import Path
from typing import List, Literal

from dotenv import load_dotenv
from google import genai
from google.genai.errors import ServerError
from pydantic import BaseModel, Field
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

console = Console()

# Define Pydantic Schemas for Structured Output
class VulnerabilityIssue(BaseModel):
    cwe_id: str = Field(description="CWE Identifier, e.g., CWE-78 or CWE-89")
    vulnerability_type: str = Field(description="Short title of the vulnerability")
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = Field(description="Risk severity level")
    explanation: str = Field(description="1-2 sentences on why the code is vulnerable")
    impact: str = Field(description="1 sentence describing the potential security impact")
    remediation_code: str = Field(description="Clean, secure replacement Python snippet")


class SecurityAuditReport(BaseModel):
    summary: str = Field(description="Overall health assessment of the analyzed file")
    issues: List[VulnerabilityIssue] = Field(default_factory=list, description="List of identified vulnerabilities")


# Authentication Setup
load_dotenv()
api_key = os.getenv("GOOGLE_API_KEY")
if not api_key:
    console.print("[bold red]Error:[/bold red] GOOGLE_API_KEY is missing from environment variables.")
    sys.exit(1)

client = genai.Client(api_key=api_key)


def audit_file(file_path: Path) -> SecurityAuditReport:
    """Reads a file and sends it to Gemini with strict schema enforcement and retry logic."""
    try:
        content = file_path.read_text(encoding="utf-8")
    except Exception as e:
        console.print(f"[bold red]Failed to read {file_path}:[/bold red] {e}")
        return SecurityAuditReport(summary="File unreadable", issues=[])

    prompt = (
        "You are a principal application security engineer auditing Python source code.\n"
        "Analyze the following code for security vulnerabilities, logic flaws, and dangerous patterns.\n"
        "Map any issues directly to CWE definitions.\n\n"
        f"Filename: {file_path.name}\n"
        "Code:\n"
        f"{content}\n"
    )

    max_retries = 3
    for attempt in range(max_retries):
        try:
            response = client.models.generate_content(
                model="gemini-3.5-flash",
                contents=prompt,
                config={
                    "response_mime_type": "application/json",
                    "response_schema": SecurityAuditReport,
                },
            )
            return SecurityAuditReport.model_validate_json(response.text)
        except ServerError as e:
            if "503" in str(e) and attempt < max_retries - 1:
                console.print(f"[bold yellow]Model busy (503). Retrying in 5 seconds (attempt {attempt + 1}/{max_retries})...[/bold yellow]")
                time.sleep(5)
                continue
            raise e


def render_report(file_path: Path, report: SecurityAuditReport):
    """Renders the structured report using Rich tables and panels."""
    console.print(Panel(f"[bold]Target File:[/bold] {file_path}\n[dim]{report.summary}[/dim]", title="Audit Results", expand=False))

    if not report.issues:
        console.print("[bold green]✓ No vulnerabilities identified.[/bold green]\n")
        return

    table = Table(title=f"Findings: {file_path.name}", show_header=True, header_style="bold magenta")
    table.add_column("Severity", justify="center", width=12)
    table.add_column("CWE", justify="center", width=12)
    table.add_column("Type", width=24)
    table.add_column("Impact", width=40)

    severity_colors = {
        "CRITICAL": "bold red on white",
        "HIGH": "bold red",
        "MEDIUM": "bold yellow",
        "LOW": "cyan",
    }

    for issue in report.issues:
        color = severity_colors.get(issue.severity, "white")
        table.add_row(
            f"[{color}]{issue.severity}[/{color}]",
            issue.cwe_id,
            issue.vulnerability_type,
            issue.impact,
        )

    console.print(table)

    # Render remediations
    for idx, issue in enumerate(report.issues, start=1):
        console.print(f"\n[bold yellow]Remediation #{idx}: {issue.vulnerability_type} ({issue.cwe_id})[/bold yellow]")
        console.print(f"[dim]{issue.explanation}[/dim]")
        syntax = Syntax(issue.remediation_code, "python", theme="monokai", line_numbers=True)
        console.print(syntax)
    console.print("-" * 60)


def main():
    parser = argparse.ArgumentParser(description="AI-Powered SAST CLI Code Auditor")
    parser.add_argument("target", help="File or folder path to scan")
    args = parser.parse_args()

    target_path = Path(args.target)
    if not target_path.exists():
        console.print(f"[bold red]Target path '{args.target}' does not exist.[/bold red]")
        sys.exit(1)

    files_to_scan = []
    if target_path.is_file():
        if target_path.suffix == ".py":
            files_to_scan.append(target_path)
    elif target_path.is_dir():
        files_to_scan = [p for p in target_path.rglob("*.py") if "venv" not in p.parts and ".git" not in p.parts]

    if not files_to_scan:
        console.print("[yellow]No Python files found to scan.[/yellow]")
        return

    console.print(f"Discovered [bold cyan]{len(files_to_scan)}[/bold cyan] Python file(s) for security auditing...\n")

    for file in files_to_scan:
        report = audit_file(file)
        render_report(file, report)


if __name__ == "__main__":
    main()