"""SecureShield CLI entrypoint."""

from __future__ import annotations

import csv
import shutil
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import click

from secureshield import __version__
from secureshield.banner import banner_environment, resolve_banner_mode, show_banner
from secureshield.db import database_health
from secureshield.reports import export_report_csv, export_report_json, export_report_markdown
from secureshield.repository import list_scan_history, save_scan_result
from secureshield.scanner import ScannerError, SecureShieldScanner


BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
FRONTEND_SRC_DIR = FRONTEND_DIR / "src"
FRONTEND_DIST_DIR = BASE_DIR / "frontend" / "dist"
STATIC_DIR = BASE_DIR / "secureshield" / "web" / "static"


def _rows_from_result(result: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for finding in result.get("issues", []):
        rows.append(
            {
                "Module": finding.get("module", "-"),
                "Severity": finding.get("severity", "-"),
                "ID": finding.get("id", "-"),
                "Title": finding.get("title", "-"),
                "Target": finding.get("target", "-"),
            }
        )
    return rows


def _render_table(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "No vulnerabilities found."

    headers = list(rows[0].keys())
    widths = {
        header: max(len(str(header)), *(len(str(row[header])) for row in rows))
        for header in headers
    }

    def format_row(row: dict[str, Any]) -> str:
        return " | ".join(str(row[header]).ljust(widths[header]) for header in headers)

    separator = "-+-".join("-" * widths[header] for header in headers)
    lines = [format_row({header: header for header in headers}), separator]
    lines.extend(format_row(row) for row in rows)
    return "\n".join(lines)


def _write_csv(rows: list[dict[str, Any]], output_path: str | None) -> None:
    if not rows:
        click.echo("No findings available for CSV export.", err=True)
        return

    fieldnames = list(rows[0].keys())
    if output_path:
        destination = Path(output_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        click.echo(f"CSV exported to {destination}")
        return

    writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)


def _sync_frontend_assets() -> str:
    if not FRONTEND_DIST_DIR.exists():
        raise click.ClickException(
            f"Frontend build not found at {FRONTEND_DIST_DIR}. Run `cd {BASE_DIR / 'frontend'} && npm run build` first."
        )

    STATIC_DIR.mkdir(parents=True, exist_ok=True)

    for item in FRONTEND_DIST_DIR.iterdir():
        destination = STATIC_DIR / item.name
        if destination.exists():
            if destination.is_dir():
                shutil.rmtree(destination)
            else:
                destination.unlink()

        if item.is_dir():
            shutil.copytree(item, destination)
        else:
            shutil.copy2(item, destination)

    return f"Frontend assets synced from {FRONTEND_DIST_DIR} to {STATIC_DIR}"


def _latest_mtime(path: Path) -> float:
    if not path.exists():
        return 0.0
    if path.is_file():
        return path.stat().st_mtime
    return max((item.stat().st_mtime for item in path.rglob("*")), default=path.stat().st_mtime)


def _frontend_build_is_stale() -> bool:
    if not FRONTEND_DIST_DIR.exists():
        return True
    source_mtime = max(
        _latest_mtime(FRONTEND_SRC_DIR),
        _latest_mtime(FRONTEND_DIR / "index.html"),
        _latest_mtime(FRONTEND_DIR / "package.json"),
    )
    dist_mtime = _latest_mtime(FRONTEND_DIST_DIR)
    return source_mtime > dist_mtime


def _build_frontend() -> str:
    if not FRONTEND_DIR.exists():
        raise click.ClickException(f"Frontend directory not found at {FRONTEND_DIR}")

    try:
        completed = subprocess.run(
            ["npm", "run", "build"],
            cwd=FRONTEND_DIR,
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise click.ClickException("npm is not installed or not available in PATH.") from exc
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip() or exc.stdout.strip() or "npm build failed."
        raise click.ClickException(f"Frontend build failed: {stderr}") from exc

    stdout = completed.stdout.strip()
    detail = f"\n{stdout}" if stdout else ""
    return f"Frontend build completed in {FRONTEND_DIR}{detail}"


def _ensure_frontend_assets() -> list[str]:
    messages: list[str] = []
    if _frontend_build_is_stale():
        messages.append(_build_frontend())
    messages.append(_sync_frontend_assets())
    return messages


@click.group(invoke_without_command=True)
@click.pass_context
def main(ctx: click.Context) -> None:
    """SecureShield terminal commands."""
    if ctx.invoked_subcommand is None:
        show_banner()
        click.echo(ctx.get_help())


@main.command()
@click.argument("image")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json", "csv"], case_sensitive=False),
    default="table",
    show_default=True,
    help="Output format.",
)
@click.option("--output", type=click.Path(dir_okay=False, path_type=str), help="Write output to a file.")
@click.option("--timeout", default=300, show_default=True, type=int, help="Trivy timeout in seconds.")
@click.option(
    "--source-path",
    type=click.Path(exists=True, file_okay=True, dir_okay=True, path_type=str),
    help="Optional local source path for integrated secrets scanning.",
)
def scan(image: str, output_format: str, output: str | None, timeout: int, source_path: str | None) -> None:
    """Run the full SecureShield scan for a container image."""
    scanner = SecureShieldScanner(timeout=timeout)

    try:
        result = scanner.scan(image, source_path=source_path)
        saved = save_scan_result(scan_type="full", target=image, source_path=result.get("source_path"), result=result)
    except ScannerError as exc:
        raise click.ClickException(str(exc)) from exc

    rows = _rows_from_result(result)
    summary = result["summary"]

    if output_format == "json":
        payload = json.dumps(result, indent=2)
        if output:
            Path(output).write_text(payload + "\n", encoding="utf-8")
            click.echo(f"JSON exported to {output}")
        else:
            click.echo(payload)
        return

    if output_format == "csv":
        _write_csv(rows, output)
        return

    header = (
        f"Image: {result['image']}\n"
        f"Saved Scan ID: {saved['id']}\n"
        f"Security Score: {result['security_score']}/100\n"
        f"Total: {summary['total']} | Critical: {summary['critical']} | High: {summary['high']} | "
        f"Medium: {summary['medium']} | Low: {summary['low']} | Info: {summary['info']} | Unknown: {summary['unknown']}\n"
    )
    table = _render_table(rows)
    content = f"{header}\n{table}\n"

    if output:
        Path(output).write_text(content, encoding="utf-8")
        click.echo(f"Table exported to {output}")
        return

    click.echo(content.rstrip())


@main.command()
@click.argument("image")
@click.option("--timeout", default=60, show_default=True, type=int, help="Scanner timeout in seconds.")
def cis_check(image: str, timeout: int) -> None:
    """Run CIS-style checks for an image."""
    scanner = SecureShieldScanner(timeout=timeout)
    try:
        result = scanner.scan_cis(image)
        save_scan_result(scan_type="cis", target=image, result=result)
    except ScannerError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps(result, indent=2))


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=str))
def secrets_scan(path: str) -> None:
    """Scan a local project path for secrets."""
    scanner = SecureShieldScanner()
    try:
        result = scanner.scan_secrets(path)
        save_scan_result(scan_type="secrets", target=path, source_path=path, result=result)
    except ScannerError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps(result, indent=2))


@main.command()
@click.argument("image")
@click.option("--timeout", default=60, show_default=True, type=int, help="Scanner timeout in seconds.")
def supply_chain_check(image: str, timeout: int) -> None:
    """Run supply-chain checks for an image."""
    scanner = SecureShieldScanner(timeout=timeout)
    try:
        result = scanner.scan_supply_chain(image)
        save_scan_result(scan_type="supply_chain", target=image, result=result)
    except ScannerError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps(result, indent=2))


@main.command()
@click.argument("target")
@click.option("--timeout", default=60, show_default=True, type=int, help="Scanner timeout in seconds.")
def runtime_check(target: str, timeout: int) -> None:
    """Run runtime checks for a running container or image name."""
    scanner = SecureShieldScanner(timeout=timeout)
    try:
        result = scanner.scan_runtime(target)
        save_scan_result(scan_type="runtime", target=target, result=result)
    except ScannerError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps(result, indent=2))


@main.command()
@click.option("--limit", default=10, show_default=True, type=int, help="Number of scan records to show.")
@click.option(
    "--scan-type",
    type=click.Choice(["full", "cis", "runtime", "secrets", "supply_chain"], case_sensitive=False),
    help="Filter history by scan type.",
)
def history(limit: int, scan_type: str | None) -> None:
    """Show persisted scan history."""
    try:
        result = list_scan_history(limit=limit, scan_type=scan_type)
    except Exception as exc:
        raise click.ClickException(f"Unable to read scan history: {exc}") from exc
    click.echo(json.dumps(result, indent=2))


@main.command(name="report-export")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "csv", "md"], case_sensitive=False),
    default="json",
    show_default=True,
    help="Export format.",
)
@click.option("--output", required=True, type=click.Path(dir_okay=False, path_type=str), help="Write report to a file.")
@click.option("--limit", default=50, show_default=True, type=int, help="Number of records to include.")
@click.option(
    "--scan-type",
    type=click.Choice(["full", "cis", "runtime", "secrets", "supply_chain"], case_sensitive=False),
    help="Filter report by scan type.",
)
def report_export(output_format: str, output: str, limit: int, scan_type: str | None) -> None:
    """Export aggregate report data for demos and documentation."""
    try:
        payload = (
            export_report_csv(limit=limit, scan_type=scan_type)
            if output_format == "csv"
            else export_report_markdown(limit=limit, scan_type=scan_type)
            if output_format == "md"
            else export_report_json(limit=limit, scan_type=scan_type)
        )
    except Exception as exc:
        raise click.ClickException(f"Unable to export report: {exc}") from exc

    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(payload, encoding="utf-8")
    click.echo(f"Report exported to {destination}")


@main.command(name="sync-ui")
def sync_ui() -> None:
    """Copy frontend build output into the API static directory."""
    click.echo(_sync_frontend_assets())


@main.command(name="build-ui")
def build_ui() -> None:
    """Build the frontend and sync it into the API static directory."""
    for message in _ensure_frontend_assets():
        click.echo(message)


@main.command()
def db_health() -> None:
    """Check database connectivity."""
    try:
        result = database_health()
    except Exception as exc:
        raise click.ClickException(f"Database health check failed: {exc}") from exc
    click.echo(json.dumps(result, indent=2))


@main.command()
@click.option("--host", default="0.0.0.0", show_default=True, help="Bind host.")
@click.option("--port", default=8000, show_default=True, type=int, help="Bind port.")
@click.option("--reload/--no-reload", default=False, show_default=True, help="Enable autoreload.")
def serve(host: str, port: int, reload: bool) -> None:
    """Run the SecureShield web API."""
    os.environ.pop("PYTHONPATH", None)
    sys.path.insert(0, str(BASE_DIR))
    try:
        import uvicorn
    except ModuleNotFoundError as exc:
        raise click.ClickException(
            "uvicorn is not installed. Install dependencies from requirements.txt first."
        ) from exc

    try:
        for message in _ensure_frontend_assets():
            click.echo(message)
    except click.ClickException as exc:
        click.echo(str(exc), err=True)

    show_banner()
    # Tanglish: CLI la irundhu web API direct-a start panna idhu use ஆகும்.
    uvicorn.run("secureshield.web.api:app", host=host, port=port, reload=reload)


@main.command(name="version")
def version_command() -> None:
    """Show the installed SecureShield version."""
    click.echo(f"SecureShield {__version__}")


@main.command(name="banner-test")
def banner_test() -> None:
    """Show banner mode detection details."""
    click.echo(json.dumps({"mode": resolve_banner_mode(), "environment": banner_environment()}, indent=2))


if __name__ == "__main__":
    main()
