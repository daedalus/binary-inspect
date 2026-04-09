"""CLI interface for Binary Inspector."""

import click
from rich.console import Console
from rich.table import Table

from binary_inspect import (
    BinaryReader,
    BinarySearch,
    DataInspector,
    EntropyAnalyzer,
    Exporter,
    MagicDetector,
)

console = Console()


@click.group()
@click.version_option(version="0.1.0")
def main() -> None:
    """Binary Inspector - Analyze unknown binary files."""
    pass


@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--endian", "-e", type=click.Choice(["little", "big"]), default="little")
def analyze(file: str, endian: str) -> None:
    """Analyze a binary file with auto-detection."""
    with open(file, "rb") as f:
        data = f.read()

    console.print(f"[bold]Analyzing:[/bold] {file} ({len(data)} bytes)")

    # Magic detection
    detector = MagicDetector()
    matches = detector.detect(data)

    if matches:
        console.print("\n[bold green]Detected Format:[/bold green]")
        for match in matches:
            console.print(
                f"  - {match.format_name}: {match.description} (confidence: {match.confidence:.1%})"
            )
    else:
        console.print("[yellow]No known format detected[/yellow]")

    # Data inspector at offset 0
    inspector = DataInspector(endian)
    results = inspector.inspect(data, 0)

    if results:
        console.print("\n[bold]Data at offset 0x00:[/bold]")
        table = Table(show_header=True)
        table.add_column("Type", style="cyan")
        table.add_column("Value", style="green")
        table.add_column("Size")

        for r in results:
            table.add_row(r["type"], r["value"], str(r["size"]))

        console.print(table)

    # Entropy
    entropy = EntropyAnalyzer()
    overall = entropy.shannon_entropy(data)
    console.print(f"\n[bold]Overall Entropy:[/bold] {overall:.2f} / 8.0 bits")

    # Show high entropy regions
    regions = entropy.find_high_entropy_regions(data, min_length=32)
    if regions:
        console.print("\n[bold yellow]High-Entropy Regions:[/bold yellow]")
        for region in regions[:5]:
            console.print(
                f"  0x{region.start:08X} - 0x{region.end:08X} (entropy: {region.entropy:.2f})"
            )


@main.command()
@click.argument("file", type=click.Path(exists=True))
def detect(file: str) -> None:
    """Detect file format using magic bytes."""
    with open(file, "rb") as f:
        data = f.read(256)  # Read first 256 bytes for detection

    detector = MagicDetector()
    matches = detector.detect(data)

    if matches:
        console.print("[bold]Detected Formats:[/bold]")
        table = Table(show_header=True)
        table.add_column("Format", style="cyan")
        table.add_column("Description")
        table.add_column("Confidence")

        for match in matches:
            table.add_row(
                match.format_name, match.description, f"{match.confidence:.1%}"
            )

        console.print(table)
    else:
        console.print("[yellow]Unknown format[/yellow]")


@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.argument("offset", type=click.INT, default=0)
@click.option("--endian", "-e", type=click.Choice(["little", "big"]), default="little")
def inspect(file: str, offset: int, endian: str) -> None:
    """Inspect data at specific offset."""
    with open(file, "rb") as f:
        data = f.read()

    inspector = DataInspector(endian)
    results = inspector.inspect(data, offset)

    console.print(f"[bold]Inspecting offset 0x{offset:08X}:[/bold]")

    table = Table(show_header=True)
    table.add_column("Name", style="cyan")
    table.add_column("Type")
    table.add_column("Value", style="green")
    table.add_column("Raw Bytes")

    for r in results:
        table.add_row(r["name"], r["type"], r["value"], r["raw"])

    console.print(table)


@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option(
    "--pattern", "-p", type=click.Path(exists=True), help="Pattern file (.pybip)"
)
@click.option("--endian", "-e", type=click.Choice(["little", "big"]), default="little")
@click.option("--output", "-o", type=click.Path(), help="Output file")
@click.option(
    "--format", "-f", type=click.Choice(["json", "csv", "yaml"]), default="json"
)
def parse(
    file: str, pattern: str | None, endian: str, output: str | None, format: str
) -> None:
    """Parse binary with optional pattern."""
    with open(file, "rb") as f:
        data = f.read()

    fields = []

    if pattern:
        # Load and apply pattern
        import json

        with open(pattern) as f:
            pattern_data = json.load(f)

        # Convert JSON to pattern directly
        if "fields" in pattern_data:
            for field in pattern_data["fields"]:
                field_type = field.get("type", "u32")
                name = field.get("name", "unknown")
                offset_str = field.get("offset", "0x0")
                offset = (
                    int(offset_str, 16) if isinstance(offset_str, str) else offset_str
                )

                reader = BinaryReader(data, endian)
                value = reader.read_type(field_type, offset)
                size = reader.get_size_of_type(field_type)

                from binary_inspect.core.models import ParsedField

                fields.append(
                    ParsedField(
                        name=name,
                        offset=offset,
                        size=size,
                        type_name=field_type,
                        value=value,
                        raw_bytes=data[offset : offset + size],
                    )
                )

    # Export
    exporter = Exporter()
    if format == "json":
        result = exporter.to_json(fields)
    elif format == "csv":
        result = exporter.to_csv(fields)
    else:
        result = exporter.to_yaml(fields)

    if output:
        with open(output, "w") as f:
            f.write(result)
        console.print(f"[green]Exported to {output}[/green]")
    else:
        console.print(result)


@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option(
    "--size", "-s", type=click.INT, default=256, help="Chunk size for entropy"
)
@click.option("--graph", "-g", is_flag=True, help="Show ASCII entropy graph")
def entropy(file: str, size: int, graph: bool) -> None:
    """Calculate entropy of binary file."""
    with open(file, "rb") as f:
        data = f.read()

    analyzer = EntropyAnalyzer()

    # Overall entropy
    overall = analyzer.shannon_entropy(data)
    console.print(f"[bold]Overall Shannon Entropy:[/bold] {overall:.4f} / 8.0 bits")

    if overall > 7.0:
        console.print(
            "[yellow]⚠ High entropy - likely compressed or encrypted[/yellow]"
        )
    elif overall > 5.0:
        console.print("[cyan]⚡ Medium entropy - likely compiled code[/cyan]")
    else:
        console.print("[green]✓ Low entropy - likely plain text or data[/green]")

    # Byte histogram
    hist = analyzer.byte_histogram(data)
    sorted_hist = sorted(hist.items(), key=lambda x: x[1], reverse=True)[:10]

    console.print("\n[bold]Top 10 Most Common Bytes:[/bold]")
    table = Table(show_header=True)
    table.add_column("Byte")
    table.add_column("Hex")
    table.add_column("Count")
    table.add_column("Percentage")

    for byte, count in sorted_hist:
        table.add_row(
            chr(byte) if 32 <= byte < 127 else ".",
            f"0x{byte:02X}",
            str(count),
            f"{count / len(data) * 100:.1f}%",
        )

    console.print(table)

    if graph:
        console.print("\n[bold]Entropy Graph:[/bold]")
        console.print(analyzer.entropy_graph(data, chunk_size=size))


@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option(
    "--min-length", "-m", type=click.INT, default=4, help="Minimum string length"
)
def strings(file: str, min_length: int) -> None:
    """Find strings in binary file."""
    with open(file, "rb") as f:
        data = f.read()

    searcher = BinarySearch(data)
    results = searcher.find_strings(min_length=min_length)

    console.print(f"[bold]Found {len(results)} strings:[/bold]")

    table = Table(show_header=True)
    table.add_column("Offset")
    table.add_column("String")
    table.add_column("Length")

    for r in results:
        table.add_row(f"0x{r['offset']:08X}", r["string"][:60], str(r["length"]))

    console.print(table)


@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--pattern", "-p", required=True, help="Hex pattern to find")
def search(file: str, pattern: str) -> None:
    """Search for hex pattern in binary."""
    with open(file, "rb") as f:
        data = f.read()

    searcher = BinarySearch(data)
    results = searcher.find_hex_pattern(pattern)

    if results:
        console.print(f"[bold]Found {len(results)} matches:[/bold]")
        for offset in results[:20]:
            console.print(f"  0x{offset:08X}")
        if len(results) > 20:
            console.print(f"  ... and {len(results) - 20} more")
    else:
        console.print("[yellow]No matches found[/yellow]")


@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--width", "-w", type=click.INT, default=16, help="Bytes per row")
@click.option("--offset", "-o", type=click.INT, default=0, help="Start offset")
@click.option("--length", "-l", type=click.INT, default=256, help="Bytes to display")
def hexview(file: str, width: int, offset: int, length: int) -> None:
    """Display hex dump of binary file."""
    with open(file, "rb") as f:
        f.seek(offset)
        data = f.read(length)

    console.print(
        f"[bold]Hex dump: {file} (offset: 0x{offset:08X}, {len(data)} bytes)[/bold]"
    )

    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        console.print(f"{offset + i:08X}  {hex_part:<{width * 3}}  {ascii_part}")


if __name__ == "__main__":
    main()
