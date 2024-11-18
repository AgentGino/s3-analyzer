import click
import json
from rich.console import Console
from rich.table import Table
from pathlib import Path
from datetime import datetime
from .core.analyzer import S3Analyzer
from .utils.logging import setup_logging
from .utils.exceptions import S3AnalyzerError, AWSConnectionError

console = Console()

def format_size(size_bytes: int) -> str:
    """Convert bytes to human readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} PB"

def format_datetime(dt) -> str:
    """Format datetime object to string."""
    if isinstance(dt, datetime):
        return dt.isoformat()
    return str(dt) if dt else ''

def print_table(results: list):
    """Print results in table format."""
    table = Table(show_header=True)
    table.add_column("Bucket")
    table.add_column("Region")
    table.add_column("Files")
    table.add_column("Size")
    table.add_column("Storage Classes")
    table.add_column("Tags")
    table.add_column("Encryption")
    table.add_column("Versioning")
    table.add_column("Latest File")
    table.add_column("Last Modified")

    for r in results:
        if 'error' in r:
            table.add_row(
                r['name'],
                r.get('region', ''),
                'ERROR',
                '',
                '',
                '',
                '',
                '',
                '',
                r['error']
            )
        else:
            metadata = r.get('metadata', {})
            tags = ', '.join(f"{k}={v}" for k, v in metadata.get('tags', {}).items())
            storage_classes = ', '.join(
                f"{k}: {v}" for k, v in r.get('storage_classes', {}).items()
            )
            table.add_row(
                r['name'],
                r.get('region', ''),
                str(r['total_files']),
                format_size(r['total_size']),
                storage_classes,
                tags,
                metadata.get('encryption', 'disabled'),
                metadata.get('versioning', 'disabled'),
                r.get('latest_file', ''),
                format_datetime(r.get('last_modified'))
            )

    console.print(table)

@click.command()
@click.option('--profile', help='AWS Profile name')
@click.option('--region', default='us-east-1', help='AWS Region')
@click.option('-b', '--buckets', multiple=True, help='Bucket name patterns (regex)')
@click.option('-p', '--paths', multiple=True, help='Path patterns (regex)')
@click.option('-f', '--filter', multiple=True, help='Filters (key:value or key:value1,value2)')
@click.option('--rate-limit', default=10, help='API calls per second')
@click.option('--batch-size', default=100, help='Batch size for processing')
@click.option('--output', type=click.Choice(['table', 'json']), default='table', help='Output format')
@click.option('--save', type=click.Path(), help='Save results to file')
@click.option('--debug', is_flag=True, help='Enable debug logging')
@click.option('--log-file', type=click.Path(), help='Log file path')
def main(profile: str, region: str, buckets: tuple, paths: tuple,
         filter: tuple, rate_limit: int, batch_size: int, 
         output: str, save: str, debug: bool, log_file: str):
    """Analyze S3 buckets with advanced filtering capabilities.
    
    Examples:
        # Filter by tags
        s3-analyzer -f "tags:env=prod" -f "tags:team=platform"
        
        # Filter by encryption and paths
        s3-analyzer -f "encryption:disabled" -p "logs/.*\.gz$"
        
        # Multiple bucket patterns
        s3-analyzer -b "prod-.*" -b "staging-.*"
        
        # Complex filters
        s3-analyzer -f "tags:env=prod,cost-center=123" -f "versioning:enabled"
    """
    logger = setup_logging(
        debug=debug,
        log_file=Path(log_file) if log_file else None
    )
    
    try:
        # Handle bucket patterns
        bucket_list = []
        for bucket in buckets:
            if ',' in bucket:
                bucket_list.extend([b.strip() for b in bucket.split(',') if b.strip()])
            else:
                bucket_list.append(bucket.strip())

        # Handle path patterns
        path_list = []
        for path in paths:
            if ',' in path:
                path_list.extend([p.strip() for p in path.split(',') if p.strip()])
            else:
                path_list.append(path.strip())

        logger.debug(f"Starting analysis with filters: buckets={bucket_list}, "
                    f"paths={path_list}, filters={filter}")
        
        analyzer = S3Analyzer(
            profile=profile,
            region=region,
            rate_limit=rate_limit,
            batch_size=batch_size,
            buckets=bucket_list if bucket_list else None,
            paths=path_list if path_list else None,
            filters=filter if filter else None
        )
        
        results = analyzer.analyze_all()
        filtered_results = [r for r in results if r is not None]
        
        # Handle output
        if output == 'table':
            print_table(filtered_results)
        else:
            json_results = []
            for r in filtered_results:
                if isinstance(r, dict):
                    result_dict = dict(r)
                    if 'last_modified' in result_dict:
                        result_dict['last_modified'] = format_datetime(result_dict['last_modified'])
                    json_results.append(result_dict)
            console.print_json(data=json_results)

        # Save results if requested
        if save:
            save_data = json_results if output == 'json' else filtered_results
            with open(save, 'w') as f:
                json.dump(save_data, f, indent=2)
            logger.info(f"Results saved to {save}")
            console.print(f"\n[green]Results saved to {save}[/green]")

    except AWSConnectionError as e:
        logger.error(f"AWS Connection Error: {str(e)}")
        console.print(f"[red]AWS Connection Error: {str(e)}[/red]")
        raise click.Abort()
    except S3AnalyzerError as e:
        logger.error(f"Analysis Error: {str(e)}")
        console.print(f"[red]Error: {str(e)}[/red]")
        raise click.Abort()
    except Exception as e:
        logger.error(f"Unexpected error occurred: {str(e)}")
        console.print(f"[red]Unexpected error: {str(e)}[/red]")
        if debug:
            logger.exception("Detailed error trace:")
        raise click.Abort()