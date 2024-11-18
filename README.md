# S3 Analyzer

A powerful CLI tool for analyzing AWS S3 buckets with advanced filtering capabilities. The tool provides detailed insights into your S3 buckets including size, files, storage classes, encryption status, tags, and more.

## Features

- **Comprehensive Analysis**: Analyze S3 buckets for multiple metrics including:
  - Total size and file count
  - Storage class distribution
  - Encryption status
  - Versioning status
  - Bucket tags
  - Public access status
  - Logging configuration
  - Last modified dates

- **Advanced Filtering**:
  - Filter by bucket name patterns (regex)
  - Filter by file path patterns (regex)
  - Filter by tags
  - Filter by encryption status
  - Filter by versioning status
  - Multiple filter combinations

- **Performance Optimizations**:
  - Async/await pattern for improved performance
  - Batch processing
  - Rate limiting to prevent API throttling
  - Parallel metadata fetching

- **Output Options**:
  - Table format with color coding
  - JSON output for further processing
  - Save results to file
  - Debug logging

## Installation

```bash
# Using pip
pip install s3-analyzer

# From source
git clone https://github.com/AgentGino/s3-analyzer.git
cd s3-analyzer
pip install -e .
```

## Usage

### Basic Usage

```bash
# List all buckets in default region
s3-analyzer

# Specify region
s3-analyzer --region us-west-2

# Use specific AWS profile
s3-analyzer --profile prod-account
```

### Filtering Examples

```bash
# Filter buckets by name pattern
s3-analyzer -b "prod-.*" -b "staging-.*"

# Filter by path pattern
s3-analyzer -p "logs/.*\.gz$"

# Filter by tags
s3-analyzer -f "tags:env=prod"
s3-analyzer -f "tags:team=platform,cost-center=123"

# Filter by encryption status
s3-analyzer -f "encryption:disabled"

# Multiple filters
s3-analyzer -f "tags:env=prod" -f "encryption:disabled" -f "versioning:enabled"

# Complex filtering
s3-analyzer -b "prod-.*" -p "logs/.*" -f "tags:env=prod" -f "encryption:enabled"
```

### Output Options

```bash
# JSON output
s3-analyzer --output json

# Save results to file
s3-analyzer --output json --save results.json

# Enable debug logging
s3-analyzer --debug --log-file analyzer.log
```

### Performance Tuning

```bash
# Adjust rate limiting
s3-analyzer --rate-limit 20

# Modify batch size
s3-analyzer --batch-size 50
```

## Command Line Options

```
Options:
  --profile TEXT                   AWS Profile name
  --region TEXT                    AWS Region [default: us-east-1]
  -b, --buckets TEXT              Bucket name patterns (regex)
  -p, --paths TEXT                Path patterns (regex)
  -f, --filter TEXT               Filters (key:value or key:value1,value2)
  --rate-limit INTEGER            API calls per second [default: 10]
  --batch-size INTEGER            Batch size for processing [default: 100]
  --output [table|json]           Output format [default: table]
  --save PATH                     Save results to file
  --debug                         Enable debug logging
  --log-file PATH                 Log file path
  --help                          Show this message and exit
```

## Filter Keys

The following filter keys are available:

- `tags`: Filter by bucket tags (format: `key=value`)
- `encryption`: Filter by encryption status (`enabled` or `disabled`)
- `versioning`: Filter by versioning status (`enabled` or `disabled`)
- `logging`: Filter by logging status (`enabled` or `disabled`)
- `public_access`: Filter by public access status (`blocked` or `allowed`)

## Output Fields

The tool provides the following information for each bucket:

- Bucket name
- Region
- Total number of files
- Total size (human-readable format)
- Storage class distribution
- Tags
- Encryption status
- Versioning status
- Latest file
- Last modified date
- Public access status
- Logging status

## AWS Credentials

The tool uses standard AWS credential resolution:

1. Command line profile (--profile)
2. Environment variables (AWS_PROFILE, AWS_ACCESS_KEY_ID, etc.)
3. AWS credential file (~/.aws/credentials)
4. IAM role credentials

Required IAM permissions:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "s3:GetBucketLocation",
                "s3:GetBucketTagging",
                "s3:GetBucketEncryption",
                "s3:GetBucketVersioning",
                "s3:GetBucketLogging",
                "s3:GetBucketPublicAccessBlock",
                "s3:ListBucket"
            ],
            "Resource": "*"
        }
    ]
}
```

## Error Handling

- AWS API throttling is handled automatically with rate limiting
- Connection errors are reported clearly
- Invalid filters show helpful error messages
- Debug mode provides detailed error traces

## TODO
- [ ] Add support for filtering by storage class
- [ ] Explicit Disabling analytics on bucket items
- [ ] Cost Analysis
- [ ] Parallel processing
- [ ] Unit Tests


## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Development

```bash
# Setup development environment
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
flake8 s3_analyzer
```
