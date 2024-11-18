import asyncio
import time
import re
from typing import List, Dict, Generator
from concurrent.futures import ThreadPoolExecutor
import aioboto3
from botocore.exceptions import ClientError
from rich.progress import Progress

from ..utils.exceptions import RateLimitError, AWSConnectionError

class RateLimiter:
    def __init__(self, rate_limit: int = 10):
        self.rate_limit = rate_limit
        self.tokens = rate_limit
        self.last_updated = time.time()

    async def acquire(self):
        """Acquire a token for API call."""
        while self.tokens <= 0:
            now = time.time()
            time_passed = now - self.last_updated
            new_tokens = int(time_passed * self.rate_limit)
            
            if new_tokens > 0:
                self.tokens = min(self.rate_limit, self.tokens + new_tokens)
                self.last_updated = now
            else:
                await asyncio.sleep(0.1)
                
        self.tokens -= 1

class BatchProcessor:
    def __init__(self, batch_size: int = 100):
        self.batch_size = batch_size

    def batch_items(self, items: list) -> Generator[list, None, None]:
        """Yield items in batches."""
        for i in range(0, len(items), self.batch_size):
            yield items[i:i + self.batch_size]

class S3Analyzer:
    def __init__(self, profile: str = None, region: str = 'us-east-1',
                 rate_limit: int = 10, batch_size: int = 100,
                 buckets: List[str] = None, paths: List[str] = None,
                 filters: List[str] = None):
        self.profile = profile
        self.region = region
        self.session = aioboto3.Session(profile_name=profile)
        self.rate_limiter = RateLimiter(rate_limit)
        self.batch_processor = BatchProcessor(batch_size)
        self.max_workers = min(32, (batch_size + 1) // 2)
        self.bucket_patterns = [re.compile(p) for p in buckets] if buckets else None
        self.path_patterns = [re.compile(p) for p in paths] if paths else None
        self.filters = self._parse_filters(filters)

    def _parse_filters(self, filters: List[str]) -> Dict[str, List[str]]:
        """Parse filter strings into structured format."""
        parsed = {}
        if not filters:
            return parsed

        for f in filters:
            try:
                key, value = f.split(':', 1)
                key = key.strip().lower()
                values = [v.strip() for v in value.split(',')]
                parsed[key] = values
            except ValueError as e:
                raise S3AnalyzerError(f"Invalid filter format '{f}'. Use 'key:value' format.") from e
        return parsed

    def _match_bucket(self, bucket_name: str) -> bool:
        """Match bucket name against bucketpatterns."""
        if not self.bucket_patterns:
            return True
        return any(pattern.match(bucket_name) for pattern in self.bucket_patterns)

    def _match_path(self, key: str) -> bool:
        """Match object key against path patterns."""
        if not self.path_patterns:
            return True
        return any(pattern.match(key) for pattern in self.path_patterns)

    def _matches_filters(self, metadata: Dict) -> bool:
        """Check if bucket metadata matches filters."""
        if not self.filters:
            return True

        for key, values in self.filters.items():
            if key == 'tags':
                for tag_filter in values:
                    try:
                        tag_key, tag_value = tag_filter.split('=', 1)
                        if tag_key not in metadata['tags'] or metadata['tags'][tag_key] != tag_value:
                            return False
                    except ValueError:
                        continue
            elif key in metadata:
                if not any(metadata[key] == value for value in values):
                    return False
        return True

    async def _get_bucket_metadata(self, s3, bucket: str) -> Dict:
        """Get bucket metadata including tags, encryption, and region."""
        metadata = {
            'name': bucket,
            'region': self.region,
            'tags': {},
            'encryption': 'disabled',
            'versioning': 'disabled',
            'logging': 'disabled',
            'public_access': 'blocked'
        }

        try:
            # Get bucket location
            try:
                location = await s3.get_bucket_location(Bucket=bucket)
                metadata['region'] = location.get('LocationConstraint') or 'us-east-1'
            except ClientError:
                pass

            # Skip if bucket is not in target region
            if metadata['region'] != self.region:
                return None

            # Get all bucket metadata in parallel
            tasks = [
                self._get_bucket_tags(s3, bucket),
                self._get_bucket_encryption(s3, bucket),
                self._get_bucket_versioning(s3, bucket),
                self._get_bucket_logging(s3, bucket),
                self._get_bucket_public_access(s3, bucket)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Update metadata with results
            for result in results:
                if isinstance(result, dict):
                    metadata.update(result)

            return metadata

        except Exception as e:
            return {'name': bucket, 'error': str(e), 'region': self.region}

    async def _get_bucket_tags(self, s3, bucket: str) -> Dict:
        """Get bucket tags."""
        try:
            response = await s3.get_bucket_tagging(Bucket=bucket)
            return {'tags': {tag['Key']: tag['Value'] for tag in response['TagSet']}}
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchTagSet':
                raise
            return {'tags': {}}

    async def _get_bucket_encryption(self, s3, bucket: str) -> Dict:
        """Get bucket encryption status."""
        try:
            await s3.get_bucket_encryption(Bucket=bucket)
            return {'encryption': 'enabled'}
        except ClientError as e:
            if e.response['Error']['Code'] != 'ServerSideEncryptionConfigurationNotFoundError':
                raise
            return {'encryption': 'disabled'}

    async def _get_bucket_versioning(self, s3, bucket: str) -> Dict:
        """Get bucket versioning status."""
        try:
            response = await s3.get_bucket_versioning(Bucket=bucket)
            return {'versioning': response.get('Status', 'disabled').lower()}
        except ClientError:
            return {'versioning': 'disabled'}

    async def _get_bucket_logging(self, s3, bucket: str) -> Dict:
        """Get bucket logging status."""
        try:
            response = await s3.get_bucket_logging(Bucket=bucket)
            return {'logging': 'enabled' if 'LoggingEnabled' in response else 'disabled'}
        except ClientError:
            return {'logging': 'disabled'}

    async def _get_bucket_public_access(self, s3, bucket: str) -> Dict:
        """Get bucket public access status."""
        try:
            response = await s3.get_public_access_block(Bucket=bucket)
            block_config = response.get('PublicAccessBlockConfiguration', {})
            is_blocked = all([
                block_config.get('BlockPublicAcls', False),
                block_config.get('BlockPublicPolicy', False),
                block_config.get('IgnorePublicAcls', False),
                block_config.get('RestrictPublicBuckets', False)
            ])
            return {'public_access': 'blocked' if is_blocked else 'allowed'}
        except ClientError:
            return {'public_access': 'unknown'}

    async def _list_objects(self, s3, bucket: str) -> Dict:
        """List objects with rate limiting and filtering."""
        if not self._match_bucket(bucket):
            return None

        try:
            # Get metadata first
            metadata = await self._get_bucket_metadata(s3, bucket)
            if not metadata or 'error' in metadata or not self._matches_filters(metadata):
                return None

            metrics = {
                'name': bucket,
                'region': metadata['region'],
                'total_size': 0,
                'total_files': 0,
                'storage_classes': {},
                'last_modified': None,
                'latest_file': None,
                'metadata': metadata,
                'error_count': 0
            }

            paginator = s3.get_paginator('list_objects_v2')
            async for page in paginator.paginate(Bucket=bucket):
                await self.rate_limiter.acquire()
                
                if 'Contents' not in page:
                    continue
                    
                for obj in page['Contents']:
                    if not self._match_path(obj['Key']):
                        continue

                    storage_class = obj.get('StorageClass', 'STANDARD')
                    metrics['storage_classes'][storage_class] = \
                        metrics['storage_classes'].get(storage_class, 0) + 1
                    
                    metrics['total_size'] += obj['Size']
                    metrics['total_files'] += 1
                    
                    if not metrics['last_modified'] or \
                       obj['LastModified'] > metrics['last_modified']:
                        metrics['last_modified'] = obj['LastModified']
                        metrics['latest_file'] = obj['Key']

            return metrics if metrics['total_files'] > 0 else None

        except ClientError as e:
            if e.response['Error']['Code'] == 'ThrottlingException':
                raise RateLimitError(f"Rate limit exceeded for bucket {bucket}")
            raise

    async def analyze_buckets(self) -> List[Dict]:
        """Analyze buckets in batches with rate limiting."""
        results = []
        async with self.session.client('s3', region_name=self.region) as s3:
            try:
                response = await s3.list_buckets()
                buckets = response['Buckets']

                with Progress() as progress:
                    task = progress.add_task(
                        f"[cyan]Analyzing buckets in {self.region}...", 
                        total=len(buckets)
                    )

                    for batch in self.batch_processor.batch_items(buckets):
                        batch_tasks = []
                        for bucket in batch:
                            batch_tasks.append((bucket['Name'], self._list_objects(s3, bucket['Name'])))
                        
                        # future: asyncio.Future
                        for bucket_name, future in batch_tasks:
                            try:
                                result = await future
                                if result is not None:
                                    results.append(result)
                            except Exception as e:
                                results.append({
                                    'name': bucket_name,
                                    'error': str(e),
                                    'region': self.region
                                })
                            finally:
                                progress.update(task, advance=1)

                        await asyncio.sleep(0.1)

            except ClientError as e:
                raise AWSConnectionError(f"Failed to list buckets: {str(e)}")

        return results

    def analyze_all(self) -> List[Dict]:
        """Synchronous wrapper for analyze_buckets."""
        return asyncio.run(self.analyze_buckets())