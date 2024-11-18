import boto3
import pytest
from moto import mock_s3
from s3_analyzer.core.analyzer import S3Analyzer

@mock_s3
def test_list_buckets():
    # Setup
    s3_client = boto3.client('s3', region_name='us-east-1')
    s3_client.create_bucket(Bucket='test-bucket')
    
    # Test
    analyzer = S3Analyzer()
    buckets = analyzer.list_buckets()
    
    # Assert
    assert len(buckets) == 1
    assert buckets[0]['Name'] == 'test-bucket'
