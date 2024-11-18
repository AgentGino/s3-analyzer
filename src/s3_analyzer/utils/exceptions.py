# src/s3_analyzer/utils/exceptions.py
class S3AnalyzerError(Exception):
    """Base exception for S3 Analyzer."""
    pass

class AWSConnectionError(S3AnalyzerError):
    """Raised when AWS connection fails."""
    pass

class BucketAccessError(S3AnalyzerError):
    """Raised when bucket access is denied."""
    pass

class BucketNotFoundError(S3AnalyzerError):
    """Raised when bucket doesn't exist."""
    pass

class ConfigurationError(S3AnalyzerError):
    """Raised for configuration related errors."""
    pass

class RateLimitError(S3AnalyzerError):
    """Raised when AWS throttles requests."""
    pass