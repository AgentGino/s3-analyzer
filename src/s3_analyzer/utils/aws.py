from typing import Optional
import boto3

def get_session(profile: Optional[str] = None, 
                region: str = 'us-east-1') -> boto3.Session:
    """Create boto3 session with profile."""
    return boto3.Session(profile_name=profile, region_name=region)
