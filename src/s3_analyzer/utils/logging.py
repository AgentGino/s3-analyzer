# src/s3_analyzer/utils/logging.py
import logging
import sys
from pathlib import Path
from typing import Optional
from rich.logging import RichHandler

def setup_logging(debug: bool = False, log_file: Optional[Path] = None) -> logging.Logger:
    """Configure logging with console and file handlers."""
    # Create logger
    logger = logging.getLogger("s3_analyzer")
    logger.setLevel(logging.DEBUG if debug else logging.INFO)

    # Remove existing handlers
    logger.handlers = []

    # Console handler with rich formatting
    console_handler = RichHandler(
        rich_tracebacks=True,
        markup=True,
        show_path=debug
    )
    console_handler.setLevel(logging.DEBUG if debug else logging.INFO)
    logger.addHandler(console_handler)

    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger