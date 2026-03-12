import time
import logging
from typing import Callable, Any

logger = logging.getLogger(__name__)

def execute_with_retry(func: Callable, max_retries: int = 4, initial_backoff: float = 2.0, *args, **kwargs) -> Any:
    """
    Executes a function with exponential backoff for 429 and RESOURCE_EXHAUSTED errors.
    """
    backoff = initial_backoff
    for attempt in range(max_retries):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            error_msg = str(e)
            if "429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg:
                if attempt == max_retries - 1:
                    logger.error(f"Max retries reached for 429 error: {e}")
                    raise
                logger.warning(f"Rate limited (429/Resource Exhausted). Retrying in {backoff} seconds...")
                time.sleep(backoff)
                backoff *= 2
            else:
                raise
