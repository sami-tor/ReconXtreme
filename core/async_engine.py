"""
Asynchronous execution engine for ReconXtreme

This module provides the core async functionality for concurrent task execution.
"""
import asyncio
import time
from typing import List, Dict, Any, Callable, Coroutine, TypeVar, Optional, Union, Set
from concurrent.futures import ThreadPoolExecutor
import logging

from core.logger import get_module_logger

# Type definitions
T = TypeVar('T')
TaskResult = TypeVar('TaskResult')
AsyncFunction = Callable[..., Coroutine[Any, Any, TaskResult]]

logger = get_module_logger("async_engine")

class AsyncEngine:
    """
    Asynchronous task execution engine for ReconXtreme
    
    This class provides functionality to:
    - Run multiple coroutines concurrently
    - Limit concurrency with semaphores
    - Handle task timeouts and retries
    - Execute CPU-bound tasks in a thread pool
    """
    
    def __init__(
        self, 
        max_concurrent_tasks: int = 10,
        timeout: int = 30,
        retry_count: int = 3,
        retry_delay: int = 2
    ):
        """
        Initialize the AsyncEngine
        
        Args:
            max_concurrent_tasks (int): Maximum number of concurrent tasks
            timeout (int): Default timeout for tasks in seconds
            retry_count (int): Default number of retries for failed tasks
            retry_delay (int): Default delay between retries in seconds
        """
        self.max_concurrent_tasks = max_concurrent_tasks
        self.timeout = timeout
        self.retry_count = retry_count
        self.retry_delay = retry_delay
        self.semaphore = asyncio.Semaphore(max_concurrent_tasks)
        self.thread_pool = ThreadPoolExecutor()
        self.running_tasks: Set[asyncio.Task] = set()
    
    async def run_task(
        self, 
        coro: Coroutine[Any, Any, TaskResult], 
        timeout: Optional[int] = None,
        retry_count: Optional[int] = None,
        retry_delay: Optional[int] = None
    ) -> TaskResult:
        """
        Run a single async task with timeout and retry logic
        
        Args:
            coro: Coroutine to execute
            timeout: Task-specific timeout (or None to use default)
            retry_count: Task-specific retry count (or None to use default)
            retry_delay: Task-specific retry delay (or None to use default)
            
        Returns:
            The result of the coroutine
        """
        timeout = timeout or self.timeout
        retry_count = retry_count or self.retry_count
        retry_delay = retry_delay or self.retry_delay
        
        for attempt in range(retry_count + 1):
            try:
                async with self.semaphore:
                    if attempt > 0:
                        logger.debug(f"Retry attempt {attempt}/{retry_count}")
                    
                    # Run the task with timeout
                    return await asyncio.wait_for(coro, timeout=timeout)
            
            except asyncio.TimeoutError:
                if attempt < retry_count:
                    logger.debug(f"Task timed out after {timeout}s, retrying in {retry_delay}s")
                    await asyncio.sleep(retry_delay)
                else:
                    logger.warning(f"Task timed out after {timeout}s, giving up after {retry_count} retries")
                    raise
            
            except Exception as e:
                if attempt < retry_count:
                    logger.debug(f"Task failed with error: {e}, retrying in {retry_delay}s")
                    await asyncio.sleep(retry_delay)
                else:
                    logger.warning(f"Task failed with error: {e}, giving up after {retry_count} retries")
                    raise
    
    async def gather(
        self, 
        coroutines: List[Coroutine[Any, Any, TaskResult]],
        return_exceptions: bool = False
    ) -> List[TaskResult]:
        """
        Run multiple coroutines concurrently with controlled concurrency
        
        Args:
            coroutines: List of coroutines to execute
            return_exceptions: Whether to return exceptions instead of raising them
            
        Returns:
            List of results from the coroutines
        """
        tasks = [self.run_task(coro) for coro in coroutines]
        return await asyncio.gather(*tasks, return_exceptions=return_exceptions)
    
    async def map(
        self, 
        func: AsyncFunction,
        iterable: List[Any],
        *args,
        return_exceptions: bool = False,
        **kwargs
    ) -> List[TaskResult]:
        """
        Apply an async function to each item in an iterable concurrently
        
        Args:
            func: Async function to apply to each item
            iterable: List of items to process
            *args: Additional positional arguments to pass to func
            return_exceptions: Whether to return exceptions instead of raising them
            **kwargs: Additional keyword arguments to pass to func
            
        Returns:
            List of results from the function calls
        """
        coroutines = [func(item, *args, **kwargs) for item in iterable]
        return await self.gather(coroutines, return_exceptions=return_exceptions)
    
    def run_in_thread(self, func: Callable[..., T], *args, **kwargs) -> asyncio.Future[T]:
        """
        Run a CPU-bound function in a thread pool
        
        Args:
            func: Function to execute
            *args: Positional arguments to pass to the function
            **kwargs: Keyword arguments to pass to the function
            
        Returns:
            Future object that will contain the result
        """
        loop = asyncio.get_event_loop()
        return loop.run_in_executor(self.thread_pool, lambda: func(*args, **kwargs))
    
    async def run_tasks_with_progress(
        self,
        coroutines: List[Coroutine[Any, Any, TaskResult]],
        progress_callback: Optional[Callable[[int, int], None]] = None,
        return_exceptions: bool = False
    ) -> List[TaskResult]:
        """
        Run tasks with progress reporting
        
        Args:
            coroutines: List of coroutines to execute
            progress_callback: Optional callback function for progress updates
            return_exceptions: Whether to return exceptions instead of raising them
            
        Returns:
            List of results from the coroutines
        """
        total_tasks = len(coroutines)
        completed_tasks = 0
        results = []
        
        # Set up progress reporting
        if progress_callback:
            progress_callback(completed_tasks, total_tasks)
        
        async def wrapper(coro):
            nonlocal completed_tasks
            try:
                result = await self.run_task(coro)
                results.append(result)
                return result
            except Exception as e:
                if return_exceptions:
                    results.append(e)
                    return e
                else:
                    raise
            finally:
                completed_tasks += 1
                if progress_callback:
                    progress_callback(completed_tasks, total_tasks)
        
        # Create and schedule all tasks
        tasks = [wrapper(coro) for coro in coroutines]
        await asyncio.gather(*tasks, return_exceptions=return_exceptions)
        
        return results
    
    def shutdown(self):
        """Shutdown the thread pool executor"""
        self.thread_pool.shutdown(wait=True)