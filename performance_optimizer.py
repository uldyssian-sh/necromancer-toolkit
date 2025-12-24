#!/usr/bin/env python3
"""
Performance Optimizer for Large Dataset Processing
Optimizes memory usage and processing speed for large-scale data operations.

Use of this code is at your own risk.
Author bears no responsibility for any damages caused by the code.
"""

import gc
import sys
import time
import psutil
import threading
from typing import Iterator, Dict, Any, Optional, Callable
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import logging
from datetime import datetime
import weakref

@dataclass
class PerformanceMetrics:
    """Performance metrics tracking."""
    start_time: datetime
    end_time: Optional[datetime] = None
    memory_peak_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    processing_rate_per_sec: float = 0.0
    items_processed: int = 0

class MemoryManager:
    """Advanced memory management for large dataset processing."""
    
    def __init__(self, max_memory_mb: int = 8192):
        self.max_memory_mb = max_memory_mb
        self.logger = logging.getLogger('MemoryManager')
        self._object_pool = weakref.WeakSet()
        self._gc_threshold = max_memory_mb * 0.8  # Trigger GC at 80%
        
    def get_memory_usage(self) -> float:
        """Get current memory usage in MB."""
        process = psutil.Process()
        return process.memory_info().rss / 1024 / 1024
    
    def check_memory_pressure(self) -> bool:
        """Check if memory usage is approaching limits."""
        current_usage = self.get_memory_usage()
        return current_usage > self._gc_threshold
    
    def force_garbage_collection(self):
        """Force garbage collection to free memory."""
        self.logger.debug("Forcing garbage collection")
        collected = gc.collect()
        self.logger.debug(f"Garbage collection freed {collected} objects")
    
    def optimize_memory_usage(self):
        """Optimize memory usage through various techniques."""
        if self.check_memory_pressure():
            self.force_garbage_collection()
            
            # Clear weak references to unused objects
            self._object_pool.clear()
            
            # Optimize Python's memory allocator
            if hasattr(sys, '_clear_type_cache'):
                sys._clear_type_cache()

class DataStreamer:
    """Streaming data processor for large datasets."""
    
    def __init__(self, chunk_size: int = 1000, max_workers: int = 4):
        self.chunk_size = chunk_size
        self.max_workers = max_workers
        self.logger = logging.getLogger('DataStreamer')
        self.memory_manager = MemoryManager()
        
    def stream_process(self, data_source: Iterator, 
                      processor: Callable, 
                      output_handler: Callable = None) -> PerformanceMetrics:
        """
        Stream process large dataset with memory optimization.
        
        Args:
            data_source: Iterator providing data chunks
            processor: Function to process each chunk
            output_handler: Optional function to handle processed results
            
        Returns:
            PerformanceMetrics with processing statistics
        """
        metrics = PerformanceMetrics(start_time=datetime.now())
        
        try:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                chunk_count = 0
                
                for chunk in self._chunked_iterator(data_source):
                    # Check memory pressure before processing
                    if self.memory_manager.check_memory_pressure():
                        self.memory_manager.optimize_memory_usage()
                    
                    # Process chunk
                    future = executor.submit(processor, chunk)
                    result = future.result()
                    
                    if output_handler:
                        output_handler(result)
                    
                    chunk_count += 1
                    metrics.items_processed += len(chunk) if hasattr(chunk, '__len__') else 1
                    
                    # Update metrics
                    current_memory = self.memory_manager.get_memory_usage()
                    metrics.memory_peak_mb = max(metrics.memory_peak_mb, current_memory)
                    
                    # Log progress periodically
                    if chunk_count % 100 == 0:
                        self.logger.info(f"Processed {chunk_count} chunks, "
                                       f"Memory: {current_memory:.1f}MB")
        
        except Exception as e:
            self.logger.error(f"Stream processing failed: {e}")
            raise
        
        finally:
            metrics.end_time = datetime.now()
            duration = (metrics.end_time - metrics.start_time).total_seconds()
            metrics.processing_rate_per_sec = metrics.items_processed / duration if duration > 0 else 0
            
        return metrics
    
    def _chunked_iterator(self, iterator: Iterator, chunk_size: int = None) -> Iterator:
        """Convert iterator into chunked batches."""
        chunk_size = chunk_size or self.chunk_size
        chunk = []
        
        for item in iterator:
            chunk.append(item)
            
            if len(chunk) >= chunk_size:
                yield chunk
                chunk = []
                
                # Memory optimization between chunks
                if self.memory_manager.check_memory_pressure():
                    self.memory_manager.optimize_memory_usage()
        
        # Yield remaining items
        if chunk:
            yield chunk

class ParallelProcessor:
    """Parallel processing engine with performance optimization."""
    
    def __init__(self, max_processes: int = None, max_threads: int = None):
        self.max_processes = max_processes or psutil.cpu_count()
        self.max_threads = max_threads or psutil.cpu_count() * 2
        self.logger = logging.getLogger('ParallelProcessor')
        
    def process_parallel(self, data_items: list, 
                        processor: Callable,
                        use_processes: bool = False) -> PerformanceMetrics:
        """
        Process data items in parallel with performance tracking.
        
        Args:
            data_items: List of items to process
            processor: Function to process each item
            use_processes: Use processes instead of threads for CPU-bound tasks
            
        Returns:
            PerformanceMetrics with processing statistics
        """
        metrics = PerformanceMetrics(start_time=datetime.now())
        
        try:
            if use_processes:
                executor_class = ProcessPoolExecutor
                max_workers = self.max_processes
            else:
                executor_class = ThreadPoolExecutor
                max_workers = self.max_threads
            
            with executor_class(max_workers=max_workers) as executor:
                # Submit all tasks
                futures = [executor.submit(processor, item) for item in data_items]
                
                # Collect results with progress tracking
                completed = 0
                for future in futures:
                    try:
                        result = future.result(timeout=300)  # 5 minute timeout
                        completed += 1
                        
                        # Update progress
                        if completed % 1000 == 0:
                            progress = (completed / len(data_items)) * 100
                            self.logger.info(f"Progress: {progress:.1f}% ({completed}/{len(data_items)})")
                            
                    except Exception as e:
                        self.logger.error(f"Task failed: {e}")
                
                metrics.items_processed = completed
                
        except Exception as e:
            self.logger.error(f"Parallel processing failed: {e}")
            raise
        
        finally:
            metrics.end_time = datetime.now()
            duration = (metrics.end_time - metrics.start_time).total_seconds()
            metrics.processing_rate_per_sec = metrics.items_processed / duration if duration > 0 else 0
            
        return metrics

class PerformanceProfiler:
    """Performance profiling and optimization recommendations."""
    
    def __init__(self):
        self.logger = logging.getLogger('PerformanceProfiler')
        self.metrics_history = []
        
    def profile_function(self, func: Callable, *args, **kwargs) -> Dict[str, Any]:
        """
        Profile function execution and provide optimization recommendations.
        
        Args:
            func: Function to profile
            *args, **kwargs: Function arguments
            
        Returns:
            Dictionary with profiling results and recommendations
        """
        # Capture initial state
        initial_memory = psutil.Process().memory_info().rss / 1024 / 1024
        start_time = time.time()
        
        # Execute function
        try:
            result = func(*args, **kwargs)
            success = True
            error = None
        except Exception as e:
            result = None
            success = False
            error = str(e)
        
        # Capture final state
        end_time = time.time()
        final_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        # Calculate metrics
        execution_time = end_time - start_time
        memory_delta = final_memory - initial_memory
        
        profile_result = {
            'function_name': func.__name__,
            'execution_time_seconds': execution_time,
            'memory_usage_mb': final_memory,
            'memory_delta_mb': memory_delta,
            'success': success,
            'error': error,
            'timestamp': datetime.now().isoformat(),
            'recommendations': self._generate_recommendations(execution_time, memory_delta)
        }
        
        self.metrics_history.append(profile_result)
        return profile_result
    
    def _generate_recommendations(self, execution_time: float, memory_delta: float) -> list:
        """Generate performance optimization recommendations."""
        recommendations = []
        
        if execution_time > 60:  # More than 1 minute
            recommendations.append({
                'type': 'performance',
                'message': 'Consider implementing parallel processing for long-running operations',
                'priority': 'high'
            })
        
        if memory_delta > 1000:  # More than 1GB memory increase
            recommendations.append({
                'type': 'memory',
                'message': 'High memory usage detected - consider streaming or chunked processing',
                'priority': 'critical'
            })
        
        if execution_time > 10 and memory_delta > 100:
            recommendations.append({
                'type': 'optimization',
                'message': 'Both time and memory usage are high - review algorithm efficiency',
                'priority': 'high'
            })
        
        return recommendations
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get summary of all profiled functions."""
        if not self.metrics_history:
            return {'message': 'No profiling data available'}
        
        total_functions = len(self.metrics_history)
        successful_functions = sum(1 for m in self.metrics_history if m['success'])
        
        avg_execution_time = sum(m['execution_time_seconds'] for m in self.metrics_history) / total_functions
        avg_memory_usage = sum(m['memory_usage_mb'] for m in self.metrics_history) / total_functions
        
        return {
            'total_functions_profiled': total_functions,
            'successful_executions': successful_functions,
            'success_rate': (successful_functions / total_functions) * 100,
            'average_execution_time': avg_execution_time,
            'average_memory_usage': avg_memory_usage,
            'total_recommendations': sum(len(m['recommendations']) for m in self.metrics_history)
        }

class CacheManager:
    """Intelligent caching system for performance optimization."""
    
    def __init__(self, max_cache_size: int = 1000):
        self.max_cache_size = max_cache_size
        self.cache = {}
        self.access_times = {}
        self.logger = logging.getLogger('CacheManager')
        
    def get(self, key: str) -> Any:
        """Get item from cache."""
        if key in self.cache:
            self.access_times[key] = time.time()
            return self.cache[key]
        return None
    
    def set(self, key: str, value: Any):
        """Set item in cache with LRU eviction."""
        if len(self.cache) >= self.max_cache_size:
            self._evict_lru()
        
        self.cache[key] = value
        self.access_times[key] = time.time()
    
    def _evict_lru(self):
        """Evict least recently used item."""
        if not self.access_times:
            return
        
        lru_key = min(self.access_times.keys(), key=lambda k: self.access_times[k])
        del self.cache[lru_key]
        del self.access_times[lru_key]
        
        self.logger.debug(f"Evicted LRU cache entry: {lru_key}")
    
    def clear(self):
        """Clear all cache entries."""
        self.cache.clear()
        self.access_times.clear()
        self.logger.info("Cache cleared")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            'cache_size': len(self.cache),
            'max_cache_size': self.max_cache_size,
            'utilization_percent': (len(self.cache) / self.max_cache_size) * 100
        }


def optimize_large_dataset_processing(data_source: Iterator, 
                                    processor: Callable,
                                    chunk_size: int = 1000,
                                    max_workers: int = 4) -> PerformanceMetrics:
    """
    Optimized processing function for large datasets.
    
    Args:
        data_source: Iterator providing data
        processor: Function to process data chunks
        chunk_size: Size of processing chunks
        max_workers: Maximum number of worker threads
        
    Returns:
        PerformanceMetrics with processing results
    """
    streamer = DataStreamer(chunk_size=chunk_size, max_workers=max_workers)
    
    def optimized_processor(chunk):
        """Wrapper processor with memory optimization."""
        try:
            result = processor(chunk)
            
            # Force garbage collection for large chunks
            if len(chunk) > 5000:
                gc.collect()
            
            return result
        except Exception as e:
            logging.error(f"Chunk processing failed: {e}")
            raise
    
    return streamer.stream_process(data_source, optimized_processor)


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    # Example data processor
    def sample_processor(data_chunk):
        """Sample data processing function."""
        # Simulate processing
        time.sleep(0.01)
        return [item * 2 for item in data_chunk]
    
    # Example data source
    def sample_data_source():
        """Sample data source generator."""
        for i in range(10000):
            yield i
    
    # Run optimized processing
    metrics = optimize_large_dataset_processing(
        data_source=sample_data_source(),
        processor=sample_processor,
        chunk_size=100,
        max_workers=4
    )
    
    print(f"Processing completed:")
    print(f"Items processed: {metrics.items_processed}")
    print(f"Processing rate: {metrics.processing_rate_per_sec:.2f} items/sec")
    print(f"Peak memory usage: {metrics.memory_peak_mb:.2f} MB")