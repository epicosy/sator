import time

from queue import Queue
from typing import Callable, Union
from threading import Thread

import pandas as pd
from cement import Handler
from cement.core.log import LogHandler
from tqdm import tqdm

from sator.core.exc import SatorError
from sator.core.interfaces import HandlersInterface
from sator.data.tasking import Runner, Task

import time
from datetime import datetime, timedelta

class TaskWorker(Thread):
    def __init__(self, queue: Queue, logger: LogHandler, func: Callable):
        Thread.__init__(self)
        self.queue = queue
        self.daemon = True
        self.logger = logger
        self.func = func
        self.start()

    # def run(self):
    #     while True:
    #         (task, callback) = self.queue.get()
    #         task.start()

    #         try:
    #             #self.logger.info(f"Running task {task.id}")
    #             task.result = self.func(**task.assets)
    #         except Exception as e:
    #             task.error(str(e))
    #             raise e.with_traceback(e.__traceback__)
    #         finally:
    #             if callback is not None:
    #                 callback(task)
    #             self.queue.task_done()
    #             #self.logger.info(f"Task {task.id} duration: {task.duration()}")


    # run with fix number retry
    # def run(self):
    #     while True:
    #         task, callback = self.queue.get()  # Get a task
    #         task.start()

    #         max_retries = 3  # Maximum number of retries
    #         retry_delay = 1  # Delay between retries, in seconds
    #         retries = 0

    #         while retries < max_retries:
    #             try:
    #                 self.logger.info(f"Running task {task.id}")
    #                 task.result = self.func(**task.assets)  # Attempt to run the task
    #                 # Task successful, break from retry loop
    #                 break
    #             except Exception as e:
    #                 self.logger.error(f"Task {task.id} failed with error: {str(e)}")
    #                 retries += 1  # Increment the retry counter
    #                 if retries < max_retries:
    #                     self.logger.info(f"Retrying task {task.id} in {retry_delay} seconds (Retry {retries}/{max_retries})")
    #                     time.sleep(retry_delay)  # Wait before retrying
    #                 else:
    #                     # Log final failure after all retries
    #                     self.logger.error(f"Task {task.id} exceeded maximum retries ({max_retries}) and failed.")
    #                     task.error(str(e))  # Record the last error

    #         # Task completion or failure after all retries
    #         if callback is not None and retries <= max_retries:
    #             callback(task)  # Call the callback if provided

    #         self.queue.task_done()  # Mark the task as done in the queue
    #         self.logger.info(f"Task {task.id} completed with {retries} retries.")


    def run(self):
        # Initialize rate limiting parameters
        last_request_time = datetime.now() - timedelta(seconds=30)  # Ensures we don't wait on the first request
        request_count = 0
        # max_requests = 5  
        rate_limit_window = 30  # Seconds
        retry_delay = 10
        while True:
            task, callback = self.queue.get()  # Get a task
            task.start()
            success = False

            while not success:
                try:
                    # Check rate limit
                    current_time = datetime.now()
                    if current_time - last_request_time < timedelta(seconds=rate_limit_window):
                        # if request_count >= max_requests:
                            # Calculate sleep time to reset the rate limit window
                            sleep_time = (last_request_time + timedelta(seconds=rate_limit_window) - current_time).total_seconds()
                            self.logger.info(f"Rate limit reached, sleeping for {sleep_time} seconds")
                            time.sleep(max(sleep_time, 1))  # Sleep at least 1 second to ensure we don't under-sleep due to time precision
                            # Reset rate limit tracking
                            last_request_time = datetime.now()
                            request_count = 0
                    else:
                        # Reset rate limit tracking if we're outside the rate limit window
                        last_request_time = current_time
                        request_count = 0

                    self.logger.info(f"Running task {task.id}")
                    task.result = self.func(**task.assets)  # Attempt to run the task
                    success = True  # Task successful, set success flag
                    request_count += 1  # Increment request count for rate limiting
                finally:
                    abc =1 

                # except Exception as e:
                #     self.logger.error(f"Task {task.id} failed with error: {str(e)}, retrying in {retry_delay} seconds")
                #     time.sleep(retry_delay)  # Wait before retrying

            # Task completion after successful attempt
            if callback is not None:
                callback(task)  # Call the callback if provided

            self.queue.task_done()  # Mark the task as done in the queue
            self.logger.info(f"Task {task.id} completed successfully after retries.")


class ThreadPoolWorker(Thread):
    """Pool of threads consuming tasks from a queue"""
    def __init__(self, runner_data: Runner, threads: int, func: Callable, logger: LogHandler):
        Thread.__init__(self)
        self.runner_data = runner_data
        self.daemon = True
        self.logger = logger
        self.func = func
        self.queue = Queue(threads)
        self.workers = []

        for _ in range(threads):
            self.workers.append(TaskWorker(self.queue, logger, func))

    def run(self):
        for task in tqdm(self.runner_data.tasks):
            self.runner_data.running[task.id] = task
            task.wait()
            # self.logger.info(f"Adding task for {self.nexus_handler.Meta.label} handler to the queue.")
            self.add_task(task)

        """Wait for completion of all the tasks in the queue"""
        self.queue.join()

    def add_task(self, task: Task):
        """Add a task to the queue"""
        if task.status is not None:
            self.queue.put((task, self.runner_data.done))


class MultiTaskHandler(HandlersInterface, Handler):
    """
        Plugin handler abstraction
    """
    class Meta:
        label = 'multi_task'

    def __init__(self, **kw):
        super().__init__(**kw)
        self._runner = None
        self._threads = None
        self._results = []

    @property
    def runner(self):
        if self._runner is None:
            self._runner = Runner()
        return self._runner

    @runner.deleter
    def runner(self):
        self._runner = None

    @property
    def threads(self):
        if self._threads is None:
            self._threads = self.app.get_config('local_threads')
        return self._threads

    def add(self, **kwargs):
        task = Task()
        task.assets = kwargs
        self.runner.add(task)

        return task

    def __call__(self, func: Callable):
        if not isinstance(func, Callable):
            raise SatorError(f"func argument must be a 'Callable'")

        if len(self.runner) == 0:
            self.app.log.warning(f"No tasks added for execution.")
            return

        worker = ThreadPoolWorker(self.runner, threads=self.threads, logger=self.app.log, func=func)
        worker.start()

        while worker.is_alive():
            time.sleep(1)

        # sort by the order of insertion in the queue
        self.runner.finished.sort(key=lambda task: task.id)

    def results(self, expand: bool = False, skip_none: bool = True):
        if not self._results:
            self._results = self.runner.results(skip_none)

            if expand:
                self._results = [res for task in self._results for res in task if not (skip_none and (res is None))]

        return self._results

    def get_tasks(self, as_dict: bool = False, as_frame: bool = False) -> Union[list, pd.DataFrame]:
        if as_dict:
            return [t.to_dict() for t in self.runner.tasks]

        if as_frame:
            df = pd.DataFrame([t.to_dict() for t in self.runner.tasks])
            return df.set_index(df['id']).drop(columns=['id'])

        return self.runner.tasks
