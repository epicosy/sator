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


class TaskWorker(Thread):
    def __init__(self, queue: Queue, logger: LogHandler, func: Callable):
        Thread.__init__(self)
        self.queue = queue
        self.daemon = True
        self.logger = logger
        self.func = func
        self.start()

    def run(self):
        while True:
            (task, callback) = self.queue.get()
            task.start()

            try:
                self.logger.info(f"Running task {task.id}")
                task.result = self.func(**task.assets)
            except Exception as e:
                task.error(str(e))
                raise e.with_traceback(e.__traceback__)
            finally:
                if callback is not None:
                    callback(task)
                self.queue.task_done()
                self.logger.info(f"Task {task.id} duration: {task.duration()}")


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
