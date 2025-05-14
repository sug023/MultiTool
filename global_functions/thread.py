import threading
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

def thread_scan(worker_function, targets: list, max_threads=250):
    results = []
    threads = []
    queue = Queue()
    progress_bar = tqdm(total=len(targets), desc="[+] Scanning...", ncols=100)

    def worker():
        while True:
            item = queue.get()
            if item is None:
                break
            result = worker_function(*item)
            results.append(result)
            queue.task_done()
            progress_bar.update(1)
    
    for _ in range(max_threads):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)
    
    for target in targets:
        queue.put(target)
    
    queue.join()

    for _ in threads:
        queue.put(None)
    for t in threads:
        t.join()
    
    progress_bar.close()
    return results