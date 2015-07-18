import redis
from celery import Celery

from .driller import Driller
import config
import os

backend_url = "redis://%s:%d" % (config.REDIS_HOST, config.REDIS_PORT)
app = Celery('tasks', broker=config.BROKER_URL, backend=backend_url)
redis_pool = redis.ConnectionPool(host=config.REDIS_HOST, port=config.REDIS_PORT, db=config.REDIS_DB)

@app.task
def drill(binary, input, fuzz_bitmap):
    redis_inst = redis.Redis(connection_pool=redis_pool)

    binary_path = os.path.join(config.BINARY_DIR, binary)
    driller = Driller(binary_path, input, fuzz_bitmap, config.QEMU_DIR, redis=redis_inst)
    return driller.drill()