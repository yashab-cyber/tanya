from redis.asyncio import Redis
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)

# Redis connection pool
redis_client: Redis = None


async def get_redis() -> Redis:
    """Get Redis client"""
    global redis_client
    if redis_client is None:
        redis_client = Redis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
            max_connections=50,
        )
    return redis_client


async def close_redis():
    """Close Redis connection"""
    global redis_client
    if redis_client:
        await redis_client.close()
        logger.info("Redis connection closed")
