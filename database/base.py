from typing_extensions import Self
from typing import Sequence

from sqlalchemy import select
from sqlalchemy.orm import declarative_base

from .connector import db_conn


Base = declarative_base()


async def init_db(dsn='sqlite+aiosqlite:///db.sqlite3', echo=True):

    print(f"Initializing database : {dsn}")
    db_conn.initialize(dsn=dsn, echo=echo)


class Manager:

    @classmethod
    async def create(cls, **kwargs) -> Self:
        obj = cls(**kwargs)
        async with db_conn.session as session:
            session.add(obj)
            await session.commit()
            await session.refresh(obj)
        return obj

    async def delete(self):
        async with db_conn.session as session:
            await session.delete(self)
            await session.commit()
            return True

    @classmethod
    async def get(cls, **kwargs) -> Self | None:
        async with db_conn.session as session:
            query = select(cls)
            for key, value in kwargs.items():
                if not hasattr(cls, key):
                    raise AttributeError(f"Class {cls.__name__} has no attribute '{key}'")
                query = query.where(getattr(cls, key) == value)
            result = await session.execute(query)
            result = result.scalar_one_or_none()
            return result

    @classmethod
    async def all(cls) -> Sequence[Self]:
        async with db_conn.session as session:
            result = await session.execute(select(cls))
            return result.scalars().all()
