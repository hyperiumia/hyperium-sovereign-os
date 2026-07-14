import os
import sys

# Override DB URL BEFORE importing any app modules
os.environ["SOS_DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"

# Ensure required directories exist (needed for CI)
_server_dir = os.path.dirname(os.path.dirname(__file__))
os.makedirs(os.path.join(_server_dir, "app", "keys"), exist_ok=True)
os.makedirs(os.path.join(_server_dir, "evidence_store"), exist_ok=True)
os.makedirs(os.path.join(_server_dir, "config"), exist_ok=True)

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from app.models import Base
from app.database import get_db, engine as app_engine
from app.core.crypto import key_manager
from app.core.evidence_vault import evidence_vault
from app.core.policy_engine import policy_engine

# All engines now point to :memory: — both test_engine AND app_engine
TestSession = async_sessionmaker(app_engine, class_=AsyncSession, expire_on_commit=False)


@pytest_asyncio.fixture
async def db():
    async with app_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with TestSession() as session:
        yield session
    async with app_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def client(db: AsyncSession):
    from app.main import app

    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db

    key_manager.initialize()
    evidence_vault._current_epoch = 0
    evidence_vault._events_in_epoch = 0
    evidence_vault._current_tree = evidence_vault._current_tree.__class__()
    await evidence_vault.initialize(db)
    await policy_engine.import_from_yaml(db)
    await policy_engine.load_policies(db)
    await db.commit()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()
