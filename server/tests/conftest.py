import os
import sys
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from app.models import Base
from app.database import get_db, engine as app_engine, async_session as app_async_session
from app.core.crypto import key_manager
from app.core.evidence_vault import evidence_vault
from app.core.policy_engine import policy_engine

# Ensure required directories exist (needed for CI)
_server_dir = os.path.dirname(os.path.dirname(__file__))
os.makedirs(os.path.join(_server_dir, "app", "keys"), exist_ok=True)
os.makedirs(os.path.join(_server_dir, "evidence_store"), exist_ok=True)
os.makedirs(os.path.join(_server_dir, "config"), exist_ok=True)

TEST_DB_URL = "sqlite+aiosqlite:///:memory:"
test_engine = create_async_engine(TEST_DB_URL, echo=False)
TestSession = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)


@pytest_asyncio.fixture
async def db():
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with TestSession() as session:
        yield session
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def client(db: AsyncSession):
    from app.main import app

    # Create tables on the app's own engine (for endpoints using direct async_session)
    async with app_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Override get_db to use test DB
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

    # Cleanup: drop tables on app engine
    async with app_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    app.dependency_overrides.clear()
