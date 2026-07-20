from sqlalchemy.orm import Session as DBSession

from .engine import PolicyEngine


def get_policy_engine(db: DBSession) -> PolicyEngine:
    return PolicyEngine(db)
