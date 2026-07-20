import json
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from app.models import PamPolicy
from app.policy.registry import get_all_policies, PolicyDefinition
import contextvars

_effective_policies: contextvars.ContextVar[Dict[str, Any]] = contextvars.ContextVar("effective_policies", default={})

def get_policy_value(policy_id: str, default: Any = None) -> Any:
    """
    Get an effective policy value. Uses cached context var if available (during a request),
    otherwise queries the DB fresh (for background tasks/gateway).
    """
    cached = _effective_policies.get()
    if cached and policy_id in cached:
        return cached[policy_id]

    from app.database import SessionLocal
    db = SessionLocal()
    try:
        effective = resolve_effective_policies(db)
        return effective.get(policy_id, default)
    except Exception:
        return default
    finally:
        db.close()

def resolve_effective_policies(db: Session, target_user: str = None, target_group: str = None, target_resource: str = None) -> Dict[str, Any]:
    """
    Resolves effective policies based on scope and priority.
    For now, it simply fetches all enabled policies and overrides defaults 
    based on highest priority (lowest number is highest priority).
    """
    effective: Dict[str, Any] = {}
    
    # Set defaults from registry
    for pd in get_all_policies():
        effective[pd.policy_id] = pd.default_value

    # Get active policies, ordered by priority (descending because highest priority is 1)
    policies = db.query(PamPolicy).filter(PamPolicy.status == "enabled").order_by(PamPolicy.priority.desc()).all()

    for policy in policies:
        try:
            if policy.value_json:
                val = json.loads(policy.value_json)
                if policy.policy_id:
                    effective[policy.policy_id] = val
        except:
            pass

    return effective
