import re

with open('app/schemas.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Replace Policy schemas
policy_regex = re.compile(r'class PolicyBase\(BaseModel\):.*?class PolicyOut\(PolicyBase\):.*?created_at: datetime\n', re.DOTALL)

pam_policy_code = '''class PamPolicyBase(BaseModel):
    policy_id: str
    category: str
    name: str
    description: str | None = None
    status: str = "disabled"
    value_json: str | None = None
    scope: str = "global"
    scope_target: str | None = None
    priority: int = 100
    exceptions_json: str | None = None


class PamPolicyCreate(PamPolicyBase):
    pass


class PamPolicyUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    status: str | None = None
    value_json: str | None = None
    scope: str | None = None
    scope_target: str | None = None
    priority: int | None = None
    exceptions_json: str | None = None


class PamPolicyOut(PamPolicyBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    updated_at: datetime
    created_by_id: int | None = None
    updated_by_id: int | None = None


class PolicyDefinitionOut(BaseModel):
    policy_id: str
    name: str
    description: str
    category: str
    value_type: str
    default_value: Any | None = None
    allowed_scopes: list[str]
'''

content = policy_regex.sub(pam_policy_code, content)

# 2. Remove PolicyRule schemas
policy_rule_regex = re.compile(r'class PolicyRuleBase\(BaseModel\):.*?class PolicyRuleOut\(PolicyRuleBase\):.*?updated_by: int \| None = None\n', re.DOTALL)
content = policy_rule_regex.sub('', content)

with open('app/schemas.py', 'w', encoding='utf-8') as f:
    f.write(content)
