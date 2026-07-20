from typing import Any, Literal

from pydantic import BaseModel, Field


WizardMode=Literal["create_resource","assign_existing_resource","request_access"]


class DraftCreate(BaseModel):
    mode:WizardMode
    resource_type:Literal["ssh","web"]|None=None
    data:dict[str,Any]=Field(default_factory=dict)


class DraftUpdate(BaseModel):
    mode:WizardMode|None=None
    resource_type:Literal["ssh","web"]|None=None
    data:dict[str,Any]|None=None
    completed_steps:list[int]|None=None


class StepValidation(BaseModel):
    mode:WizardMode
    resource_type:Literal["ssh","web"]|None=None
    step:int=Field(ge=1,le=10)
    data:dict[str,Any]


class SecretInput(BaseModel):
    name:str=Field(min_length=1,max_length=128)
    secret_type:str="password"
    value:str=Field(min_length=1,max_length=65536)
    rotating:bool=False


class ConnectionTestIn(BaseModel):
    resource_type:Literal["ssh","web"]
    resource:dict[str,Any]=Field(default_factory=dict)
    connection:dict[str,Any]
    secret_inputs:dict[str,SecretInput]=Field(default_factory=dict)


class WebDiscoveryIn(BaseModel):
    start_url:str=Field(min_length=1,max_length=2048)
    allowed_domains:list[str]=Field(default_factory=list)
    blocked_domains:list[str]=Field(default_factory=list)
    allow_private_network:bool=False


class WizardComplete(BaseModel):
    draft_id:int
    submission_key:str=Field(min_length=8,max_length=64,pattern=r"^[A-Za-z0-9_-]+$")
    secret_inputs:dict[str,SecretInput]=Field(default_factory=dict)
    accept_warnings:bool=False


class CheckResult(BaseModel):
    name:str
    status:Literal["success","warning","error","skipped"]
    message:str
    technical_detail:str|None=None
