"""Waiver models for policy exception management."""

from datetime import datetime

from pydantic import BaseModel, Field


class Waiver(BaseModel):
    """A policy exception/waiver that downgrades a hard_block to soft_risk."""

    check_id: str = Field(description="The policy check ID to waive")
    resource_kind: str | None = Field(default=None, description="Optional: specific resource kind")
    resource_name: str | None = Field(default=None, description="Optional: specific resource name")
    namespace: str | None = Field(default=None, description="Optional: specific namespace")
    reason: str = Field(description="Justification for the exception")
    approved_by: str = Field(description="Name/email of approver")
    expires: datetime | None = Field(default=None, description="Optional expiry date")
    created_at: datetime = Field(default_factory=datetime.now)
