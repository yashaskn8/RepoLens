"""Closed resource and intervention policy for evaluator-only replay."""

from pydantic import BaseModel, ConfigDict, Field


class CounterfactualReplayPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = "counterfactual-replay-policy/1.1"
    max_interventions_per_trial: int = Field(default=1, ge=1, le=1)
    scripted_branches_per_intervention: int = Field(default=1, ge=1, le=1)
    live_branches_per_intervention: int = Field(default=3, ge=1, le=3)
    max_trials_per_run: int = Field(default=2, ge=1, le=2)
    max_total_branches_per_run: int = Field(default=6, ge=1, le=6)
    max_replay_model_calls_per_branch: int = Field(default=2, ge=0, le=2)
    max_replay_tokens_per_branch: int = Field(default=8_000, ge=0, le=8_000)
    max_total_replay_model_calls: int = Field(default=12, ge=0, le=12)
    max_wall_clock_seconds: int = Field(default=120, ge=1, le=120)
    max_history_checkpoints: int = Field(default=512, ge=1, le=512)


COUNTERFACTUAL_REPLAY_POLICY = CounterfactualReplayPolicy()
