import pytest

from app.evaluation.agent import compute_metrics, grade_trial, run_scripted_trial
from app.evaluation.agent.loader import load_agent_dataset


@pytest.mark.asyncio
async def test_versioned_scripted_dataset_runs_through_production_investigator():
    dataset = load_agent_dataset()
    assert len(dataset.cases) == len(dataset.manifest.case_files)
    trials = []
    grades = []
    for case in dataset.cases:
        trial = await run_scripted_trial(case, interrupt_after_tool=case.annotation.durability_case)
        trials.append(trial)
        grades.append(grade_trial(case, trial))
    metrics = compute_metrics(grades, trials)
    assert all(grade.passed for grade in grades), [grade.model_dump() for grade in grades]
    assert metrics.classification_metrics_measured is False
    assert metrics.case_count == len(dataset.cases)
