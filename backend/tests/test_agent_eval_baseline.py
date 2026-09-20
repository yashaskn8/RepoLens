import json

import pytest

from app.evaluation.agent import (
    assert_report_matches_baseline,
    compute_metrics,
    grade_trial,
    load_baseline,
    load_agent_dataset,
    report_for_dataset,
    run_scripted_trial,
)
from app.evaluation.agent.report import AgentEvalReportMode


@pytest.mark.asyncio
async def test_committed_baseline_matches_scripted_trajectory():
    dataset = load_agent_dataset()
    baseline = load_baseline(dataset.root + "/baseline.scripted.json")
    trials = []
    grades = []
    for case in dataset.cases:
        trial = await run_scripted_trial(case, interrupt_after_tool=case.annotation.durability_case)
        trials.append(trial)
        grades.append(grade_trial(case, trial))
    report = report_for_dataset(
        dataset,
        mode=AgentEvalReportMode.SCRIPTED,
        grades=grades,
        metrics=compute_metrics(grades, trials),
    )
    assert_report_matches_baseline(report, baseline)
