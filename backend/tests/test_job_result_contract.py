import pytest
from fastapi import HTTPException

from app.api.routes.jobs import _materialize_result


def test_materialize_result_unwraps_durable_artifact_envelope():
    payload = {"finding_id": "finding-1", "summary": "grounded result"}

    assert _materialize_result({"result_kind": "RESEARCH", "result": payload}) == payload


@pytest.mark.parametrize("envelope", [None, {}, {"result": None}, {"result": ["invalid"]}])
def test_materialize_result_rejects_invalid_artifact_envelope(envelope):
    with pytest.raises(HTTPException) as caught:
        _materialize_result(envelope)

    assert caught.value.status_code == 500
    assert caught.value.detail["error_code"] == "JOB_RESULT_INVALID"
