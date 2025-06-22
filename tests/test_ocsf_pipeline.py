import os

from sigma.collection import SigmaCollection
from sigma.processing.resolver import ProcessingPipelineResolver

from sigma.backends.athena import athenaBackend


def test_ocsf_pipeline():
    # Get the directory of the current Python file
    current_dir = os.path.dirname(__file__)
    yaml_path = os.path.join(current_dir, "cloudtail.yaml")

    piperesolver = ProcessingPipelineResolver()

    resolved_pipeline = piperesolver.resolve([yaml_path])

    athena_backend = athenaBackend(processing_pipeline=resolved_pipeline)

    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                product: aws
                service: cloudtrail
            detection:
                sel:
                    eventSource: valueA
                    recipientAccountId: valueB
                condition: sel
            """
            )
        )
        == [
            "SELECT * FROM <TABLE> WHERE LOWER(api.service.name) = 'valuea' AND LOWER(accountid) = 'valueb'"
        ]
    )


def test_ocsf_pipeline_when_not_cloudtrail():
    # Get the directory of the current Python file
    current_dir = os.path.dirname(__file__)
    yaml_path = os.path.join(current_dir, "cloudtail.yaml")

    piperesolver = ProcessingPipelineResolver()

    resolved_pipeline = piperesolver.resolve([yaml_path])

    athena_backend = athenaBackend(processing_pipeline=resolved_pipeline)

    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                product: somthing
                service: else
            detection:
                sel:
                    eventSource: valueA
                    recipientAccountId: valueB
                condition: sel
            """
            )
        )
        == [
            "SELECT * FROM <TABLE> WHERE LOWER(eventSource) = 'valuea' AND LOWER(recipientAccountId) = 'valueb'"
        ]
    )
