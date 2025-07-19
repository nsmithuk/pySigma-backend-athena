import pytest
from sigma.collection import SigmaCollection

from sigma.backends.athena import athenaBackend


@pytest.fixture
def athena_backend():
    return athenaBackend()


def test_athena_and_expression(athena_backend: athenaBackend):
    assert (
        athena_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
            fields:
            - time_dt
            - metadata.uid as event_id
            - actor.us@er.uid as actor_uid
            - element_at(unmapped, 'serviceEventDetails.account_id') as target_account_id
        """
            )
        )
        == [
            """SELECT time_dt, metadata.uid as event_id, actor."us@er".uid as actor_uid, element_at(unmapped, 'serviceEventDetails.account_id') as target_account_id FROM <TABLE> WHERE LOWER(fieldA) = 'valuea' AND LOWER(fieldB) = 'valueb'"""
        ]
    )
