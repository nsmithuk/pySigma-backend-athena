from sigma.collection import SigmaCollection

from sigma.backends.athena import athenaBackend


def test_table_name_and_fields():
    backend = athenaBackend(
        table="my_events",
        field_list=["uid", "time", "api.service as api_service", "esc@ped AS esc$ped"],
    )

    assert (
        backend.convert(
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
        """
            )
        )
        == [
            """SELECT uid, time, api.service as api_service, "esc@ped" AS "esc$ped" FROM my_events WHERE LOWER(fieldA) = 'valuea' AND LOWER(fieldB) = 'valueb'"""
        ]
    )


def test_table_name_and_fields_with_function():

    backend = athenaBackend(
        table="my_events",
        field_list=["uid"],
        pre_escaped_field_list=["element_at(f, 'a.b') AS a_b"],
    )

    assert (
        backend.convert(
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
        """
            )
        )
        == [
            """SELECT uid, element_at(f, 'a.b') AS a_b FROM my_events WHERE LOWER(fieldA) = 'valuea' AND LOWER(fieldB) = 'valueb'"""
        ]
    )
