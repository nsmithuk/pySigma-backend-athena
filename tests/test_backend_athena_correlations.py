import pytest
from sigma.collection import SigmaCollection

from sigma.backends.athena import athenaBackend
from tests.test_backend_athena import athena_backend


# Correlation tests - delete whole file if your backend doesn't supports correlation rules.
def test_event_count_correlation_rule_stats_query(athena_backend: athenaBackend):
    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule
name: base_rule
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
        fieldB: value2
    condition: selection
---
title: Multiple occurrences of base event
status: test
correlation:
    type: event_count
    rules:
        - base_rule
    group-by:
        - fieldC
        - fieldD
    timespan: 15m
    condition:
        gte: 10
            """
    )
    assert athena_backend.convert(correlation_rule) == [
        """WITH event_counts AS (SELECT *, COUNT(*) OVER """
        """(PARTITION BY fieldC, fieldD ORDER BY time RANGE BETWEEN INTERVAL '900' SECOND PRECEDING AND CURRENT ROW) as event_count """
        """FROM <TABLE> WHERE LOWER(fieldA) = 'value1' AND LOWER(fieldB) = 'value2' ORDER BY time) """
        """SELECT * FROM event_counts WHERE event_count >= 10"""
    ]


def test_value_count_correlation_rule_stats_query(athena_backend):
    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule
name: base_rule
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
        fieldB: value2
    condition: selection
---
title: Multiple occurrences of base event
status: test
correlation:
    type: value_count
    rules:
        - base_rule
    group-by:
        - fieldC
    timespan: 15m
    condition:
        lt: 10
        field: fie@ldD
            """
    )
    with pytest.raises(NotImplementedError) as exc_info:
        athena_backend.convert(correlation_rule)

    # If Athena supported COUNT(DISTINCT x) with OVER(), the below is what we'd expect.
    # assert athena_backend.convert(correlation_rule) == [
    #     """WITH value_counts AS (SELECT *, COUNT(DISTINCT "fie@ldD") """
    #     """OVER (PARTITION BY fieldC ORDER BY time RANGE BETWEEN INTERVAL '900' SECOND PRECEDING AND CURRENT ROW) as value_count """
    #     """FROM <TABLE> WHERE LOWER(fieldA) = 'value1' AND LOWER(fieldB) = 'value2' ORDER BY time) """
    #     """SELECT * FROM value_counts WHERE value_count < 10"""
    # ]


def test_temporal_correlation_rule_stats_query(athena_backend):
    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule 1
name: base_rule_1
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
        fieldB: value2
    condition: selection
---
title: Base rule 2
name: base_rule_2
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value3
        fieldB: value4
    condition: selection
---
title: Temporal correlation rule
status: test
correlation:
    type: temporal
    rules:
        - base_rule_1
        - base_rule_2
    aliases:
        field:
            base_rule_1: fieldC
            base_rule_2: fieldD
    group-by:
        - fieldC
    timespan: 15m
"""
    )
    with pytest.raises(NotImplementedError) as exc_info:
        athena_backend.convert(correlation_rule)


def test_temporal_ordered_correlation_rule_stats_query(athena_backend):
    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule 1
name: base_rule_1
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
        fieldB: value2
    condition: selection
---
title: Base rule 2
name: base_rule_2
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value3
        fieldB: value4
    condition: selection
---
title: Ordered temporal correlation rule
status: test
correlation:
    type: temporal_ordered
    rules:
        - base_rule_1
        - base_rule_2
    aliases:
        field:
            base_rule_1: fieldC
            base_rule_2: fieldD
    group-by:
        - fieldC
    timespan: 15m
"""
    )
    with pytest.raises(NotImplementedError) as exc_info:
        athena_backend.convert(correlation_rule)

def test_event_count_correlation_multi_rule_stats_query(athena_backend: athenaBackend):
    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule 1
name: base_rule1
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
        fieldB: value2
    condition: selection
---
title: Base rule 2
name: base_rule2
status: test
logsource:
    category: test
detection:
    selection:
        fieldA: value1
        fieldB: value2
    condition: selection
---
title: Multiple occurrences of base event
status: test
correlation:
    type: event_count
    rules:
        - base_rule1
        - base_rule2
    group-by:
        - fieldC
        - fieldD
    timespan: 15m
    condition:
        gte: 10
            """
    )
    with pytest.raises(NotImplementedError) as exc_info:
        athena_backend.convert(correlation_rule)
