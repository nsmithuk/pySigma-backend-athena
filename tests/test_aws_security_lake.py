import pytest
from sigma.collection import SigmaCollection

from sigma.backends.athena import athenaBackend


def test_event_count_security_lake():
    athena_backend = athenaBackend(time_field="time_dt")

    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule
name: base_rule
status: test
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        api.service.name|cased: sso.amazonaws.com
        api.operation|cased: Federate
    condition: selection
---
title: Multiple occurrences of base event
status: test
correlation:
    type: event_count
    rules:
        - base_rule
    group-by:
        - unmapped.serviceEventDetails.account_id
    timespan: 15m
    condition:
        gte: 1
            """
    )
    assert athena_backend.convert(correlation_rule) == [
        """WITH event_counts AS (SELECT *, COUNT(*) OVER """
        """(PARTITION BY unmapped.serviceEventDetails.account_id ORDER BY time_dt """
        """RANGE BETWEEN INTERVAL '900' SECOND PRECEDING AND CURRENT ROW) as event_count FROM <TABLE> """
        """WHERE api.service.name = 'sso.amazonaws.com' AND api.operation = 'Federate' ORDER BY time_dt) """
        """SELECT * FROM event_counts WHERE event_count >= 1"""
    ]


def test_value_count_security_lake():
    athena_backend = athenaBackend(time_field="time_dt")

    correlation_rule = SigmaCollection.from_yaml(
        """
title: Base rule
name: base_rule
status: test
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        api.service.name|cased: signin.amazonaws.com
        api.operation|cased: ConsoleLogin
    condition: selection
---
title: Low number of unique users with multiple source IPs
status: test
correlation:
    type: value_count
    rules:
        - base_rule
    group-by:
        - src_endpoint.ip
    timespan: 15m
    condition:
        lt: 5
        field: actor.user.uid
            """
    )
    with pytest.raises(NotImplementedError) as exc_info:
        athena_backend.convert(correlation_rule)
