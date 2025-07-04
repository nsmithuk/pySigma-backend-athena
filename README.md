![Tests](https://github.com/nsmithuk/pySigma-backend-athena/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/nsmithuk/b932f78b1023d303a0ebf37e6a27f405/raw/9966c79f1f0e377f22c01aecde581ccb63df4c07/pySigma-backend-athena.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma Athena Backend

An AWS Athena backend for pySigma that converts Sigma detection rules into Athena-compatible SQL queries.

While designed for AWS Athena, it likely works with any Trino-based SQL engine.

---

## Features

Most standard Sigma rule features are supported, including logical and comparison operators,
wildcards, regular expressions, CIDR matching, field reference matching, existence checks and case-sensitive matching. 
A handful of operations—like full-text value-only expressions and distinct-count window 
functions—aren't implemented; see the Limitations section below.


## Limitations

- Full-text searches (value-only expressions) are not supported.
- At present, only the `event_count` correlation rule type is supported, and only when a single rule is referenced.

---

[//]: # (## Installation)

[//]: # ()
[//]: # (Install via pip:)

[//]: # ()
[//]: # (```bash)

[//]: # (pip install pySigma-backend-athena)

[//]: # (```)

[//]: # ()
[//]: # (Or with Poetry:)

[//]: # ()
[//]: # (```bash)

[//]: # (poetry add pySigma-backend-athena)

[//]: # (```)

[//]: # ()
[//]: # (---)

## Usage

```python
from sigma.backends.athena import athenaBackend
from sigma.collection import SigmaCollection

# Initialize the backend, optionally specifying table, fields, and time field
backend = athenaBackend(table="my_table", field_list=["*"], time_field="timestamp")

# Load your Sigma rule collection
collection = SigmaCollection.from_yaml("...")

# Convert to Athena SQL
queries = backend.convert(collection)
for q in queries:
    print(q)
```

---

## Supported Correlation Rules

The Athena backend currently supports **event\_count** correlation rules. Other types (`value_count`, `temporal`, `temporal_ordered`) are not implemented and will raise `NotImplementedError`.

### event\_count

- **Type**: `event_count`
- **Parameters**:
  - `rules`: List of Sigma rules to correlate
  - `group-by`: Fields to partition by
  - `timespan`: Window duration (e.g. `15m`, `1h`)
  - `condition`: Comparison operator and threshold (e.g. `gte: 10`)

Generates a sliding time window-function query that counts matching events within the specified timeframe.

#### Example

```yaml
title: Windows Failed Logon
id: dc9f1a2e-7d3b-4f1c-b8f4-1e23eadf4567
status: stable
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection
---
title: Possible Brute-Force Attack via Repeated Logon Failures
id: e8b2c3d4-5f6a-7b8c-9d0e-f1a2b3c4d5e6
status: stable
description: Detects more than 5 failed Windows logon attempts from the same source IP within 10 minutes.
correlation:
  type: event_count
  rules:
    - dc9f1a2e-7d3b-4f1c-b8f4-1e23eadf4567
  group-by:
    - SourceIp
  timespan: 10m
  condition:
    gte: 5
```
Gives:
```sql
WITH event_counts AS (
    SELECT
        *,
        COUNT(*) OVER (
            PARTITION BY SourceIp
            ORDER BY time
            RANGE BETWEEN INTERVAL '600' SECOND PRECEDING AND CURRENT ROW
        ) AS event_count
    FROM <TABLE>
    WHERE EventID = 4625
)
SELECT * FROM event_counts WHERE event_count >= 5
```

---

## Testing

Run the test suite:

```bash
pytest
```

---

## Maintainers

- [Neil Smith](https://github.com/nsmithuk/)

---

## License

Licensed under the [MIT License](LICENSE).

