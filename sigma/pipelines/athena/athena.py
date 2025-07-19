from sigma.pipelines.base import Pipeline
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline, SigmaRule, Transformation
from dataclasses import dataclass, field
from typing import Dict

@dataclass
class SetStateFromBackendOptionsTransformation(Transformation):
    key: str
    template: str
    default_values: Dict[str, str] = field(default_factory=dict)

    def apply(self, pipeline: "sigma.processing.pipeline.Proces", rule: SigmaRule) -> None:
        super().apply(pipeline, rule)
        values = self.default_values | pipeline.vars
        pipeline.state[self.key] = self.template.format_map(values)

@dataclass
class SetStateFromBackendOptionsTransformationDashToUnderscore(SetStateFromBackendOptionsTransformation):
    def apply(self, pipeline: "sigma.processing.pipeline.Proces", rule: SigmaRule) -> None:
        super().apply(pipeline, rule)
        pipeline.state[self.key] = pipeline.state[self.key].replace("-", "_")

@Pipeline
def athena_pipeline_security_lake_table_name() -> ProcessingPipeline:
    sources = [
        (LogsourceCondition(product="aws", service="cloudtrail"), "amazon_security_lake_table_{backend_aws_table_region}_cloud_trail_mgmt_{backend_aws_table_version}"),
        (LogsourceCondition(product="aws", service="cloudtrail_s3"), "amazon_security_lake_table_{backend_aws_table_region}_s3_data_{backend_aws_table_version}"),
        (LogsourceCondition(product="aws", service="cloudtrail_lambda"), "amazon_security_lake_table_{backend_aws_table_region}_lambda_execution_{backend_aws_table_version}"),
        (LogsourceCondition(product="aws", service="route53"), "amazon_security_lake_table_{backend_aws_table_region}_route53_{backend_aws_table_version}"),
        (LogsourceCondition(product="aws", service="security_hub"), "amazon_security_lake_table_{backend_aws_table_region}_sh_findings_{backend_aws_table_version}"),
        (LogsourceCondition(product="aws", service="vpc_flow_logs"), "amazon_security_lake_table_{backend_aws_table_region}_vpc_flow_{backend_aws_table_version}"),
        (LogsourceCondition(product="aws", service="waf"), "amazon_security_lake_table_{backend_aws_table_region}_waf_{backend_aws_table_version}"),
        (LogsourceCondition(product="aws", service="eks_audit"), "amazon_security_lake_table_{backend_aws_table_region}_eks_audit_{backend_aws_table_version}"),
    ]

    return ProcessingPipeline(
        name="athena map source to table name pipeline",
        allowed_backends=frozenset(), # Set of identifiers of backends (from the backends mapping) that are allowed to use this processing pipeline. This can be used by frontends like Sigma CLI to warn the user about inappropriate usage.
        priority=20,
        items=[ ProcessingItem(
            identifier=f"table_{name}",
            transformation=SetStateFromBackendOptionsTransformationDashToUnderscore(
                key="table_name",
                template=name,
                default_values={"backend_aws_table_version": "2_0"}
            ),
            rule_conditions=[condition],
        ) for condition, name in sources ],
    )

