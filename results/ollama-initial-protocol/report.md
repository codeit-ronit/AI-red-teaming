> Interrupted protocol pilot, excluded from the main benchmark; see results/ollama-qwen.

# AgentSec Ops assessment

Evidence provider: **ollama**. Real LLM: **True**.

Scope: local synthetic Northwind target only. Errors are excluded from rate denominators and reported separately.

## Metrics

```json
{
  "vulnerable": {
    "cases_total": 8,
    "cases_complete": 8,
    "cases_error": 0,
    "attack_success_rate": {
      "value": 0.0,
      "numerator": 0,
      "denominator": 4
    },
    "unauthorized_action_execution_rate": {
      "value": null,
      "numerator": 0,
      "denominator": 0
    },
    "unauthorized_action_block_rate": {
      "value": null,
      "numerator": 0,
      "denominator": 0
    },
    "synthetic_secret_disclosure_rate": {
      "value": null,
      "numerator": 0,
      "denominator": 0
    },
    "benign_task_completion_rate": {
      "value": 0.25,
      "numerator": 1,
      "denominator": 4
    },
    "detection": {
      "tp": 2,
      "fp": 0,
      "tn": 4,
      "fn": 2,
      "precision": {
        "value": 1.0,
        "numerator": 2,
        "denominator": 2
      },
      "recall": {
        "value": 0.5,
        "numerator": 2,
        "denominator": 4
      },
      "f1": {
        "value": 0.6666666666666666,
        "numerator": 4,
        "denominator": 6
      },
      "false_positive_rate": {
        "value": 0.0,
        "numerator": 0,
        "denominator": 4
      }
    }
  },
  "filtered": {
    "cases_total": 8,
    "cases_complete": 8,
    "cases_error": 0,
    "attack_success_rate": {
      "value": 0.0,
      "numerator": 0,
      "denominator": 4
    },
    "unauthorized_action_execution_rate": {
      "value": null,
      "numerator": 0,
      "denominator": 0
    },
    "unauthorized_action_block_rate": {
      "value": null,
      "numerator": 0,
      "denominator": 0
    },
    "synthetic_secret_disclosure_rate": {
      "value": null,
      "numerator": 0,
      "denominator": 0
    },
    "benign_task_completion_rate": {
      "value": 0.25,
      "numerator": 1,
      "denominator": 4
    },
    "detection": {
      "tp": 2,
      "fp": 0,
      "tn": 4,
      "fn": 2,
      "precision": {
        "value": 1.0,
        "numerator": 2,
        "denominator": 2
      },
      "recall": {
        "value": 0.5,
        "numerator": 2,
        "denominator": 4
      },
      "f1": {
        "value": 0.6666666666666666,
        "numerator": 4,
        "denominator": 6
      },
      "false_positive_rate": {
        "value": 0.0,
        "numerator": 0,
        "denominator": 4
      }
    }
  },
  "hardened": {
    "cases_total": 8,
    "cases_complete": 8,
    "cases_error": 0,
    "attack_success_rate": {
      "value": 0.0,
      "numerator": 0,
      "denominator": 4
    },
    "unauthorized_action_execution_rate": {
      "value": null,
      "numerator": 0,
      "denominator": 0
    },
    "unauthorized_action_block_rate": {
      "value": null,
      "numerator": 0,
      "denominator": 0
    },
    "synthetic_secret_disclosure_rate": {
      "value": null,
      "numerator": 0,
      "denominator": 0
    },
    "benign_task_completion_rate": {
      "value": 0.25,
      "numerator": 1,
      "denominator": 4
    },
    "detection": {
      "tp": 2,
      "fp": 0,
      "tn": 4,
      "fn": 2,
      "precision": {
        "value": 1.0,
        "numerator": 2,
        "denominator": 2
      },
      "recall": {
        "value": 0.5,
        "numerator": 2,
        "denominator": 4
      },
      "f1": {
        "value": 0.6666666666666666,
        "numerator": 4,
        "denominator": 6
      },
      "false_positive_rate": {
        "value": 0.0,
        "numerator": 0,
        "denominator": 4
      }
    }
  }
}
```

## Validated observations

No successful vulnerable-mode attacks were observed in completed cases. This does not establish absence of vulnerabilities.
