import re
import glob
import yaml
from dataclasses import dataclass

@dataclass
class Rule:
    id: str
    name: str
    pattern: str
    secret_type: str
    severity: str
    description: str
    remediation: str
    weight: float
    compiled: object = None

    def match(self, text):
        if self.compiled is None:
            self.compiled = re.compile(self.pattern)
        return self.compiled.finditer(text)

def load_rules(rules_dir: str):
    rules = []
    for path in glob.glob(f"{rules_dir}/*.yaml") + glob.glob(f"{rules_dir}/*.yml"):
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        for r in data.get("rules", []):
            rules.append(Rule(
                id=r["id"], name=r["name"], pattern=r["pattern"],
                secret_type=r["secret_type"], severity=r["severity"],
                description=r.get("description", ""),
                remediation=r.get("remediation", ""),
                weight=float(r.get("weight", 50)),
            ))
    return rules
