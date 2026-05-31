"""
Benchmark Metrics — расчёт precision, recall, F1, false positive rate
"""
from dataclasses import dataclass


@dataclass
class BenchmarkMetrics:
    true_positives: int = 0   # правильно найденные уязвимости
    false_positives: int = 0  # ложные срабатывания
    false_negatives: int = 0  # пропущенные уязвимости
    true_negatives: int = 0   # правильно не найденные (не применимо в нашем случае)

    @property
    def precision(self) -> float:
        """Precision = TP / (TP + FP) — доля правильных среди найденных."""
        if self.true_positives + self.false_positives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_positives)

    @property
    def recall(self) -> float:
        """Recall = TP / (TP + FN) — доля найденных среди всех реальных."""
        if self.true_positives + self.false_negatives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_negatives)

    @property
    def f1_score(self) -> float:
        """F1 = 2 * (precision * recall) / (precision + recall)."""
        if self.precision + self.recall == 0:
            return 0.0
        return 2 * (self.precision * self.recall) / (self.precision + self.recall)

    @property
    def false_positive_rate(self) -> float:
        """FPR = FP / (FP + TN) — но TN не применимо, возвращаем FP / total_found."""
        total_found = self.true_positives + self.false_positives
        if total_found == 0:
            return 0.0
        return self.false_positives / total_found

    def to_dict(self) -> dict:
        return {
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 3),
            "recall": round(self.recall, 3),
            "f1_score": round(self.f1_score, 3),
            "false_positive_rate": round(self.false_positive_rate, 3),
        }


def calculate_metrics(ground_truth: dict, agent_findings: list) -> BenchmarkMetrics:
    """
    Сравнить ground truth с находками агента и посчитать метрики.
    
    ground_truth: {"cves": [...], "vulnerabilities": [{"type": "sqli", ...}, ...]}
    agent_findings: [{"name": "...", "cve": "...", "description": "...", ...}, ...]
    """
    metrics = BenchmarkMetrics()

    # Извлечь ground truth CVE и типы уязвимостей
    gt_cves = set(ground_truth.get("cves", []))
    gt_vuln_types = set(v["type"] for v in ground_truth.get("vulnerabilities", []))

    # Извлечь найденные агентом CVE и типы
    found_cves = set()
    found_types = set()

    for finding in agent_findings:
        # CVE
        if cve := finding.get("cve"):
            found_cves.add(cve)

        # Тип уязвимости — определяем из названия или description
        vuln_type = _infer_vuln_type(finding)
        if vuln_type:
            found_types.add(vuln_type)

    # True Positives: CVE которые есть в ground truth и найдены агентом
    tp_cves = gt_cves & found_cves
    # True Positives: типы уязвимостей которые есть в ground truth и найдены
    tp_types = gt_vuln_types & found_types

    metrics.true_positives = len(tp_cves) + len(tp_types)

    # False Positives: найдено агентом, но нет в ground truth
    fp_cves = found_cves - gt_cves
    fp_types = found_types - gt_vuln_types
    metrics.false_positives = len(fp_cves) + len(fp_types)

    # False Negatives: есть в ground truth, но не найдено агентом
    fn_cves = gt_cves - found_cves
    fn_types = gt_vuln_types - found_types
    metrics.false_negatives = len(fn_cves) + len(fn_types)

    return metrics


def _infer_vuln_type(finding: dict) -> str | None:
    """Определить тип уязвимости из названия или описания."""
    text = (finding.get("name", "") + " " + finding.get("description", "")).lower()

    type_keywords = {
        "sqli": ["sql injection", "sqli", "sql inject"],
        "xss": ["xss", "cross-site scripting", "cross site scripting"],
        "xss_reflected": ["reflected xss"],
        "xss_stored": ["stored xss"],
        "xss_dom": ["dom xss", "dom-based xss"],
        "csrf": ["csrf", "cross-site request forgery"],
        "rce": ["rce", "remote code execution", "command injection", "code execution"],
        "command_injection": ["command injection", "os command"],
        "file_inclusion": ["lfi", "rfi", "file inclusion", "local file inclusion", "remote file inclusion"],
        "file_upload": ["file upload", "unrestricted upload"],
        "xxe": ["xxe", "xml external entity"],
        "ssrf": ["ssrf", "server-side request forgery"],
        "auth_bypass": ["authentication bypass", "auth bypass", "bypass authentication"],
        "brute_force": ["brute force", "bruteforce", "weak password"],
        "path_traversal": ["path traversal", "directory traversal"],
        "insecure_deserialization": ["deserialization", "insecure deserialization"],
        "jwt_manipulation": ["jwt", "json web token"],
        "nosql_injection": ["nosql injection", "nosql inject"],
        "samba_rce": ["samba", "smb"],
        "vsftpd_backdoor": ["vsftpd", "ftp backdoor"],
        "wordpress_brute_force": ["wordpress", "wp-login"],
        "privilege_escalation": ["privilege escalation", "privesc"],
    }

    for vuln_type, keywords in type_keywords.items():
        if any(kw in text for kw in keywords):
            return vuln_type

    return None


def aggregate_metrics(results: list[dict]) -> dict:
    """Агрегировать метрики по всем целям."""
    total = BenchmarkMetrics()

    for r in results:
        m = r.get("metrics", {})
        total.true_positives += m.get("true_positives", 0)
        total.false_positives += m.get("false_positives", 0)
        total.false_negatives += m.get("false_negatives", 0)

    return {
        "aggregate": total.to_dict(),
        "per_target": [
            {
                "target": r["target"],
                "metrics": r.get("metrics", {}),
            }
            for r in results
        ],
    }
