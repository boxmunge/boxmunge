"""Tests for boxmunge.cve.scanner — Trivy CLI wrapper."""

import json
import logging
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from boxmunge.cve.scanner import (
    AttackVector,
    Finding,
    ScanResult,
    ScannerError,
    Severity,
    TrivyNotInstalledError,
    _parse_attack_vector,
    refresh_db,
    scan_image,
)


def _captured_records() -> tuple[logging.Handler, list]:
    """Attach a handler to the boxmunge logger to capture records.

    The boxmunge logger sets propagate=False once initialised, so caplog
    cannot see records reliably across tests. Same pattern as the
    fileutil tests.
    """
    records: list = []

    class _ListHandler(logging.Handler):
        def emit(self, record):  # type: ignore[override]
            records.append(record)

    h = _ListHandler(level=logging.WARNING)
    return h, records


def _make_completed(stdout: str, returncode: int = 0) -> MagicMock:
    cp = MagicMock(spec=subprocess.CompletedProcess)
    cp.stdout = stdout
    cp.stderr = ""
    cp.returncode = returncode
    return cp


# ---------- realistic Trivy payload fixtures ----------

_PAYLOAD_TWO_FINDINGS = {
    "Metadata": {"DB": {"UpdatedAt": "2026-05-01T00:00:00Z"}},
    "Results": [
        {
            "Target": "image:tag (alpine 3.18.0)",
            "Class": "os-pkgs",
            "Type": "alpine",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2026-1234",
                    "PkgName": "openssl",
                    "InstalledVersion": "3.0.7-r0",
                    "FixedVersion": "3.0.8-r0",
                    "Severity": "HIGH",
                    "Title": "openssl: example vuln",
                    "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2026-1234",
                },
                {
                    "VulnerabilityID": "CVE-2026-9999",
                    "PkgName": "libfoo",
                    "InstalledVersion": "1.0",
                    "Severity": "CRITICAL",
                    "Title": "libfoo: rce",
                    "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2026-9999",
                },
            ],
        }
    ],
}


# ---------- scan_image: parsing ----------

class TestScanImageParsing:
    @patch("boxmunge.cve.scanner.subprocess.run")
    def test_scan_image_parses_findings(self, mock_run: MagicMock) -> None:
        mock_run.return_value = _make_completed(json.dumps(_PAYLOAD_TWO_FINDINGS))

        result = scan_image("myimage:tag")

        assert isinstance(result, ScanResult)
        assert result.image_ref == "myimage:tag"
        assert isinstance(result.findings, tuple)
        assert len(result.findings) == 2
        # CRITICAL sorts before HIGH
        assert result.findings[0].cve_id == "CVE-2026-9999"
        assert result.findings[0].severity == Severity.CRITICAL
        assert result.findings[0].package == "libfoo"
        assert result.findings[0].installed_version == "1.0"
        assert result.findings[0].fixed_version is None
        assert result.findings[0].title == "libfoo: rce"
        assert result.findings[0].primary_url == (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-9999"
        )
        assert result.findings[1].cve_id == "CVE-2026-1234"
        assert result.findings[1].severity == Severity.HIGH
        assert result.findings[1].fixed_version == "3.0.8-r0"
        assert result.db_version == "2026-05-01T00:00:00Z"

    @patch("boxmunge.cve.scanner.subprocess.run")
    def test_scan_image_invokes_correct_cli(self, mock_run: MagicMock) -> None:
        mock_run.return_value = _make_completed(json.dumps({"Results": []}))
        scan_image("alpine:3.18", timeout=60)

        cmd = mock_run.call_args[0][0]
        assert cmd[:2] == ["trivy", "image"]
        assert "--format" in cmd and cmd[cmd.index("--format") + 1] == "json"
        assert "--severity" in cmd
        assert cmd[cmd.index("--severity") + 1] == "LOW,MEDIUM,HIGH,CRITICAL"
        assert "--no-progress" in cmd
        assert "--quiet" in cmd
        assert cmd[-1] == "alpine:3.18"
        assert mock_run.call_args.kwargs["timeout"] == 60

    @patch("boxmunge.cve.scanner.subprocess.run")
    def test_scan_image_no_vulnerabilities(self, mock_run: MagicMock) -> None:
        mock_run.return_value = _make_completed(json.dumps({"Results": []}))
        result = scan_image("clean:tag")
        assert result.findings == ()
        assert result.image_ref == "clean:tag"

    @patch("boxmunge.cve.scanner.subprocess.run")
    def test_scan_image_results_missing(self, mock_run: MagicMock) -> None:
        # Some image types (scratch images, distroless) emit {} with no Results key.
        mock_run.return_value = _make_completed(json.dumps({}))
        result = scan_image("scratch:tag")
        assert result.findings == ()
        assert result.db_version is None

    @patch("boxmunge.cve.scanner.subprocess.run")
    def test_scan_image_result_with_no_vulnerabilities_key(
        self, mock_run: MagicMock,
    ) -> None:
        # A result entry without a Vulnerabilities array is valid (clean image).
        payload = {"Results": [{"Target": "x", "Class": "os-pkgs"}]}
        mock_run.return_value = _make_completed(json.dumps(payload))
        result = scan_image("img:tag")
        assert result.findings == ()


# ---------- scan_image: error paths ----------

class TestScanImageErrors:
    @patch("boxmunge.cve.scanner.subprocess.run", side_effect=FileNotFoundError())
    def test_scan_image_trivy_not_installed(self, _mock_run: MagicMock) -> None:
        with pytest.raises(TrivyNotInstalledError) as exc:
            scan_image("img:tag")
        msg = str(exc.value)
        assert "trivy not found on PATH" in msg
        assert "https://aquasecurity.github.io/trivy/" in msg
        # Subclass relationship: callers can catch the family.
        assert isinstance(exc.value, ScannerError)

    @patch("boxmunge.cve.scanner.subprocess.run")
    def test_scan_image_subprocess_failure(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = subprocess.CalledProcessError(
            returncode=2, cmd=["trivy"], stderr="db corrupted\n",
        )
        with pytest.raises(ScannerError) as exc:
            scan_image("img:tag")
        msg = str(exc.value)
        assert "db corrupted" in msg
        assert "img:tag" in msg
        assert "exit 2" in msg

    @patch("boxmunge.cve.scanner.subprocess.run")
    def test_scan_image_timeout(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["trivy"], timeout=5)
        with pytest.raises(ScannerError) as exc:
            scan_image("img:tag", timeout=5)
        msg = str(exc.value)
        assert "timed out" in msg.lower()
        assert "5s" in msg
        assert "img:tag" in msg

    @patch("boxmunge.cve.scanner.subprocess.run")
    def test_scan_image_malformed_json(self, mock_run: MagicMock) -> None:
        mock_run.return_value = _make_completed("not json at all")
        with pytest.raises(ScannerError) as exc:
            scan_image("img:tag")
        assert "unparseable JSON" in str(exc.value)


# ---------- ordering and Finding behavior ----------

class TestOrdering:
    @patch("boxmunge.cve.scanner.subprocess.run")
    def test_findings_sorted_severity_desc_then_cve_asc(
        self, mock_run: MagicMock,
    ) -> None:
        payload = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2026-0002",
                            "PkgName": "p", "InstalledVersion": "1",
                            "Severity": "LOW", "Title": "t",
                        },
                        {
                            "VulnerabilityID": "CVE-2026-0003",
                            "PkgName": "p", "InstalledVersion": "1",
                            "Severity": "CRITICAL", "Title": "t",
                        },
                        {
                            "VulnerabilityID": "CVE-2026-0001",
                            "PkgName": "p", "InstalledVersion": "1",
                            "Severity": "CRITICAL", "Title": "t",
                        },
                        {
                            "VulnerabilityID": "CVE-2026-0004",
                            "PkgName": "p", "InstalledVersion": "1",
                            "Severity": "MEDIUM", "Title": "t",
                        },
                        {
                            "VulnerabilityID": "CVE-2026-0005",
                            "PkgName": "p", "InstalledVersion": "1",
                            "Severity": "HIGH", "Title": "t",
                        },
                    ],
                },
            ],
        }
        mock_run.return_value = _make_completed(json.dumps(payload))
        result = scan_image("img:tag")
        ordered = [(f.severity, f.cve_id) for f in result.findings]
        assert ordered == [
            (Severity.CRITICAL, "CVE-2026-0001"),
            (Severity.CRITICAL, "CVE-2026-0003"),
            (Severity.HIGH, "CVE-2026-0005"),
            (Severity.MEDIUM, "CVE-2026-0004"),
            (Severity.LOW, "CVE-2026-0002"),
        ]


class TestFindingProperties:
    def test_finding_fix_available_property(self) -> None:
        no_fix = Finding(
            cve_id="CVE-X", severity=Severity.HIGH, package="p",
            installed_version="1", fixed_version=None,
            title="t", primary_url=None,
        )
        with_fix = Finding(
            cve_id="CVE-Y", severity=Severity.HIGH, package="p",
            installed_version="1", fixed_version="1.2.3",
            title="t", primary_url=None,
        )
        assert no_fix.fix_available is False
        assert with_fix.fix_available is True


# ---------- unknown severity handling ----------

class TestUnknownSeverity:
    @patch("boxmunge.cve.scanner.subprocess.run")
    def test_unrecognised_severity_maps_to_unknown_with_one_warning(
        self, mock_run: MagicMock,
    ) -> None:
        payload = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-A",
                            "PkgName": "p", "InstalledVersion": "1",
                            "Severity": "FUNKY", "Title": "t",
                        },
                        {
                            "VulnerabilityID": "CVE-B",
                            "PkgName": "p", "InstalledVersion": "1",
                            "Severity": "FUNKY", "Title": "t",
                        },
                    ],
                },
            ],
        }
        mock_run.return_value = _make_completed(json.dumps(payload))
        h, records = _captured_records()
        logging.getLogger("boxmunge").addHandler(h)
        try:
            result = scan_image("img:tag")
        finally:
            logging.getLogger("boxmunge").removeHandler(h)

        severities = {f.severity for f in result.findings}
        assert severities == {Severity.UNKNOWN}
        # Two findings with unrecognised severity, but only one warning logged.
        assert len(records) == 1
        assert "FUNKY" in records[0].getMessage()


# ---------- refresh_db ----------

class TestRefreshDb:
    @patch("boxmunge.cve.scanner.subprocess.run")
    def test_refresh_db_success(self, mock_run: MagicMock) -> None:
        mock_run.return_value = _make_completed("")
        h, records = _captured_records()
        logging.getLogger("boxmunge").addHandler(h)
        try:
            refresh_db()
        finally:
            logging.getLogger("boxmunge").removeHandler(h)

        cmd = mock_run.call_args[0][0]
        assert cmd == ["trivy", "image", "--download-db-only"]
        assert records == []

    @patch("boxmunge.cve.scanner.subprocess.run")
    def test_refresh_db_failure_logs_warning_no_raise(
        self, mock_run: MagicMock,
    ) -> None:
        mock_run.side_effect = subprocess.CalledProcessError(
            returncode=1, cmd=["trivy"], stderr="network unreachable",
        )
        h, records = _captured_records()
        logging.getLogger("boxmunge").addHandler(h)
        try:
            refresh_db()  # must not raise
        finally:
            logging.getLogger("boxmunge").removeHandler(h)

        assert len(records) == 1
        msg = records[0].getMessage()
        assert "trivy DB refresh failed" in msg
        assert "network unreachable" in msg

    @patch(
        "boxmunge.cve.scanner.subprocess.run",
        side_effect=FileNotFoundError(),
    )
    def test_refresh_db_missing_binary_logs_warning_no_raise(
        self, _mock_run: MagicMock,
    ) -> None:
        h, records = _captured_records()
        logging.getLogger("boxmunge").addHandler(h)
        try:
            refresh_db()
        finally:
            logging.getLogger("boxmunge").removeHandler(h)

        assert len(records) == 1
        assert "trivy not found on PATH" in records[0].getMessage()

    @patch("boxmunge.cve.scanner.subprocess.run")
    def test_refresh_db_timeout_logs_warning_no_raise(
        self, mock_run: MagicMock,
    ) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd=["trivy"], timeout=120,
        )
        h, records = _captured_records()
        logging.getLogger("boxmunge").addHandler(h)
        try:
            refresh_db()
        finally:
            logging.getLogger("boxmunge").removeHandler(h)

        assert len(records) == 1
        assert "timed out" in records[0].getMessage().lower()


class TestSeverityFromTrivyString:
    """Audit F-4: severity case normalization is encapsulated."""

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("CRITICAL", Severity.CRITICAL),
            ("Critical", Severity.CRITICAL),
            ("critical", Severity.CRITICAL),
            ("HIGH", Severity.HIGH),
            ("High", Severity.HIGH),
            ("high", Severity.HIGH),
            ("MEDIUM", Severity.MEDIUM),
            ("Medium", Severity.MEDIUM),
            ("medium", Severity.MEDIUM),
            ("LOW", Severity.LOW),
            ("Low", Severity.LOW),
            ("low", Severity.LOW),
            ("UNKNOWN", Severity.UNKNOWN),
            ("Unknown", Severity.UNKNOWN),
            ("unknown", Severity.UNKNOWN),
        ],
    )
    def test_known_strings_round_trip_case_insensitively(
        self, raw: str, expected: Severity,
    ) -> None:
        assert Severity.from_trivy_string(raw) is expected

    def test_empty_string_maps_to_unknown(self) -> None:
        assert Severity.from_trivy_string("") is Severity.UNKNOWN

    def test_none_maps_to_unknown(self) -> None:
        assert Severity.from_trivy_string(None) is Severity.UNKNOWN

    def test_unrecognised_string_maps_to_unknown(self) -> None:
        # Defensive: a value Trivy invents should not raise — UNKNOWN is
        # the right shelter, with the (non-empty) input logged in the
        # caller's parse loop.
        assert Severity.from_trivy_string("FATAL") is Severity.UNKNOWN


# ---------- structured-extras (audit A-1) ----------


class TestStructuredLogging:
    """Wave 3: cve/scanner.py warnings must carry component='cve-scan'
    extras so `boxmunge log --component cve-scan` finds them."""

    @patch("boxmunge.cve.scanner.subprocess.run")
    def test_refresh_db_failure_extras_carry_component(
        self, mock_run: MagicMock,
    ) -> None:
        mock_run.side_effect = subprocess.CalledProcessError(
            returncode=1, cmd=["trivy"], stderr="net unreachable",
        )
        h, records = _captured_records()
        logging.getLogger("boxmunge").addHandler(h)
        try:
            refresh_db()
        finally:
            logging.getLogger("boxmunge").removeHandler(h)
        assert len(records) == 1
        rec = records[0]
        assert getattr(rec, "component", None) == "cve-scan"
        assert getattr(rec, "project", "missing") is None

    @patch(
        "boxmunge.cve.scanner.subprocess.run", side_effect=FileNotFoundError(),
    )
    def test_refresh_db_missing_binary_extras(
        self, _mock_run: MagicMock,
    ) -> None:
        h, records = _captured_records()
        logging.getLogger("boxmunge").addHandler(h)
        try:
            refresh_db()
        finally:
            logging.getLogger("boxmunge").removeHandler(h)
        assert len(records) == 1
        rec = records[0]
        assert getattr(rec, "component", None) == "cve-scan"
        assert getattr(rec, "project", "missing") is None

    @patch("boxmunge.cve.scanner.subprocess.run")
    def test_unknown_severity_warning_extras(
        self, mock_run: MagicMock,
    ) -> None:
        payload = {
            "Results": [{
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-X",
                        "PkgName": "p", "InstalledVersion": "1",
                        "Severity": "FUNKY", "Title": "t",
                    },
                ],
            }],
        }
        mock_run.return_value = _make_completed(json.dumps(payload))
        h, records = _captured_records()
        logging.getLogger("boxmunge").addHandler(h)
        try:
            scan_image("img:tag")
        finally:
            logging.getLogger("boxmunge").removeHandler(h)
        assert len(records) == 1
        rec = records[0]
        assert getattr(rec, "component", None) == "cve-scan"
        # Detail dict carries the offending raw severity for forensic use.
        detail = getattr(rec, "detail", None)
        assert isinstance(detail, dict)
        assert detail.get("raw_severity") == "FUNKY"


# ---------- v0.7.1 CVSS Attack Vector parsing ----------


class TestParseAttackVector:
    """Parser walks per-source CVSS blocks and extracts the AV: token."""

    def test_single_source_ghsa_v3_av_n(self) -> None:
        cvss = {
            "ghsa": {
                "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "V3Score": 9.8,
            },
        }
        assert _parse_attack_vector(cvss) is AttackVector.NETWORK

    def test_single_source_nvd_v3_av_l(self) -> None:
        cvss = {
            "nvd": {
                "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:H/A:N",
                "V3Score": 5.0,
            },
        }
        assert _parse_attack_vector(cvss) is AttackVector.LOCAL

    def test_multi_source_disagree_nvd_wins(self) -> None:
        # nvd is highest priority; nvd:L should win over ghsa:N.
        cvss = {
            "ghsa": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
            "nvd": {"V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:H/A:N"},
        }
        assert _parse_attack_vector(cvss) is AttackVector.LOCAL

    def test_redhat_priority_above_ghsa(self) -> None:
        cvss = {
            "ghsa": {"V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"},
            "redhat": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        }
        assert _parse_attack_vector(cvss) is AttackVector.NETWORK

    def test_only_v40_vector_parses(self) -> None:
        cvss = {
            "ghsa": {
                "V40Vector": "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                "V40Score": 7.2,
            },
        }
        assert _parse_attack_vector(cvss) is AttackVector.ADJACENT

    def test_v3_preferred_over_v40_same_source(self) -> None:
        # V3 wins per spec: more populated in the Trivy DB.
        cvss = {
            "ghsa": {
                "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "V40Vector": "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            },
        }
        assert _parse_attack_vector(cvss) is AttackVector.NETWORK

    def test_unknown_source_falls_back_alphabetical(self) -> None:
        # No nvd/redhat/ghsa — order alphabetically among extras.
        cvss = {
            "zzz_oss": {"V3Vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
            "aaa_oss": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        }
        # aaa_oss wins alphabetically.
        assert _parse_attack_vector(cvss) is AttackVector.NETWORK

    def test_priority_source_overrides_alphabetical(self) -> None:
        cvss = {
            "aaa_oss": {"V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
            "redhat": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        }
        assert _parse_attack_vector(cvss) is AttackVector.NETWORK

    def test_empty_dict_returns_none(self) -> None:
        assert _parse_attack_vector({}) is None

    def test_no_cvss_at_all_returns_none(self) -> None:
        # _parse_attack_vector tolerates {} (caller passes `vuln.get("CVSS") or {}`).
        assert _parse_attack_vector({}) is None

    def test_malformed_vector_string_returns_none(self) -> None:
        cvss = {"nvd": {"V3Vector": "garbage-not-cvss"}}
        assert _parse_attack_vector(cvss) is None

    def test_unknown_av_token_returns_none(self) -> None:
        cvss = {"nvd": {"V3Vector": "CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}
        assert _parse_attack_vector(cvss) is None

    def test_skips_unparseable_source_tries_next(self) -> None:
        cvss = {
            "nvd": {"V3Vector": "garbage"},
            "ghsa": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        }
        assert _parse_attack_vector(cvss) is AttackVector.NETWORK

    def test_non_dict_entry_skipped(self) -> None:
        cvss = {
            "nvd": "not a dict",
            "ghsa": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        }
        assert _parse_attack_vector(cvss) is AttackVector.NETWORK

    def test_non_dict_input_returns_none(self) -> None:
        # Defensive: the field could be anything if Trivy schema drifts.
        assert _parse_attack_vector(None) is None  # type: ignore[arg-type]
        assert _parse_attack_vector("string") is None  # type: ignore[arg-type]


class TestParseFindingsAttackVector:
    """_parse_findings propagates the attack vector to Finding."""

    @patch("boxmunge.cve.scanner.subprocess.run")
    def test_finding_with_av_n_propagates_to_finding(
        self, mock_run: MagicMock,
    ) -> None:
        payload = {
            "Results": [{
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2026-1111",
                    "PkgName": "pkg", "InstalledVersion": "1",
                    "Severity": "HIGH", "Title": "t",
                    "CVSS": {
                        "ghsa": {
                            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        },
                    },
                }],
            }],
        }
        mock_run.return_value = _make_completed(json.dumps(payload))
        result = scan_image("img:tag")
        assert result.findings[0].attack_vector is AttackVector.NETWORK

    @patch("boxmunge.cve.scanner.subprocess.run")
    def test_finding_with_av_l_propagates(self, mock_run: MagicMock) -> None:
        payload = {
            "Results": [{
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2026-2222",
                    "PkgName": "pkg", "InstalledVersion": "1",
                    "Severity": "HIGH", "Title": "t",
                    "CVSS": {
                        "nvd": {
                            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:H/A:N",
                        },
                    },
                }],
            }],
        }
        mock_run.return_value = _make_completed(json.dumps(payload))
        result = scan_image("img:tag")
        assert result.findings[0].attack_vector is AttackVector.LOCAL

    @patch("boxmunge.cve.scanner.subprocess.run")
    def test_finding_without_cvss_block_has_none_av(
        self, mock_run: MagicMock,
    ) -> None:
        payload = {
            "Results": [{
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2026-3333",
                    "PkgName": "pkg", "InstalledVersion": "1",
                    "Severity": "HIGH", "Title": "t",
                    # No CVSS key at all.
                }],
            }],
        }
        mock_run.return_value = _make_completed(json.dumps(payload))
        result = scan_image("img:tag")
        assert result.findings[0].attack_vector is None

    @patch("boxmunge.cve.scanner.subprocess.run")
    def test_finding_severity_unaffected_by_av_parsing(
        self, mock_run: MagicMock,
    ) -> None:
        """Regression guard: severity parsing path doesn't depend on CVSS."""
        payload = {
            "Results": [{
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2026-4444",
                    "PkgName": "pkg", "InstalledVersion": "1",
                    "Severity": "CRITICAL", "Title": "t",
                    "CVSS": {
                        "ghsa": {
                            "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                        },
                    },
                }],
            }],
        }
        mock_run.return_value = _make_completed(json.dumps(payload))
        result = scan_image("img:tag")
        assert result.findings[0].severity is Severity.CRITICAL
        assert result.findings[0].attack_vector is AttackVector.LOCAL
