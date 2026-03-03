"""Tests for the secrets detection engine."""

import math

import pytest

from vlamguard.engine.secrets import (
    _extract_configmap_data,
    _extract_env_vars,
    _scan_hard_patterns,
    _scan_soft_patterns,
    _shannon_entropy,
    scan_secrets,
)


# ---------------------------------------------------------------------------
# _shannon_entropy
# ---------------------------------------------------------------------------


class TestShannonEntropy:
    def test_empty_string_returns_zero(self):
        assert _shannon_entropy("") == 0.0

    def test_single_repeated_char_returns_zero(self):
        # All chars identical → probability 1.0 → -1*log2(1) = 0
        assert _shannon_entropy("aaaa") == 0.0

    def test_single_char_returns_zero(self):
        assert _shannon_entropy("x") == 0.0

    def test_hello_returns_approx_1_92(self):
        result = _shannon_entropy("hello")
        assert abs(result - 1.9219280948873626) < 1e-9

    def test_two_char_equal_frequency_returns_1(self):
        # "ab" → each 50% → entropy = 1.0
        assert _shannon_entropy("ab") == pytest.approx(1.0)

    def test_high_entropy_random_string_exceeds_4_5(self):
        # Realistic API key pattern: 34 chars with high symbol diversity → ~5.09 bits
        high_entropy = "sk-Tz3xL9RqmA5bKpW8vYnE2cUoJ4dGfMi"
        result = _shannon_entropy(high_entropy)
        assert result > 4.5

    def test_result_is_non_negative(self):
        for s in ["hello", "world", "abc", "AAABBBCCC"]:
            assert _shannon_entropy(s) >= 0.0

    def test_uniform_alphabet_reaches_max_entropy(self):
        # All 26 lowercase letters used once → entropy = log2(26) ≈ 4.7
        s = "abcdefghijklmnopqrstuvwxyz"
        result = _shannon_entropy(s)
        assert result == pytest.approx(math.log2(26))


# ---------------------------------------------------------------------------
# _scan_hard_patterns
# ---------------------------------------------------------------------------


class TestScanHardPatterns:
    def test_detects_rsa_private_key_header(self):
        text = "-----BEGIN RSA PRIVATE KEY-----"
        findings = _scan_hard_patterns(text, "test/location")
        types = [f.type for f in findings]
        assert "private_key" in types

    def test_detects_bare_private_key_header(self):
        text = "-----BEGIN PRIVATE KEY-----"
        findings = _scan_hard_patterns(text, "test/location")
        types = [f.type for f in findings]
        assert "private_key" in types

    def test_detects_ec_private_key_header(self):
        text = "-----BEGIN EC PRIVATE KEY-----"
        findings = _scan_hard_patterns(text, "test/location")
        types = [f.type for f in findings]
        assert "private_key" in types

    def test_detects_openssh_private_key_header(self):
        text = "-----BEGIN OPENSSH PRIVATE KEY-----"
        findings = _scan_hard_patterns(text, "test/location")
        types = [f.type for f in findings]
        assert "private_key" in types

    def test_detects_aws_access_key(self):
        text = "AKIAIOSFODNN7EXAMPLE"
        findings = _scan_hard_patterns(text, "test/location")
        types = [f.type for f in findings]
        assert "aws_access_key" in types

    def test_aws_access_key_must_be_20_chars(self):
        # Valid: AKIA + 16 alphanumeric uppercase
        text = "AKIAZ3KBCDEF012345678"  # AKIA + 17 chars — still matches if >=16
        findings = _scan_hard_patterns(text, "test/location")
        types = [f.type for f in findings]
        assert "aws_access_key" in types

    def test_does_not_detect_partial_aws_key(self):
        # Less than 16 chars after AKIA → no match
        text = "AKIA1234"
        findings = _scan_hard_patterns(text, "test/location")
        types = [f.type for f in findings]
        assert "aws_access_key" not in types

    def test_detects_github_token_ghp(self):
        text = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
        findings = _scan_hard_patterns(text, "test/location")
        types = [f.type for f in findings]
        assert "github_token" in types

    def test_detects_github_token_gho(self):
        text = "gho_someOAuthTokenValue12345"
        findings = _scan_hard_patterns(text, "test/location")
        types = [f.type for f in findings]
        assert "github_token" in types

    def test_detects_github_token_ghs(self):
        text = "ghs_someServerToken12345"
        findings = _scan_hard_patterns(text, "test/location")
        types = [f.type for f in findings]
        assert "github_token" in types

    def test_detects_github_pat(self):
        text = "github_pat_somePersonalAccessToken123"
        findings = _scan_hard_patterns(text, "test/location")
        types = [f.type for f in findings]
        assert "github_token" in types

    def test_detects_postgresql_database_url(self):
        text = "postgresql://user:pass@host/db"
        findings = _scan_hard_patterns(text, "test/location")
        types = [f.type for f in findings]
        assert "database_url" in types

    def test_detects_mysql_database_url(self):
        text = "mysql://admin:secret@localhost:3306/mydb"
        findings = _scan_hard_patterns(text, "test/location")
        types = [f.type for f in findings]
        assert "database_url" in types

    def test_detects_mongodb_database_url(self):
        text = "mongodb://user:password@mongo-host:27017/mydb"
        findings = _scan_hard_patterns(text, "test/location")
        types = [f.type for f in findings]
        assert "database_url" in types

    def test_database_url_without_password_not_detected(self):
        # No :password@ segment → no match
        text = "postgresql://host/mydb"
        findings = _scan_hard_patterns(text, "test/location")
        types = [f.type for f in findings]
        assert "database_url" not in types

    def test_detects_generic_password_env_var(self):
        text = "PASSWORD=mysecretpassword"
        findings = _scan_hard_patterns(text, "test/location")
        types = [f.type for f in findings]
        assert "generic_password_env" in types

    def test_detects_secret_env_var(self):
        text = "SECRET=topsecret123"
        findings = _scan_hard_patterns(text, "test/location")
        types = [f.type for f in findings]
        assert "generic_password_env" in types

    def test_detects_token_env_var(self):
        text = "TOKEN=eyJhbGciOiJIUzI1NiJ9"
        findings = _scan_hard_patterns(text, "test/location")
        types = [f.type for f in findings]
        assert "generic_password_env" in types

    def test_detects_api_key_env_var(self):
        text = "API_KEY=sk-abc123xyz"
        findings = _scan_hard_patterns(text, "test/location")
        types = [f.type for f in findings]
        assert "generic_password_env" in types

    def test_generic_password_env_is_case_insensitive(self):
        text = "password=lowercasevalue"
        findings = _scan_hard_patterns(text, "test/location")
        types = [f.type for f in findings]
        assert "generic_password_env" in types

    def test_clean_text_returns_empty(self):
        findings = _scan_hard_patterns("APP_NAME=myapp", "test/location")
        assert findings == []

    def test_clean_log_line_returns_empty(self):
        findings = _scan_hard_patterns("Starting server on port 8080", "test/location")
        assert findings == []

    def test_finding_severity_is_critical(self):
        findings = _scan_hard_patterns("AKIAIOSFODNN7EXAMPLE", "test/location")
        assert len(findings) == 1
        assert findings[0].severity == "critical"

    def test_finding_detection_is_deterministic(self):
        findings = _scan_hard_patterns("AKIAIOSFODNN7EXAMPLE", "test/location")
        assert findings[0].detection == "deterministic"

    def test_finding_location_propagated(self):
        location = "Deployment/backend → container/api → env/KEY"
        findings = _scan_hard_patterns("AKIAIOSFODNN7EXAMPLE", location)
        assert findings[0].location == location

    def test_multiple_patterns_in_same_text_all_detected(self):
        # Both an AWS key and a private key header in the same text
        text = "AKIAIOSFODNN7EXAMPLE and -----BEGIN RSA PRIVATE KEY-----"
        findings = _scan_hard_patterns(text, "test/location")
        types = {f.type for f in findings}
        assert "aws_access_key" in types
        assert "private_key" in types


# ---------------------------------------------------------------------------
# _scan_soft_patterns
# ---------------------------------------------------------------------------


class TestScanSoftPatterns:
    def test_detects_api_key_name(self):
        findings = _scan_soft_patterns("api_key", "test/location")
        types = [f.type for f in findings]
        assert "suspicious_key_name" in types

    def test_detects_apikey_no_separator(self):
        findings = _scan_soft_patterns("apikey", "test/location")
        types = [f.type for f in findings]
        assert "suspicious_key_name" in types

    def test_detects_api_dash_key(self):
        findings = _scan_soft_patterns("api-key", "test/location")
        types = [f.type for f in findings]
        assert "suspicious_key_name" in types

    def test_detects_auth_token(self):
        findings = _scan_soft_patterns("auth_token", "test/location")
        types = [f.type for f in findings]
        assert "suspicious_key_name" in types

    def test_detects_authtoken_no_separator(self):
        findings = _scan_soft_patterns("authtoken", "test/location")
        types = [f.type for f in findings]
        assert "suspicious_key_name" in types

    def test_detects_secret_key(self):
        findings = _scan_soft_patterns("secret_key", "test/location")
        types = [f.type for f in findings]
        assert "suspicious_key_name" in types

    def test_detects_secretkey_no_separator(self):
        findings = _scan_soft_patterns("secretkey", "test/location")
        types = [f.type for f in findings]
        assert "suspicious_key_name" in types

    def test_case_insensitive_detection(self):
        findings = _scan_soft_patterns("API_KEY", "test/location")
        types = [f.type for f in findings]
        assert "suspicious_key_name" in types

    def test_clean_key_name_returns_empty(self):
        for name in ["app_name", "replica_count", "image_tag", "port", "namespace"]:
            findings = _scan_soft_patterns(name, "test/location")
            soft_types = [f.type for f in findings if f.type == "suspicious_key_name"]
            assert soft_types == [], f"Unexpected match for key name: {name}"

    def test_finding_severity_is_medium(self):
        findings = _scan_soft_patterns("api_key", "test/location")
        key_findings = [f for f in findings if f.type == "suspicious_key_name"]
        assert len(key_findings) == 1
        assert key_findings[0].severity == "medium"

    def test_finding_detection_is_deterministic(self):
        findings = _scan_soft_patterns("api_key", "test/location")
        key_findings = [f for f in findings if f.type == "suspicious_key_name"]
        assert key_findings[0].detection == "deterministic"

    def test_high_entropy_string_triggers_entropy_finding(self):
        # 34 chars with high symbol diversity → entropy ~5.09, well above 4.5 threshold
        high_entropy = "sk-Tz3xL9RqmA5bKpW8vYnE2cUoJ4dGfMi"
        findings = _scan_soft_patterns(high_entropy, "test/location")
        types = [f.type for f in findings]
        assert "high_entropy_string" in types

    def test_high_entropy_finding_severity_is_high(self):
        high_entropy = "sk-Tz3xL9RqmA5bKpW8vYnE2cUoJ4dGfMi"
        findings = _scan_soft_patterns(high_entropy, "test/location")
        entropy_findings = [f for f in findings if f.type == "high_entropy_string"]
        assert len(entropy_findings) == 1
        assert entropy_findings[0].severity == "high"

    def test_high_entropy_finding_detection_is_entropy(self):
        high_entropy = "sk-Tz3xL9RqmA5bKpW8vYnE2cUoJ4dGfMi"
        findings = _scan_soft_patterns(high_entropy, "test/location")
        entropy_findings = [f for f in findings if f.type == "high_entropy_string"]
        assert entropy_findings[0].detection == "entropy"

    def test_short_string_below_entropy_threshold_not_flagged(self):
        # Only 4 chars — below the >= 8 requirement for entropy check
        findings = _scan_soft_patterns("abcd", "test/location")
        entropy_findings = [f for f in findings if f.type == "high_entropy_string"]
        assert entropy_findings == []

    def test_low_entropy_long_string_not_flagged(self):
        # Long but all the same char — entropy = 0
        findings = _scan_soft_patterns("aaaaaaaaaa", "test/location")
        entropy_findings = [f for f in findings if f.type == "high_entropy_string"]
        assert entropy_findings == []


# ---------------------------------------------------------------------------
# _extract_env_vars
# ---------------------------------------------------------------------------


class TestExtractEnvVars:
    def test_extracts_env_from_deployment(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "backend"},
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "api",
                                "env": [
                                    {"name": "DATABASE_URL", "value": "postgresql://user:pass@host/db"},
                                    {"name": "APP_ENV", "value": "production"},
                                ],
                            }
                        ]
                    }
                }
            },
        }
        results = _extract_env_vars(manifest)
        names = [r[0] for r in results]
        values = [r[1] for r in results]
        assert "DATABASE_URL" in names
        assert "APP_ENV" in names
        assert "postgresql://user:pass@host/db" in values

    def test_location_format_is_correct(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "backend"},
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "api",
                                "env": [{"name": "MY_SECRET", "value": "val"}],
                            }
                        ]
                    }
                }
            },
        }
        results = _extract_env_vars(manifest)
        locations = [r[2] for r in results]
        assert "Deployment/backend → container/api → env/MY_SECRET" in locations

    def test_extracts_from_init_containers(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "backend"},
            "spec": {
                "template": {
                    "spec": {
                        "containers": [],
                        "initContainers": [
                            {
                                "name": "migrator",
                                "env": [{"name": "MIGRATION_DB_URL", "value": "postgresql://u:p@h/db"}],
                            }
                        ],
                    }
                }
            },
        }
        results = _extract_env_vars(manifest)
        names = [r[0] for r in results]
        assert "MIGRATION_DB_URL" in names

    def test_extracts_from_both_containers_and_init_containers(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "backend"},
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {"name": "app", "env": [{"name": "APP_KEY", "value": "v1"}]}
                        ],
                        "initContainers": [
                            {"name": "init", "env": [{"name": "INIT_KEY", "value": "v2"}]}
                        ],
                    }
                }
            },
        }
        results = _extract_env_vars(manifest)
        names = [r[0] for r in results]
        assert "APP_KEY" in names
        assert "INIT_KEY" in names

    def test_extracts_command_args(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "backend"},
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "app",
                                "command": ["/bin/sh"],
                                "args": ["--token=supersecret123"],
                            }
                        ]
                    }
                }
            },
        }
        results = _extract_env_vars(manifest)
        # command and args fields are included
        fields = [r[0] for r in results]
        values = [r[1] for r in results]
        assert "command" in fields
        assert "args" in fields
        assert "--token=supersecret123" in values

    def test_command_location_format(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "backend"},
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {"name": "app", "args": ["--token=secret"]}
                        ]
                    }
                }
            },
        }
        results = _extract_env_vars(manifest)
        locations = [r[2] for r in results]
        assert "Deployment/backend → container/app → args[0]" in locations

    def test_skips_env_var_without_value(self):
        # valueFrom refs (no "value" key) should be ignored
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "backend"},
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "app",
                                "env": [
                                    {"name": "FROM_SECRET", "valueFrom": {"secretKeyRef": {"name": "mysecret", "key": "password"}}},
                                    {"name": "LITERAL", "value": "hello"},
                                ],
                            }
                        ]
                    }
                }
            },
        }
        results = _extract_env_vars(manifest)
        names = [r[0] for r in results]
        assert "FROM_SECRET" not in names
        assert "LITERAL" in names

    def test_returns_empty_for_configmap(self):
        manifest = {
            "kind": "ConfigMap",
            "metadata": {"name": "config"},
            "data": {"key": "value"},
        }
        assert _extract_env_vars(manifest) == []

    def test_returns_empty_for_service(self):
        manifest = {
            "kind": "Service",
            "metadata": {"name": "svc"},
            "spec": {"ports": [{"port": 80}]},
        }
        assert _extract_env_vars(manifest) == []

    def test_works_for_statefulset(self):
        manifest = {
            "kind": "StatefulSet",
            "metadata": {"name": "db"},
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {"name": "postgres", "env": [{"name": "POSTGRES_PASSWORD", "value": "secret"}]}
                        ]
                    }
                }
            },
        }
        results = _extract_env_vars(manifest)
        names = [r[0] for r in results]
        assert "POSTGRES_PASSWORD" in names

    def test_works_for_daemonset(self):
        manifest = {
            "kind": "DaemonSet",
            "metadata": {"name": "agent"},
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {"name": "agent", "env": [{"name": "NODE_TOKEN", "value": "tok123"}]}
                        ]
                    }
                }
            },
        }
        results = _extract_env_vars(manifest)
        names = [r[0] for r in results]
        assert "NODE_TOKEN" in names

    def test_returns_empty_for_manifest_without_containers(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "empty"},
            "spec": {"template": {"spec": {}}},
        }
        assert _extract_env_vars(manifest) == []


# ---------------------------------------------------------------------------
# _extract_configmap_data
# ---------------------------------------------------------------------------


class TestExtractConfigmapData:
    def test_extracts_all_data_fields(self):
        manifest = {
            "kind": "ConfigMap",
            "metadata": {"name": "app-config"},
            "data": {
                "database_url": "postgresql://user:pass@host/db",
                "log_level": "info",
            },
        }
        results = _extract_configmap_data(manifest)
        keys = [r[0] for r in results]
        values = [r[1] for r in results]
        assert "database_url" in keys
        assert "log_level" in keys
        assert "postgresql://user:pass@host/db" in values
        assert "info" in values

    def test_location_format_is_correct(self):
        manifest = {
            "kind": "ConfigMap",
            "metadata": {"name": "app-config"},
            "data": {"api_key": "somevalue"},
        }
        results = _extract_configmap_data(manifest)
        locations = [r[2] for r in results]
        assert "ConfigMap/app-config → data/api_key" in locations

    def test_returns_empty_for_configmap_with_no_data(self):
        manifest = {
            "kind": "ConfigMap",
            "metadata": {"name": "empty"},
            "data": {},
        }
        assert _extract_configmap_data(manifest) == []

    def test_returns_empty_for_deployment(self):
        manifest = {
            "kind": "Deployment",
            "metadata": {"name": "web"},
            "spec": {"template": {"spec": {"containers": []}}},
        }
        assert _extract_configmap_data(manifest) == []

    def test_returns_empty_for_service(self):
        manifest = {
            "kind": "Service",
            "metadata": {"name": "svc"},
        }
        assert _extract_configmap_data(manifest) == []

    def test_value_converted_to_string(self):
        manifest = {
            "kind": "ConfigMap",
            "metadata": {"name": "cfg"},
            "data": {"count": 42},
        }
        results = _extract_configmap_data(manifest)
        values = [r[1] for r in results]
        assert "42" in values

    def test_uses_unknown_when_name_missing(self):
        manifest = {
            "kind": "ConfigMap",
            "metadata": {},
            "data": {"key": "value"},
        }
        results = _extract_configmap_data(manifest)
        locations = [r[2] for r in results]
        assert any("ConfigMap/unknown" in loc for loc in locations)


# ---------------------------------------------------------------------------
# scan_secrets (integration)
# ---------------------------------------------------------------------------


class TestScanSecrets:
    def _deployment_with_env(self, env_vars: list[dict], name: str = "backend") -> dict:
        return {
            "kind": "Deployment",
            "metadata": {"name": name},
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{"name": "api", "env": env_vars}]
                    }
                }
            },
        }

    def test_clean_manifests_produce_zero_suspects(self):
        manifests = [
            {
                "kind": "Deployment",
                "metadata": {"name": "web"},
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {
                                    "name": "app",
                                    "env": [
                                        {"name": "APP_ENV", "value": "production"},
                                        {"name": "PORT", "value": "8080"},
                                    ],
                                }
                            ]
                        }
                    }
                },
            }
        ]
        result = scan_secrets(manifests, {}, "production")
        assert result.total_suspects == 0
        assert result.confirmed_secrets == 0
        assert result.hard_blocks == []
        assert result.soft_risks == []

    def test_hardcoded_database_url_in_production_goes_to_hard_blocks(self):
        manifests = [
            self._deployment_with_env(
                [{"name": "DATABASE_URL", "value": "postgresql://admin:s3cret@db-host/mydb"}]
            )
        ]
        result = scan_secrets(manifests, {}, "production")
        assert result.confirmed_secrets > 0
        assert len(result.hard_blocks) > 0
        types = {f.type for f in result.hard_blocks}
        assert "database_url" in types

    def test_hardcoded_database_url_production_finding_is_critical(self):
        manifests = [
            self._deployment_with_env(
                [{"name": "DATABASE_URL", "value": "postgresql://admin:s3cret@db-host/mydb"}]
            )
        ]
        result = scan_secrets(manifests, {}, "production")
        for finding in result.hard_blocks:
            if finding.type == "database_url":
                assert finding.severity == "critical"

    def test_hardcoded_database_url_in_dev_goes_to_soft_risks(self):
        manifests = [
            self._deployment_with_env(
                [{"name": "DATABASE_URL", "value": "postgresql://admin:s3cret@db-host/mydb"}]
            )
        ]
        result = scan_secrets(manifests, {}, "dev")
        assert len(result.hard_blocks) == 0
        assert len(result.soft_risks) > 0

    def test_hardcoded_database_url_in_dev_confirmed_secrets_is_zero(self):
        # In non-prod, confirmed_secrets counts only hard_blocks which are empty
        manifests = [
            self._deployment_with_env(
                [{"name": "DATABASE_URL", "value": "postgresql://admin:s3cret@db-host/mydb"}]
            )
        ]
        result = scan_secrets(manifests, {}, "dev")
        assert result.confirmed_secrets == 0

    def test_hardcoded_database_url_in_dev_downgraded_to_high_severity(self):
        manifests = [
            self._deployment_with_env(
                [{"name": "DATABASE_URL", "value": "postgresql://admin:s3cret@db-host/mydb"}]
            )
        ]
        result = scan_secrets(manifests, {}, "dev")
        for finding in result.soft_risks:
            if finding.type == "database_url":
                assert finding.severity == "high"

    def test_hardcoded_database_url_in_staging_goes_to_soft_risks(self):
        manifests = [
            self._deployment_with_env(
                [{"name": "DATABASE_URL", "value": "postgresql://admin:s3cret@db-host/mydb"}]
            )
        ]
        result = scan_secrets(manifests, {}, "staging")
        assert len(result.hard_blocks) == 0
        assert len(result.soft_risks) > 0

    def test_suspicious_key_name_creates_soft_risk(self):
        # Use "api-key" (dash separator): matches SOFT_PATTERNS suspicious_key_name regex
        # but combined "api-key=notasecretvalue" does NOT match the hard generic_password_env
        # pattern (which requires PASSWORD|SECRET|TOKEN|API_KEY with underscore or nothing)
        manifests = [
            self._deployment_with_env(
                [{"name": "api-key", "value": "notasecretvalue"}]
            )
        ]
        result = scan_secrets(manifests, {}, "production")
        assert len(result.soft_risks) > 0
        types = {f.type for f in result.soft_risks}
        assert "suspicious_key_name" in types

    def test_suspicious_key_name_does_not_go_to_hard_blocks(self):
        # "secret-key" matches soft suspicious_key_name but combined "secret-key=notasecretvalue"
        # does not match the hard generic_password_env pattern (requires SECRET= not SECRET-)
        manifests = [
            self._deployment_with_env(
                [{"name": "secret-key", "value": "notasecretvalue"}]
            )
        ]
        result = scan_secrets(manifests, {}, "production")
        assert result.hard_blocks == []

    def test_values_dict_with_high_entropy_string_creates_soft_risk(self):
        # Use a neutral key name ("session_id") so the combined string does not trigger
        # the hard generic_password_env pattern (which matches TOKEN=, PASSWORD=, etc.)
        # The value has entropy ~5.09 > 4.5, so it fires the inline entropy check
        values = {"config": {"session_id": "sk-Tz3xL9RqmA5bKpW8vYnE2cUoJ4dGfMi"}}
        result = scan_secrets([], values, "production")
        assert result.total_suspects > 0
        entropy_findings = [f for f in result.soft_risks if f.type == "high_entropy_string"]
        assert len(entropy_findings) > 0

    def test_values_dict_with_low_entropy_string_not_flagged(self):
        values = {"config": {"replicas": "3", "app_name": "myapp"}}
        result = scan_secrets([], values, "production")
        entropy_findings = [f for f in result.soft_risks if f.type == "high_entropy_string"]
        assert len(entropy_findings) == 0

    def test_aws_access_key_in_configmap_detected(self):
        manifests = [
            {
                "kind": "ConfigMap",
                "metadata": {"name": "aws-config"},
                "data": {"access_key": "AKIAIOSFODNN7EXAMPLE"},
            }
        ]
        result = scan_secrets(manifests, {}, "production")
        assert result.confirmed_secrets > 0
        types = {f.type for f in result.hard_blocks}
        assert "aws_access_key" in types

    def test_github_token_in_env_detected(self):
        manifests = [
            self._deployment_with_env(
                [{"name": "GH_TOKEN", "value": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"}]
            )
        ]
        result = scan_secrets(manifests, {}, "production")
        assert result.confirmed_secrets > 0
        types = {f.type for f in result.hard_blocks}
        assert "github_token" in types

    def test_private_key_in_configmap_detected(self):
        manifests = [
            {
                "kind": "ConfigMap",
                "metadata": {"name": "tls-config"},
                "data": {"private.key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK..."},
            }
        ]
        result = scan_secrets(manifests, {}, "production")
        assert result.confirmed_secrets > 0
        types = {f.type for f in result.hard_blocks}
        assert "private_key" in types

    def test_multiple_secret_types_in_one_manifest(self):
        manifests = [
            self._deployment_with_env(
                [
                    {"name": "DB_URL", "value": "postgresql://admin:s3cret@db/app"},
                    {"name": "GH_TOKEN", "value": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"},
                    {"name": "AWS_KEY", "value": "AKIAIOSFODNN7EXAMPLE"},
                ]
            )
        ]
        result = scan_secrets(manifests, {}, "production")
        assert result.confirmed_secrets >= 3
        types = {f.type for f in result.hard_blocks}
        assert "database_url" in types
        assert "github_token" in types
        assert "aws_access_key" in types

    def test_total_suspects_equals_hard_blocks_plus_soft_risks(self):
        manifests = [
            self._deployment_with_env(
                [
                    {"name": "DB_URL", "value": "postgresql://admin:s3cret@db/app"},
                    {"name": "api_key", "value": "nothighentropy"},
                ]
            )
        ]
        result = scan_secrets(manifests, {}, "production")
        assert result.total_suspects == len(result.hard_blocks) + len(result.soft_risks)

    def test_false_positives_is_zero(self):
        manifests = [
            self._deployment_with_env(
                [{"name": "DATABASE_URL", "value": "postgresql://user:pass@host/db"}]
            )
        ]
        result = scan_secrets(manifests, {}, "production")
        assert result.false_positives == 0

    def test_empty_manifests_and_empty_values_return_zero(self):
        result = scan_secrets([], {}, "production")
        assert result.total_suspects == 0
        assert result.confirmed_secrets == 0
        assert result.hard_blocks == []
        assert result.soft_risks == []

    def test_valueFrom_refs_in_env_not_scanned(self):
        # Env vars with valueFrom (not value) should not produce findings
        manifests = [
            {
                "kind": "Deployment",
                "metadata": {"name": "secure"},
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {
                                    "name": "app",
                                    "env": [
                                        {
                                            "name": "DATABASE_URL",
                                            "valueFrom": {
                                                "secretKeyRef": {
                                                    "name": "db-secret",
                                                    "key": "url",
                                                }
                                            },
                                        }
                                    ],
                                }
                            ]
                        }
                    }
                },
            }
        ]
        result = scan_secrets(manifests, {}, "production")
        assert result.confirmed_secrets == 0
        assert result.hard_blocks == []

    def test_nested_values_dict_flattened_and_scanned(self):
        values = {
            "database": {
                "url": "postgresql://admin:secret@db/app",
            }
        }
        result = scan_secrets([], values, "production")
        assert result.confirmed_secrets > 0
        types = {f.type for f in result.hard_blocks}
        assert "database_url" in types

    def test_annotation_with_secret_detected(self):
        manifests = [
            {
                "kind": "Deployment",
                "metadata": {
                    "name": "web",
                    "annotations": {
                        "deploy-token": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
                    },
                },
                "spec": {"template": {"spec": {"containers": []}}},
            }
        ]
        result = scan_secrets(manifests, {}, "production")
        assert result.confirmed_secrets > 0
        types = {f.type for f in result.hard_blocks}
        assert "github_token" in types
