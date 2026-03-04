"""Unit tests for all 10 Istio CRD policy checks.

Each check gets tests for every code branch:
  - skip  — non-matching kind returns passed=True with "skipped" message
  - pass  — correctly-configured resource
  - fail  — misconfigured resource triggers the violation

The helper ``_run_check`` finds a check by ID by iterating over
``get_check_fns()``.  The import of ``vlamguard.engine.crd.istio`` is required
to trigger the ``@policy_check`` decorator registrations before the registry
is queried.
"""

import vlamguard.engine.crd.istio  # noqa: F401  — registers Istio checks
from vlamguard.engine.registry import get_check_fns
from vlamguard.models.response import PolicyCheckResult


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _run_check(check_id: str, manifest: dict) -> PolicyCheckResult:
    """Find check by ID and run it against *manifest*."""
    for fn in get_check_fns():
        result = fn(manifest)
        if result.check_id == check_id:
            return result
    raise ValueError(f"Check '{check_id}' not found in registry")


# ---------------------------------------------------------------------------
# Manifest builders
# ---------------------------------------------------------------------------


def _virtual_service(
    *,
    name: str = "my-vs",
    http_routes: list | None = None,
) -> dict:
    spec: dict = {}
    if http_routes is not None:
        spec["http"] = http_routes
    return {
        "apiVersion": "networking.istio.io/v1beta1",
        "kind": "VirtualService",
        "metadata": {"name": name, "namespace": "default"},
        "spec": spec,
    }


def _destination_rule(
    *,
    name: str = "my-dr",
    traffic_policy: dict | None = None,
) -> dict:
    spec: dict = {}
    if traffic_policy is not None:
        spec["trafficPolicy"] = traffic_policy
    return {
        "apiVersion": "networking.istio.io/v1beta1",
        "kind": "DestinationRule",
        "metadata": {"name": name, "namespace": "default"},
        "spec": spec,
    }


def _peer_authentication(
    *,
    name: str = "my-pa",
    mtls: dict | None = None,
) -> dict:
    spec: dict = {}
    if mtls is not None:
        spec["mtls"] = mtls
    return {
        "apiVersion": "security.istio.io/v1beta1",
        "kind": "PeerAuthentication",
        "metadata": {"name": name, "namespace": "default"},
        "spec": spec,
    }


def _authorization_policy(
    *,
    name: str = "my-ap",
    action: str | None = None,
    rules: list | None = None,
) -> dict:
    spec: dict = {}
    if action is not None:
        spec["action"] = action
    if rules is not None:
        spec["rules"] = rules
    return {
        "apiVersion": "security.istio.io/v1beta1",
        "kind": "AuthorizationPolicy",
        "metadata": {"name": name, "namespace": "default"},
        "spec": spec,
    }


def _gateway(
    *,
    name: str = "my-gw",
    servers: list | None = None,
) -> dict:
    spec: dict = {}
    if servers is not None:
        spec["servers"] = servers
    return {
        "apiVersion": "networking.istio.io/v1beta1",
        "kind": "Gateway",
        "metadata": {"name": name, "namespace": "default"},
        "spec": spec,
    }


def _deployment(name: str = "web") -> dict:
    """Generic non-Istio manifest for skip cases."""
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name},
        "spec": {
            "replicas": 1,
            "template": {
                "spec": {"containers": [{"name": "app", "image": "nginx:1.25.3"}]}
            },
        },
    }


# ---------------------------------------------------------------------------
# 1. istio_virtualservice_timeout
# ---------------------------------------------------------------------------


class TestVirtualServiceTimeout:
    _ID = "istio_virtualservice_timeout"

    def test_skip_non_virtual_service(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_skip_non_virtual_service_check_id_correct(self):
        result = _run_check(self._ID, _deployment())
        assert result.check_id == self._ID

    def test_pass_no_http_routes(self):
        result = _run_check(self._ID, _virtual_service(http_routes=[]))
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_pass_no_http_key_in_spec(self):
        # spec has no 'http' key at all
        result = _run_check(self._ID, _virtual_service())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_pass_single_route_with_timeout(self):
        routes = [{"timeout": "30s", "route": [{"destination": {"host": "svc"}}]}]
        result = _run_check(self._ID, _virtual_service(http_routes=routes))
        assert result.passed is True
        assert "1" in result.message

    def test_pass_multiple_routes_all_have_timeout(self):
        routes = [
            {"timeout": "30s", "route": [{"destination": {"host": "svc-a"}}]},
            {"timeout": "10s", "route": [{"destination": {"host": "svc-b"}}]},
            {"timeout": "60s", "route": [{"destination": {"host": "svc-c"}}]},
        ]
        result = _run_check(self._ID, _virtual_service(http_routes=routes))
        assert result.passed is True
        assert "3" in result.message

    def test_fail_single_route_missing_timeout(self):
        routes = [{"route": [{"destination": {"host": "svc"}}]}]
        result = _run_check(self._ID, _virtual_service(http_routes=routes))
        assert result.passed is False
        assert "route[0]" in result.message
        assert result.details is not None
        assert result.details["routes_without_timeout"] == ["route[0]"]
        assert result.details["total_routes"] == 1

    def test_fail_multiple_routes_all_missing_timeout(self):
        routes = [
            {"route": [{"destination": {"host": "svc-a"}}]},
            {"route": [{"destination": {"host": "svc-b"}}]},
        ]
        result = _run_check(self._ID, _virtual_service(http_routes=routes))
        assert result.passed is False
        assert result.details["routes_without_timeout"] == ["route[0]", "route[1]"]
        assert result.details["total_routes"] == 2

    def test_fail_mixed_routes_some_missing_timeout(self):
        routes = [
            {"timeout": "30s", "route": [{"destination": {"host": "svc-a"}}]},
            {"route": [{"destination": {"host": "svc-b"}}]},
            {"timeout": "10s", "route": [{"destination": {"host": "svc-c"}}]},
            {"route": [{"destination": {"host": "svc-d"}}]},
        ]
        result = _run_check(self._ID, _virtual_service(http_routes=routes))
        assert result.passed is False
        assert result.details["routes_without_timeout"] == ["route[1]", "route[3]"]
        assert result.details["total_routes"] == 4
        assert "2 HTTP route(s)" in result.message

    def test_fail_message_mentions_cascade_failures(self):
        routes = [{"route": [{"destination": {"host": "svc"}}]}]
        result = _run_check(self._ID, _virtual_service(http_routes=routes))
        assert "cascading" in result.message.lower()


# ---------------------------------------------------------------------------
# 2. istio_virtualservice_retries
# ---------------------------------------------------------------------------


class TestVirtualServiceRetries:
    _ID = "istio_virtualservice_retries"

    def test_skip_non_virtual_service(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_pass_no_http_routes(self):
        result = _run_check(self._ID, _virtual_service(http_routes=[]))
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_pass_no_http_key_in_spec(self):
        result = _run_check(self._ID, _virtual_service())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_pass_single_route_with_retries(self):
        routes = [
            {
                "retries": {"attempts": 3, "perTryTimeout": "5s"},
                "route": [{"destination": {"host": "svc"}}],
            }
        ]
        result = _run_check(self._ID, _virtual_service(http_routes=routes))
        assert result.passed is True
        assert "1" in result.message

    def test_pass_multiple_routes_all_have_retries(self):
        routes = [
            {"retries": {"attempts": 3, "perTryTimeout": "5s"}},
            {"retries": {"attempts": 2, "perTryTimeout": "3s"}},
        ]
        result = _run_check(self._ID, _virtual_service(http_routes=routes))
        assert result.passed is True
        assert "2" in result.message

    def test_fail_single_route_missing_retries(self):
        routes = [{"route": [{"destination": {"host": "svc"}}]}]
        result = _run_check(self._ID, _virtual_service(http_routes=routes))
        assert result.passed is False
        assert "route[0]" in result.message
        assert result.details is not None
        assert result.details["routes_without_retries"] == ["route[0]"]
        assert result.details["total_routes"] == 1

    def test_fail_multiple_routes_all_missing_retries(self):
        routes = [
            {"route": [{"destination": {"host": "svc-a"}}]},
            {"route": [{"destination": {"host": "svc-b"}}]},
        ]
        result = _run_check(self._ID, _virtual_service(http_routes=routes))
        assert result.passed is False
        assert result.details["routes_without_retries"] == ["route[0]", "route[1]"]
        assert result.details["total_routes"] == 2

    def test_fail_mixed_routes_some_missing_retries(self):
        routes = [
            {"retries": {"attempts": 3, "perTryTimeout": "5s"}},
            {"route": [{"destination": {"host": "svc-b"}}]},
        ]
        result = _run_check(self._ID, _virtual_service(http_routes=routes))
        assert result.passed is False
        assert result.details["routes_without_retries"] == ["route[1]"]
        assert result.details["total_routes"] == 2

    def test_fail_message_mentions_transient_errors(self):
        routes = [{"route": [{"destination": {"host": "svc"}}]}]
        result = _run_check(self._ID, _virtual_service(http_routes=routes))
        assert "transient" in result.message.lower()


# ---------------------------------------------------------------------------
# 3. istio_virtualservice_fault_injection_production
# ---------------------------------------------------------------------------


class TestVirtualServiceFaultInjection:
    _ID = "istio_virtualservice_fault_injection_production"

    def test_skip_non_virtual_service(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_pass_no_http_routes(self):
        result = _run_check(self._ID, _virtual_service(http_routes=[]))
        assert result.passed is True
        assert "no fault" in result.message.lower()

    def test_pass_no_http_key_in_spec(self):
        result = _run_check(self._ID, _virtual_service())
        assert result.passed is True
        assert "no fault" in result.message.lower()

    def test_pass_routes_without_fault(self):
        routes = [
            {"timeout": "30s", "route": [{"destination": {"host": "svc"}}]},
            {"retries": {"attempts": 3}},
        ]
        result = _run_check(self._ID, _virtual_service(http_routes=routes))
        assert result.passed is True

    def test_fail_single_route_with_fault_delay(self):
        routes = [
            {"fault": {"delay": {"fixedDelay": "5s", "percentage": {"value": 100}}}}
        ]
        result = _run_check(self._ID, _virtual_service(http_routes=routes))
        assert result.passed is False
        assert "route[0]" in result.message
        assert result.details is not None
        assert result.details["routes_with_fault"] == ["route[0]"]

    def test_fail_single_route_with_fault_abort(self):
        routes = [
            {"fault": {"abort": {"httpStatus": 500, "percentage": {"value": 50}}}}
        ]
        result = _run_check(self._ID, _virtual_service(http_routes=routes))
        assert result.passed is False

    def test_fail_multiple_routes_with_fault(self):
        routes = [
            {"fault": {"delay": {"fixedDelay": "2s"}}},
            {"route": [{"destination": {"host": "svc-ok"}}]},
            {"fault": {"abort": {"httpStatus": 503}}},
        ]
        result = _run_check(self._ID, _virtual_service(http_routes=routes))
        assert result.passed is False
        assert result.details["routes_with_fault"] == ["route[0]", "route[2]"]
        assert "2 route(s)" in result.message

    def test_fail_message_mentions_live_traffic(self):
        routes = [{"fault": {"delay": {"fixedDelay": "5s"}}}]
        result = _run_check(self._ID, _virtual_service(http_routes=routes))
        assert "live traffic" in result.message.lower() or "intentionally" in result.message.lower()


# ---------------------------------------------------------------------------
# 4. istio_destination_rule_tls
# ---------------------------------------------------------------------------


class TestDestinationRuleTls:
    _ID = "istio_destination_rule_tls"

    def test_skip_non_destination_rule(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_skip_virtual_service(self):
        result = _run_check(self._ID, _virtual_service())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_fail_no_traffic_policy(self):
        # No trafficPolicy key at all
        result = _run_check(self._ID, _destination_rule())
        assert result.passed is False
        assert result.details is not None
        assert result.details["tls_mode"] is None

    def test_fail_no_tls_in_traffic_policy(self):
        result = _run_check(self._ID, _destination_rule(traffic_policy={"connectionPool": {}}))
        assert result.passed is False
        assert result.details["tls_mode"] is None

    def test_fail_no_mode_in_tls(self):
        result = _run_check(self._ID, _destination_rule(traffic_policy={"tls": {}}))
        assert result.passed is False
        assert result.details["tls_mode"] is None

    def test_fail_mode_disable(self):
        result = _run_check(self._ID, _destination_rule(traffic_policy={"tls": {"mode": "DISABLE"}}))
        assert result.passed is False
        assert "DISABLE" in result.message
        assert result.details["tls_mode"] == "DISABLE"

    def test_fail_mode_simple(self):
        result = _run_check(self._ID, _destination_rule(traffic_policy={"tls": {"mode": "SIMPLE"}}))
        assert result.passed is False
        assert "SIMPLE" in result.message
        assert result.details["tls_mode"] == "SIMPLE"

    def test_fail_mode_unknown_value(self):
        result = _run_check(self._ID, _destination_rule(traffic_policy={"tls": {"mode": "PLAINTEXT"}}))
        assert result.passed is False
        assert result.details["tls_mode"] == "PLAINTEXT"
        assert "accepted_modes" in result.details

    def test_pass_mode_istio_mutual(self):
        result = _run_check(
            self._ID, _destination_rule(traffic_policy={"tls": {"mode": "ISTIO_MUTUAL"}})
        )
        assert result.passed is True
        assert "ISTIO_MUTUAL" in result.message

    def test_pass_mode_mutual(self):
        result = _run_check(
            self._ID, _destination_rule(traffic_policy={"tls": {"mode": "MUTUAL"}})
        )
        assert result.passed is True
        assert "MUTUAL" in result.message

    def test_fail_accepted_modes_listed_in_details(self):
        result = _run_check(self._ID, _destination_rule(traffic_policy={"tls": {"mode": "DISABLE"}}))
        assert "accepted_modes" in result.details
        assert "ISTIO_MUTUAL" in result.details["accepted_modes"]
        assert "MUTUAL" in result.details["accepted_modes"]


# ---------------------------------------------------------------------------
# 5. istio_destination_rule_outlier_detection
# ---------------------------------------------------------------------------


class TestDestinationRuleOutlierDetection:
    _ID = "istio_destination_rule_outlier_detection"

    def test_skip_non_destination_rule(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_skip_virtual_service(self):
        result = _run_check(self._ID, _virtual_service())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_fail_no_traffic_policy(self):
        result = _run_check(self._ID, _destination_rule())
        assert result.passed is False
        assert result.details is not None
        assert result.details["outlierDetection"] is None

    def test_fail_traffic_policy_without_outlier_detection(self):
        result = _run_check(self._ID, _destination_rule(traffic_policy={"connectionPool": {"tcp": {}}}))
        assert result.passed is False
        assert result.details["outlierDetection"] is None

    def test_fail_message_mentions_ejected(self):
        result = _run_check(self._ID, _destination_rule())
        assert "ejected" in result.message.lower()

    def test_pass_outlier_detection_present(self):
        outlier = {
            "consecutiveGatewayErrors": 5,
            "interval": "10s",
            "baseEjectionTime": "30s",
        }
        result = _run_check(
            self._ID,
            _destination_rule(traffic_policy={"outlierDetection": outlier}),
        )
        assert result.passed is True
        assert "outlier detection" in result.message.lower()

    def test_pass_outlier_detection_minimal(self):
        # Even an empty dict for outlierDetection is truthy enough to pass
        result = _run_check(
            self._ID,
            _destination_rule(traffic_policy={"outlierDetection": {"consecutiveErrors": 3}}),
        )
        assert result.passed is True


# ---------------------------------------------------------------------------
# 6. istio_destination_rule_connection_pool
# ---------------------------------------------------------------------------


class TestDestinationRuleConnectionPool:
    _ID = "istio_destination_rule_connection_pool"

    def test_skip_non_destination_rule(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_skip_virtual_service(self):
        result = _run_check(self._ID, _virtual_service())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_fail_no_traffic_policy(self):
        result = _run_check(self._ID, _destination_rule())
        assert result.passed is False
        assert result.details is not None
        assert result.details["connectionPool"] is None

    def test_fail_traffic_policy_without_connection_pool(self):
        result = _run_check(
            self._ID,
            _destination_rule(traffic_policy={"outlierDetection": {"consecutiveErrors": 3}}),
        )
        assert result.passed is False
        assert result.details["connectionPool"] is None

    def test_fail_message_mentions_resource_exhaustion(self):
        result = _run_check(self._ID, _destination_rule())
        assert "exhaustion" in result.message.lower() or "unbounded" in result.message.lower()

    def test_pass_connection_pool_present(self):
        conn_pool = {"tcp": {"maxConnections": 100}, "http": {"http1MaxPendingRequests": 50}}
        result = _run_check(
            self._ID,
            _destination_rule(traffic_policy={"connectionPool": conn_pool}),
        )
        assert result.passed is True
        assert "connection pool" in result.message.lower()

    def test_pass_connection_pool_tcp_only(self):
        result = _run_check(
            self._ID,
            _destination_rule(traffic_policy={"connectionPool": {"tcp": {"maxConnections": 50}}}),
        )
        assert result.passed is True

    def test_pass_all_three_traffic_policies_set(self):
        traffic = {
            "tls": {"mode": "ISTIO_MUTUAL"},
            "outlierDetection": {"consecutiveErrors": 5},
            "connectionPool": {"tcp": {"maxConnections": 100}},
        }
        result = _run_check(self._ID, _destination_rule(traffic_policy=traffic))
        assert result.passed is True


# ---------------------------------------------------------------------------
# 7. istio_peer_auth_strict_mtls
# ---------------------------------------------------------------------------


class TestPeerAuthStrictMtls:
    _ID = "istio_peer_auth_strict_mtls"

    def test_skip_non_peer_authentication(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_skip_authorization_policy(self):
        result = _run_check(self._ID, _authorization_policy())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_fail_no_spec_mtls(self):
        # spec has no 'mtls' key at all
        result = _run_check(self._ID, _peer_authentication())
        assert result.passed is False
        assert result.details is not None
        assert result.details["mtls_mode"] is None
        assert "inherited" in result.message.lower() or "permissive" in result.message.lower()

    def test_fail_empty_mtls_dict(self):
        result = _run_check(self._ID, _peer_authentication(mtls={}))
        assert result.passed is False
        assert result.details["mtls_mode"] is None

    def test_fail_mode_permissive(self):
        result = _run_check(self._ID, _peer_authentication(mtls={"mode": "PERMISSIVE"}))
        assert result.passed is False
        assert "PERMISSIVE" in result.message
        assert result.details["mtls_mode"] == "PERMISSIVE"

    def test_fail_mode_unset(self):
        result = _run_check(self._ID, _peer_authentication(mtls={"mode": "UNSET"}))
        assert result.passed is False
        assert result.details["mtls_mode"] == "UNSET"

    def test_fail_mode_disable(self):
        result = _run_check(self._ID, _peer_authentication(mtls={"mode": "DISABLE"}))
        assert result.passed is False
        assert result.details["mtls_mode"] == "DISABLE"

    def test_pass_mode_strict(self):
        result = _run_check(self._ID, _peer_authentication(mtls={"mode": "STRICT"}))
        assert result.passed is True
        assert "STRICT" in result.message

    def test_fail_message_mentions_plaintext(self):
        result = _run_check(self._ID, _peer_authentication(mtls={"mode": "PERMISSIVE"}))
        assert "plaintext" in result.message.lower()


# ---------------------------------------------------------------------------
# 8. istio_authz_no_allow_all
# ---------------------------------------------------------------------------


class TestAuthzNoAllowAll:
    _ID = "istio_authz_no_allow_all"

    def test_skip_non_authorization_policy(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_skip_peer_authentication(self):
        result = _run_check(self._ID, _peer_authentication())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_fail_allow_with_no_rules_key(self):
        # action ALLOW, rules key absent (defaults to None via spec.get("rules"))
        manifest = _authorization_policy(action="ALLOW")
        result = _run_check(self._ID, manifest)
        assert result.passed is False
        assert result.details is not None
        assert result.details["action"] == "ALLOW"
        assert result.details["rules"] is None

    def test_fail_allow_with_empty_rules_list(self):
        # rules=[] is falsy — same as having no rules
        manifest = _authorization_policy(action="ALLOW", rules=[])
        result = _run_check(self._ID, manifest)
        assert result.passed is False

    def test_fail_default_action_no_rules(self):
        # Per Istio API, action defaults to ALLOW when absent
        # Build manifest with no action key and no rules
        manifest = {
            "apiVersion": "security.istio.io/v1beta1",
            "kind": "AuthorizationPolicy",
            "metadata": {"name": "no-action", "namespace": "default"},
            "spec": {},
        }
        result = _run_check(self._ID, manifest)
        assert result.passed is False
        assert result.details["action"] == "ALLOW"

    def test_fail_message_includes_policy_name(self):
        manifest = _authorization_policy(name="open-door", action="ALLOW")
        result = _run_check(self._ID, manifest)
        assert "open-door" in result.message

    def test_fail_unnamed_policy_shows_placeholder(self):
        manifest = {
            "apiVersion": "security.istio.io/v1beta1",
            "kind": "AuthorizationPolicy",
            "metadata": {},
            "spec": {"action": "ALLOW"},
        }
        result = _run_check(self._ID, manifest)
        assert result.passed is False
        assert "<unnamed>" in result.message

    def test_pass_allow_with_explicit_rules(self):
        rules = [{"from": [{"source": {"principals": ["cluster.local/ns/default/sa/web"]}}]}]
        manifest = _authorization_policy(action="ALLOW", rules=rules)
        result = _run_check(self._ID, manifest)
        assert result.passed is True
        assert "ALLOW" in result.message

    def test_pass_deny_with_no_rules(self):
        # DENY with no rules means deny nothing — that is safe
        manifest = _authorization_policy(action="DENY")
        result = _run_check(self._ID, manifest)
        assert result.passed is True
        assert "DENY" in result.message

    def test_pass_deny_with_rules(self):
        rules = [{"to": [{"operation": {"methods": ["DELETE"]}}]}]
        manifest = _authorization_policy(action="DENY", rules=rules)
        result = _run_check(self._ID, manifest)
        assert result.passed is True

    def test_pass_custom_action_with_rules(self):
        rules = [{"from": [{"source": {"namespaces": ["prod"]}}]}]
        manifest = _authorization_policy(action="ALLOW", rules=rules)
        result = _run_check(self._ID, manifest)
        assert result.passed is True


# ---------------------------------------------------------------------------
# 9. istio_gateway_tls_required
# ---------------------------------------------------------------------------


class TestGatewayTlsRequired:
    _ID = "istio_gateway_tls_required"

    def test_skip_non_gateway(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_skip_virtual_service(self):
        result = _run_check(self._ID, _virtual_service())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_pass_no_servers_key(self):
        result = _run_check(self._ID, _gateway())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_pass_empty_servers_list(self):
        result = _run_check(self._ID, _gateway(servers=[]))
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_pass_single_server_with_tls_mode(self):
        servers = [
            {
                "port": {"number": 443, "name": "https", "protocol": "HTTPS"},
                "hosts": ["api.example.com"],
                "tls": {"mode": "SIMPLE", "credentialName": "my-cert"},
            }
        ]
        result = _run_check(self._ID, _gateway(servers=servers))
        assert result.passed is True
        assert "1" in result.message

    def test_pass_multiple_servers_all_with_tls(self):
        servers = [
            {
                "port": {"number": 443, "name": "https", "protocol": "HTTPS"},
                "hosts": ["api.example.com"],
                "tls": {"mode": "SIMPLE"},
            },
            {
                "port": {"number": 8443, "name": "grpcs"},
                "hosts": ["grpc.example.com"],
                "tls": {"mode": "PASSTHROUGH"},
            },
        ]
        result = _run_check(self._ID, _gateway(servers=servers))
        assert result.passed is True
        assert "2" in result.message

    def test_fail_server_missing_tls_key(self):
        servers = [
            {
                "port": {"number": 80, "name": "http"},
                "hosts": ["api.example.com"],
            }
        ]
        result = _run_check(self._ID, _gateway(servers=servers))
        assert result.passed is False
        assert result.details is not None
        assert "http" in result.details["servers_without_tls"]
        assert result.details["total_servers"] == 1

    def test_fail_server_tls_without_mode(self):
        servers = [
            {
                "port": {"number": 443, "name": "https"},
                "hosts": ["api.example.com"],
                "tls": {"credentialName": "my-cert"},  # missing mode
            }
        ]
        result = _run_check(self._ID, _gateway(servers=servers))
        assert result.passed is False
        assert "https" in result.details["servers_without_tls"]

    def test_fail_port_name_used_in_violation(self):
        servers = [
            {
                "port": {"number": 80, "name": "plaintext-http"},
                "hosts": ["api.example.com"],
            }
        ]
        result = _run_check(self._ID, _gateway(servers=servers))
        assert result.passed is False
        assert "plaintext-http" in result.details["servers_without_tls"]

    def test_fail_port_number_fallback_when_no_name(self):
        servers = [
            {
                "port": {"number": 80},  # no 'name' key
                "hosts": ["api.example.com"],
            }
        ]
        result = _run_check(self._ID, _gateway(servers=servers))
        assert result.passed is False
        assert "80" in result.details["servers_without_tls"]

    def test_fail_server_index_fallback_when_no_port(self):
        servers = [
            {
                "hosts": ["api.example.com"],
                # no 'port' key and no tls
            }
        ]
        result = _run_check(self._ID, _gateway(servers=servers))
        assert result.passed is False
        assert "server[0]" in result.details["servers_without_tls"]

    def test_fail_mixed_servers_reports_only_violating(self):
        servers = [
            {
                "port": {"number": 443, "name": "https"},
                "hosts": ["api.example.com"],
                "tls": {"mode": "SIMPLE"},
            },
            {
                "port": {"number": 80, "name": "http"},
                "hosts": ["api.example.com"],
            },
        ]
        result = _run_check(self._ID, _gateway(servers=servers))
        assert result.passed is False
        assert result.details["servers_without_tls"] == ["http"]
        assert result.details["total_servers"] == 2

    def test_fail_message_mentions_plaintext(self):
        servers = [{"port": {"number": 80, "name": "http"}, "hosts": ["x.com"]}]
        result = _run_check(self._ID, _gateway(servers=servers))
        assert "plaintext" in result.message.lower()


# ---------------------------------------------------------------------------
# 10. istio_gateway_wildcard_host
# ---------------------------------------------------------------------------


class TestGatewayWildcardHost:
    _ID = "istio_gateway_wildcard_host"

    def test_skip_non_gateway(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_skip_virtual_service(self):
        result = _run_check(self._ID, _virtual_service())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_pass_no_servers(self):
        result = _run_check(self._ID, _gateway())
        assert result.passed is True
        assert "wildcard" not in result.message.lower() or "no" in result.message.lower()

    def test_pass_empty_servers_list(self):
        result = _run_check(self._ID, _gateway(servers=[]))
        assert result.passed is True

    def test_pass_specific_fqdn_hosts(self):
        servers = [
            {
                "port": {"number": 443, "name": "https"},
                "hosts": ["api.example.com", "www.example.com"],
                "tls": {"mode": "SIMPLE"},
            }
        ]
        result = _run_check(self._ID, _gateway(servers=servers))
        assert result.passed is True
        assert "no gateway servers" in result.message.lower()

    def test_pass_subdomain_wildcard_not_bare(self):
        # "*.example.com" is a subdomain wildcard, not a bare "*"
        servers = [
            {
                "port": {"number": 443, "name": "https"},
                "hosts": ["*.example.com"],
                "tls": {"mode": "SIMPLE"},
            }
        ]
        result = _run_check(self._ID, _gateway(servers=servers))
        assert result.passed is True

    def test_pass_server_with_no_hosts_key(self):
        # hosts key absent — no wildcard possible
        servers = [{"port": {"number": 443, "name": "https"}, "tls": {"mode": "SIMPLE"}}]
        result = _run_check(self._ID, _gateway(servers=servers))
        assert result.passed is True

    def test_fail_bare_wildcard_host(self):
        servers = [
            {
                "port": {"number": 80, "name": "http"},
                "hosts": ["*"],
            }
        ]
        result = _run_check(self._ID, _gateway(servers=servers))
        assert result.passed is False
        assert result.details is not None
        assert "http" in result.details["wildcard_servers"]

    def test_fail_wildcard_with_other_hosts(self):
        # "*" is in the hosts list alongside explicit hosts
        servers = [
            {
                "port": {"number": 80, "name": "http"},
                "hosts": ["api.example.com", "*"],
            }
        ]
        result = _run_check(self._ID, _gateway(servers=servers))
        assert result.passed is False
        assert "http" in result.details["wildcard_servers"]

    def test_fail_multiple_servers_with_wildcard(self):
        servers = [
            {"port": {"number": 80, "name": "http"}, "hosts": ["*"]},
            {"port": {"number": 443, "name": "https"}, "hosts": ["api.example.com"], "tls": {"mode": "SIMPLE"}},
            {"port": {"number": 8080, "name": "http-alt"}, "hosts": ["*"]},
        ]
        result = _run_check(self._ID, _gateway(servers=servers))
        assert result.passed is False
        assert "http" in result.details["wildcard_servers"]
        assert "http-alt" in result.details["wildcard_servers"]
        assert "https" not in result.details["wildcard_servers"]

    def test_fail_port_number_fallback_in_wildcard_violation(self):
        servers = [
            {
                "port": {"number": 80},  # no 'name' key
                "hosts": ["*"],
            }
        ]
        result = _run_check(self._ID, _gateway(servers=servers))
        assert result.passed is False
        assert "80" in result.details["wildcard_servers"]

    def test_fail_no_port_key_uses_server_index(self):
        servers = [
            {
                "hosts": ["*"],
            }
        ]
        result = _run_check(self._ID, _gateway(servers=servers))
        assert result.passed is False
        assert "server[0]" in result.details["wildcard_servers"]

    def test_fail_message_mentions_fqdns(self):
        servers = [{"port": {"number": 80, "name": "http"}, "hosts": ["*"]}]
        result = _run_check(self._ID, _gateway(servers=servers))
        assert "fqdn" in result.message.lower() or "explicit" in result.message.lower()


# ---------------------------------------------------------------------------
# Cross-check: all 10 Istio check IDs are registered
# ---------------------------------------------------------------------------


class TestIstioCheckRegistration:
    _EXPECTED_IDS = {
        "istio_virtualservice_timeout",
        "istio_virtualservice_retries",
        "istio_virtualservice_fault_injection_production",
        "istio_destination_rule_tls",
        "istio_destination_rule_outlier_detection",
        "istio_destination_rule_connection_pool",
        "istio_peer_auth_strict_mtls",
        "istio_authz_no_allow_all",
        "istio_gateway_tls_required",
        "istio_gateway_wildcard_host",
    }

    def test_all_istio_checks_registered(self):
        registered = {fn(_deployment()).check_id for fn in get_check_fns()}
        assert self._EXPECTED_IDS.issubset(registered), (
            f"Missing Istio checks: {self._EXPECTED_IDS - registered}"
        )

    def test_istio_check_severity_values(self):
        from vlamguard.engine.registry import get_all_checks

        istio_checks = {c.check_id: c for c in get_all_checks() if c.check_id.startswith("istio_")}
        assert len(istio_checks) == 10

        # Verify severity classifications match the source
        assert istio_checks["istio_peer_auth_strict_mtls"].severity == "critical"
        assert istio_checks["istio_authz_no_allow_all"].severity == "critical"
        assert istio_checks["istio_destination_rule_tls"].severity == "high"
        assert istio_checks["istio_gateway_tls_required"].severity == "high"
        assert istio_checks["istio_virtualservice_fault_injection_production"].severity == "high"
        assert istio_checks["istio_virtualservice_timeout"].severity == "medium"
        assert istio_checks["istio_virtualservice_retries"].severity == "medium"
        assert istio_checks["istio_destination_rule_outlier_detection"].severity == "medium"
        assert istio_checks["istio_destination_rule_connection_pool"].severity == "medium"
        assert istio_checks["istio_gateway_wildcard_host"].severity == "medium"

    def test_istio_check_categories(self):
        from vlamguard.engine.registry import get_all_checks

        istio_checks = {c.check_id: c for c in get_all_checks() if c.check_id.startswith("istio_")}

        security_checks = {cid for cid, c in istio_checks.items() if c.category == "istio-security"}
        reliability_checks = {cid for cid, c in istio_checks.items() if c.category == "istio-reliability"}

        assert "istio_destination_rule_tls" in security_checks
        assert "istio_peer_auth_strict_mtls" in security_checks
        assert "istio_authz_no_allow_all" in security_checks
        assert "istio_gateway_tls_required" in security_checks
        assert "istio_gateway_wildcard_host" in security_checks

        assert "istio_virtualservice_timeout" in reliability_checks
        assert "istio_virtualservice_retries" in reliability_checks
        assert "istio_virtualservice_fault_injection_production" in reliability_checks
        assert "istio_destination_rule_outlier_detection" in reliability_checks
        assert "istio_destination_rule_connection_pool" in reliability_checks

    def test_istio_result_is_policy_check_result_instance(self):
        result = _run_check("istio_virtualservice_timeout", _deployment())
        assert isinstance(result, PolicyCheckResult)

    def test_all_check_ids_unique_in_registry(self):
        from vlamguard.engine.registry import get_all_checks

        ids = [c.check_id for c in get_all_checks()]
        assert len(ids) == len(set(ids)), "Duplicate check IDs detected in registry"
