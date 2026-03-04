"""Unit tests for the 8 Argo CD CRD policy checks.

Coverage targets:
  argocd_auto_sync_prune               — 5 code paths
  argocd_sync_retry_configured         — 3 code paths
  argocd_destination_not_in_cluster    — 4 code paths
  argocd_project_not_default           — 4 code paths
  argocd_source_target_revision        — 5 code paths
  argocd_project_wildcard_destination  — 4 code paths
  argocd_project_wildcard_source       — 3 code paths
  argocd_project_cluster_resources     — 4 code paths

The _run_check helper finds a check by ID via the global registry so that
the @policy_check decorator registration is also exercised in every test.
The import of vlamguard.engine.crd.argocd triggers those registrations.
"""

import vlamguard.engine.crd.argocd  # noqa: F401  — registers Argo CD checks
from vlamguard.engine.registry import get_check_fns
from vlamguard.models.response import PolicyCheckResult


# ---------------------------------------------------------------------------
# Registry helper
# ---------------------------------------------------------------------------


def _run_check(check_id: str, manifest: dict) -> PolicyCheckResult:
    """Find a check by ID and run it against manifest."""
    for fn in get_check_fns():
        result = fn(manifest)
        if result.check_id == check_id:
            return result
    raise ValueError(f"Check '{check_id}' not found in registry")


# ---------------------------------------------------------------------------
# Manifest builders
# ---------------------------------------------------------------------------


def _application(
    *,
    name: str = "my-app",
    project: str = "my-project",
    revision: str = "v1.2.3",
    server: str = "https://k8s.example.com",
    sync_policy: dict | None = None,
) -> dict:
    """Build a minimal valid Argo CD Application manifest."""
    manifest: dict = {
        "apiVersion": "argoproj.io/v1alpha1",
        "kind": "Application",
        "metadata": {"name": name, "namespace": "argocd"},
        "spec": {
            "project": project,
            "source": {
                "repoURL": "https://github.com/example/repo",
                "targetRevision": revision,
                "path": "charts/app",
            },
            "destination": {
                "server": server,
                "namespace": "default",
            },
        },
    }
    if sync_policy is not None:
        manifest["spec"]["syncPolicy"] = sync_policy
    return manifest


def _app_project(
    *,
    name: str = "my-project",
    destinations: list | None = None,
    source_repos: list | None = None,
    cluster_resource_whitelist: list | None = None,
) -> dict:
    """Build a minimal valid Argo CD AppProject manifest."""
    spec: dict = {}
    if destinations is not None:
        spec["destinations"] = destinations
    if source_repos is not None:
        spec["sourceRepos"] = source_repos
    if cluster_resource_whitelist is not None:
        spec["clusterResourceWhitelist"] = cluster_resource_whitelist
    return {
        "apiVersion": "argoproj.io/v1alpha1",
        "kind": "AppProject",
        "metadata": {"name": name, "namespace": "argocd"},
        "spec": spec,
    }


def _deployment(name: str = "web") -> dict:
    """Generic non-Argo CD manifest for skip-path tests."""
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name},
        "spec": {
            "replicas": 1,
            "template": {
                "spec": {"containers": [{"name": "app", "image": "nginx:1.25"}]}
            },
        },
    }


# ---------------------------------------------------------------------------
# 1. argocd_auto_sync_prune
# ---------------------------------------------------------------------------


class TestArgoCDAutoSyncPrune:
    _ID = "argocd_auto_sync_prune"

    def test_skip_non_application(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_pass_no_automated_sync_policy(self):
        # Application with no syncPolicy at all
        result = _run_check(self._ID, _application())
        assert result.passed is True
        assert "no automated" in result.message.lower()

    def test_pass_empty_automated_block(self):
        # syncPolicy present but automated is an empty dict (falsy)
        result = _run_check(
            self._ID,
            _application(sync_policy={"automated": {}}),
        )
        assert result.passed is True
        assert "no automated" in result.message.lower()

    def test_fail_prune_true_self_heal_false(self):
        result = _run_check(
            self._ID,
            _application(
                sync_policy={"automated": {"prune": True, "selfHeal": False}}
            ),
        )
        assert result.passed is False
        assert result.details is not None
        assert result.details["prune"] is True
        assert result.details["selfHeal"] is False
        assert "prune=true" in result.message.lower() or "prune" in result.message

    def test_fail_prune_true_self_heal_absent_defaults_to_false(self):
        # selfHeal key missing — defaults to False in automated.get("selfHeal", False)
        result = _run_check(
            self._ID,
            _application(sync_policy={"automated": {"prune": True}}),
        )
        assert result.passed is False
        assert result.details["prune"] is True
        assert result.details["selfHeal"] is False

    def test_pass_prune_true_self_heal_true(self):
        result = _run_check(
            self._ID,
            _application(
                sync_policy={"automated": {"prune": True, "selfHeal": True}}
            ),
        )
        assert result.passed is True
        assert "consistently configured" in result.message.lower()

    def test_pass_prune_false(self):
        result = _run_check(
            self._ID,
            _application(
                sync_policy={"automated": {"prune": False, "selfHeal": False}}
            ),
        )
        assert result.passed is True

    def test_pass_only_self_heal_set(self):
        # prune defaults to False — should pass
        result = _run_check(
            self._ID,
            _application(sync_policy={"automated": {"selfHeal": True}}),
        )
        assert result.passed is True


# ---------------------------------------------------------------------------
# 2. argocd_sync_retry_configured
# ---------------------------------------------------------------------------


class TestArgoCDSyncRetryConfigured:
    _ID = "argocd_sync_retry_configured"

    def test_skip_non_application(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_fail_no_retry_no_sync_policy(self):
        # No syncPolicy at all means no retry
        result = _run_check(self._ID, _application())
        assert result.passed is False
        assert result.details is not None
        assert result.details["retry"] is None
        assert "no sync retry" in result.message.lower() or "retry" in result.message.lower()

    def test_fail_sync_policy_without_retry(self):
        result = _run_check(
            self._ID,
            _application(sync_policy={"automated": {"prune": True, "selfHeal": True}}),
        )
        assert result.passed is False
        assert result.details["retry"] is None

    def test_pass_retry_configured_with_limit(self):
        result = _run_check(
            self._ID,
            _application(
                sync_policy={
                    "retry": {
                        "limit": 5,
                        "backoff": {"duration": "5s", "factor": 2, "maxDuration": "3m"},
                    }
                }
            ),
        )
        assert result.passed is True
        assert "5" in result.message

    def test_pass_retry_without_limit_key(self):
        # retry dict present but no limit key — still counts as configured
        result = _run_check(
            self._ID,
            _application(sync_policy={"retry": {"backoff": {"duration": "5s"}}}),
        )
        assert result.passed is True
        assert "unset" in result.message


# ---------------------------------------------------------------------------
# 3. argocd_destination_not_in_cluster
# ---------------------------------------------------------------------------


class TestArgoCDDestinationNotInCluster:
    _ID = "argocd_destination_not_in_cluster"

    def test_skip_non_application(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_fail_in_cluster_server_url(self):
        result = _run_check(
            self._ID,
            _application(server="https://kubernetes.default.svc"),
        )
        assert result.passed is False
        assert result.details is not None
        assert result.details["server"] == "https://kubernetes.default.svc"
        assert "in-cluster" in result.message.lower()

    def test_pass_explicit_external_server_url(self):
        result = _run_check(
            self._ID,
            _application(server="https://k8s.prod.example.com"),
        )
        assert result.passed is True
        assert "k8s.prod.example.com" in result.message

    def test_pass_empty_server_uses_name_based(self):
        # Empty server string is acceptable (name-based cluster reference)
        app = _application()
        app["spec"]["destination"]["server"] = ""
        result = _run_check(self._ID, app)
        assert result.passed is True
        assert "(name-based)" in result.message

    def test_pass_destination_without_server_key(self):
        # No server key at all — defaults to "" in destination.get("server", "")
        app = _application()
        app["spec"]["destination"] = {"namespace": "prod"}
        result = _run_check(self._ID, app)
        assert result.passed is True


# ---------------------------------------------------------------------------
# 4. argocd_project_not_default
# ---------------------------------------------------------------------------


class TestArgoCDProjectNotDefault:
    _ID = "argocd_project_not_default"

    def test_skip_non_application(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_fail_explicit_default_project(self):
        result = _run_check(self._ID, _application(project="default"))
        assert result.passed is False
        assert result.details is not None
        assert result.details["project"] == "default"
        assert "default" in result.message.lower()

    def test_fail_missing_project_key_defaults_to_default(self):
        # spec.project absent — implementation uses .get("project", "default")
        app = _application()
        del app["spec"]["project"]
        result = _run_check(self._ID, app)
        assert result.passed is False
        assert result.details["project"] == "default"

    def test_pass_explicit_named_project(self):
        result = _run_check(self._ID, _application(project="team-alpha"))
        assert result.passed is True
        assert "team-alpha" in result.message

    def test_pass_project_name_contains_default_substring(self):
        # "default-extended" is not the literal string "default"
        result = _run_check(self._ID, _application(project="default-extended"))
        assert result.passed is True


# ---------------------------------------------------------------------------
# 5. argocd_source_target_revision
# ---------------------------------------------------------------------------


class TestArgoCDSourceTargetRevision:
    _ID = "argocd_source_target_revision"

    def test_skip_non_application(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_fail_head_revision(self):
        result = _run_check(self._ID, _application(revision="HEAD"))
        assert result.passed is False
        assert "'HEAD'" in result.message
        assert result.details is not None
        assert result.details["targetRevision"] is None or result.details["targetRevision"] == "HEAD"

    def test_fail_head_revision_lowercase(self):
        # The check uses .upper() for case-insensitive comparison
        result = _run_check(self._ID, _application(revision="head"))
        assert result.passed is False

    def test_fail_empty_revision(self):
        result = _run_check(self._ID, _application(revision=""))
        assert result.passed is False
        assert "(empty)" in result.message
        assert result.details["targetRevision"] is None

    def test_fail_missing_target_revision_key(self):
        # targetRevision absent — defaults to "" in source.get("targetRevision", "")
        app = _application()
        del app["spec"]["source"]["targetRevision"]
        result = _run_check(self._ID, app)
        assert result.passed is False
        assert "(empty)" in result.message

    def test_pass_pinned_semver_tag(self):
        result = _run_check(self._ID, _application(revision="v1.2.3"))
        assert result.passed is True
        assert "v1.2.3" in result.message

    def test_pass_full_commit_sha(self):
        sha = "a3f4b2c1d9e8f7061234567890abcdef12345678"
        result = _run_check(self._ID, _application(revision=sha))
        assert result.passed is True
        assert sha in result.message

    def test_pass_short_commit_sha(self):
        result = _run_check(self._ID, _application(revision="abc1234"))
        assert result.passed is True


# ---------------------------------------------------------------------------
# 6. argocd_project_wildcard_destination
# ---------------------------------------------------------------------------


class TestArgoCDProjectWildcardDestination:
    _ID = "argocd_project_wildcard_destination"

    def test_skip_non_app_project(self):
        # Application manifest — not an AppProject
        result = _run_check(self._ID, _application())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_skip_deployment(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_fail_single_wildcard_destination(self):
        result = _run_check(
            self._ID,
            _app_project(
                destinations=[{"server": "*", "namespace": "*"}]
            ),
        )
        assert result.passed is False
        assert result.details is not None
        assert result.details["wildcard_destinations"] == 1
        assert result.details["total_destinations"] == 1

    def test_fail_multiple_destinations_one_wildcard(self):
        result = _run_check(
            self._ID,
            _app_project(
                destinations=[
                    {"server": "https://k8s.example.com", "namespace": "staging"},
                    {"server": "*", "namespace": "*"},
                ]
            ),
        )
        assert result.passed is False
        assert result.details["wildcard_destinations"] == 1
        assert result.details["total_destinations"] == 2

    def test_fail_multiple_wildcard_destinations(self):
        result = _run_check(
            self._ID,
            _app_project(
                destinations=[
                    {"server": "*", "namespace": "*"},
                    {"server": "*", "namespace": "*"},
                ]
            ),
        )
        assert result.passed is False
        assert result.details["wildcard_destinations"] == 2

    def test_pass_scoped_destinations(self):
        result = _run_check(
            self._ID,
            _app_project(
                destinations=[
                    {"server": "https://k8s.prod.example.com", "namespace": "production"},
                    {"server": "https://k8s.staging.example.com", "namespace": "staging"},
                ]
            ),
        )
        assert result.passed is True
        assert "2" in result.message

    def test_pass_partial_wildcard_server_only(self):
        # server=* but namespace is scoped — not both wildcards, should pass
        result = _run_check(
            self._ID,
            _app_project(
                destinations=[{"server": "*", "namespace": "my-namespace"}]
            ),
        )
        assert result.passed is True

    def test_pass_partial_wildcard_namespace_only(self):
        # namespace=* but server is scoped
        result = _run_check(
            self._ID,
            _app_project(
                destinations=[{"server": "https://k8s.example.com", "namespace": "*"}]
            ),
        )
        assert result.passed is True

    def test_pass_empty_destinations_list(self):
        result = _run_check(self._ID, _app_project(destinations=[]))
        assert result.passed is True
        assert "0" in result.message

    def test_pass_no_destinations_key(self):
        # No destinations key — defaults to []
        result = _run_check(self._ID, _app_project())
        assert result.passed is True


# ---------------------------------------------------------------------------
# 7. argocd_project_wildcard_source
# ---------------------------------------------------------------------------


class TestArgoCDProjectWildcardSource:
    _ID = "argocd_project_wildcard_source"

    def test_skip_non_app_project(self):
        result = _run_check(self._ID, _application())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_skip_deployment(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_fail_wildcard_in_source_repos(self):
        result = _run_check(
            self._ID,
            _app_project(source_repos=["*"]),
        )
        assert result.passed is False
        assert result.details is not None
        assert "*" in result.details["sourceRepos"]
        assert "sourceRepos" in result.message

    def test_fail_wildcard_mixed_with_explicit_repos(self):
        result = _run_check(
            self._ID,
            _app_project(
                source_repos=["https://github.com/example/repo", "*"]
            ),
        )
        assert result.passed is False

    def test_pass_explicit_repos_only(self):
        result = _run_check(
            self._ID,
            _app_project(
                source_repos=[
                    "https://github.com/example/repo-a",
                    "https://github.com/example/repo-b",
                ]
            ),
        )
        assert result.passed is True
        assert "2" in result.message

    def test_pass_empty_source_repos(self):
        result = _run_check(self._ID, _app_project(source_repos=[]))
        assert result.passed is True
        assert "0" in result.message

    def test_pass_no_source_repos_key(self):
        # No sourceRepos key — defaults to []
        result = _run_check(self._ID, _app_project())
        assert result.passed is True


# ---------------------------------------------------------------------------
# 8. argocd_project_cluster_resources
# ---------------------------------------------------------------------------


class TestArgoCDProjectClusterResources:
    _ID = "argocd_project_cluster_resources"

    def test_skip_non_app_project(self):
        result = _run_check(self._ID, _application())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_skip_deployment(self):
        result = _run_check(self._ID, _deployment())
        assert result.passed is True
        assert "skipped" in result.message.lower()

    def test_fail_wildcard_group_and_kind(self):
        result = _run_check(
            self._ID,
            _app_project(
                cluster_resource_whitelist=[{"group": "*", "kind": "*"}]
            ),
        )
        assert result.passed is False
        assert result.details is not None
        assert result.details["wildcard_entries"] == 1
        assert result.details["total_whitelist_entries"] == 1
        assert "cluster-admin" in result.message.lower()

    def test_fail_mixed_entries_one_wildcard(self):
        result = _run_check(
            self._ID,
            _app_project(
                cluster_resource_whitelist=[
                    {"group": "rbac.authorization.k8s.io", "kind": "ClusterRole"},
                    {"group": "*", "kind": "*"},
                ]
            ),
        )
        assert result.passed is False
        assert result.details["wildcard_entries"] == 1
        assert result.details["total_whitelist_entries"] == 2

    def test_pass_scoped_cluster_resource_whitelist(self):
        result = _run_check(
            self._ID,
            _app_project(
                cluster_resource_whitelist=[
                    {"group": "rbac.authorization.k8s.io", "kind": "ClusterRole"},
                    {"group": "", "kind": "Namespace"},
                ]
            ),
        )
        assert result.passed is True
        assert "2" in result.message

    def test_pass_partial_wildcard_group_only(self):
        # group=* but kind is scoped — not both wildcards
        result = _run_check(
            self._ID,
            _app_project(
                cluster_resource_whitelist=[{"group": "*", "kind": "ClusterRole"}]
            ),
        )
        assert result.passed is True

    def test_pass_partial_wildcard_kind_only(self):
        # kind=* but group is scoped
        result = _run_check(
            self._ID,
            _app_project(
                cluster_resource_whitelist=[
                    {"group": "rbac.authorization.k8s.io", "kind": "*"}
                ]
            ),
        )
        assert result.passed is True

    def test_pass_empty_whitelist(self):
        result = _run_check(
            self._ID,
            _app_project(cluster_resource_whitelist=[]),
        )
        assert result.passed is True
        assert "empty" in result.message.lower()

    def test_pass_no_whitelist_key(self):
        # No clusterResourceWhitelist — defaults to []
        result = _run_check(self._ID, _app_project())
        assert result.passed is True
        assert "empty" in result.message.lower()


# ---------------------------------------------------------------------------
# Registration smoke test — all 8 Argo CD check IDs are in the registry
# ---------------------------------------------------------------------------


class TestArgoCDCheckRegistration:
    _EXPECTED_IDS = {
        "argocd_auto_sync_prune",
        "argocd_sync_retry_configured",
        "argocd_destination_not_in_cluster",
        "argocd_project_not_default",
        "argocd_source_target_revision",
        "argocd_project_wildcard_destination",
        "argocd_project_wildcard_source",
        "argocd_project_cluster_resources",
    }

    def test_all_argocd_checks_registered(self):
        registered = {fn(_deployment()).check_id for fn in get_check_fns()}
        assert self._EXPECTED_IDS.issubset(registered), (
            f"Missing Argo CD checks: {self._EXPECTED_IDS - registered}"
        )
