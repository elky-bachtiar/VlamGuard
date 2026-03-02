"""Tests for Helm template rendering."""

import pytest

from vlamguard.engine.helm import HelmRenderError, render_chart, parse_manifests


class TestParseManifests:
    def test_single_document(self):
        yaml_str = """apiVersion: v1
kind: ConfigMap
metadata:
  name: test
data:
  key: value
"""
        manifests = parse_manifests(yaml_str)
        assert len(manifests) == 1
        assert manifests[0]["kind"] == "ConfigMap"

    def test_multi_document(self):
        yaml_str = """apiVersion: v1
kind: ConfigMap
metadata:
  name: cfg
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 3
"""
        manifests = parse_manifests(yaml_str)
        assert len(manifests) == 2
        assert manifests[0]["kind"] == "ConfigMap"
        assert manifests[1]["kind"] == "Deployment"

    def test_empty_documents_filtered(self):
        yaml_str = """---
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: test
---
"""
        manifests = parse_manifests(yaml_str)
        assert len(manifests) == 1

    def test_helm_notes_filtered(self):
        yaml_str = """---
# Source: mychart/templates/NOTES.txt
Thank you for installing mychart.
---
apiVersion: v1
kind: Service
metadata:
  name: svc
"""
        manifests = parse_manifests(yaml_str)
        assert len(manifests) == 1
        assert manifests[0]["kind"] == "Service"


class TestRenderChart:
    def test_chart_not_found_raises(self):
        with pytest.raises(HelmRenderError, match="helm"):
            render_chart("/nonexistent/chart", {})
