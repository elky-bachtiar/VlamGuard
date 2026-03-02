"""Filter manifest data for AI input. Only send structured metadata, not full YAML."""

_WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"}


def extract_metadata(manifest: dict) -> dict:
    """Extract filtered metadata from a K8s manifest for AI consumption."""
    kind = manifest.get("kind", "Unknown")
    meta = manifest.get("metadata", {})
    result: dict = {
        "kind": kind,
        "name": meta.get("name", "unknown"),
        "namespace": meta.get("namespace", "default"),
    }

    if kind not in _WORKLOAD_KINDS:
        return result

    spec = manifest.get("spec", {})
    result["replicas"] = spec.get("replicas", 1)

    pod_spec = spec.get("template", {}).get("spec", {})
    containers: list[dict] = []

    for container in pod_spec.get("containers", []) + pod_spec.get("initContainers", []):
        c_meta: dict = {
            "name": container.get("name", "unknown"),
            "image": container.get("image", "unknown"),
        }
        if "securityContext" in container:
            c_meta["securityContext"] = container["securityContext"]
        if "resources" in container:
            c_meta["resources"] = container["resources"]
        containers.append(c_meta)

    result["containers"] = containers
    return result
