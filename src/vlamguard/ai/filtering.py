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

    if kind == "Service":
        spec = manifest.get("spec", {})
        result["service_type"] = spec.get("type", "ClusterIP")
        ports = spec.get("ports", [])
        if ports:
            result["ports"] = [
                {"port": p.get("port"), "targetPort": p.get("targetPort"), "protocol": p.get("protocol", "TCP")}
                for p in ports
            ]
        return result

    if kind not in _WORKLOAD_KINDS:
        return result

    spec = manifest.get("spec", {})
    result["replicas"] = spec.get("replicas", 1)

    pod_spec = spec.get("template", {}).get("spec", {})

    # Security-relevant pod-level fields
    result["automountServiceAccountToken"] = pod_spec.get("automountServiceAccountToken")
    for ns_field in ("hostNetwork", "hostPID", "hostIPC"):
        val = pod_spec.get(ns_field)
        if val is True:
            result[ns_field] = True

    # Volume metadata (names + types only, not paths for security)
    volumes = pod_spec.get("volumes", [])
    if volumes:
        vol_meta = []
        for v in volumes:
            entry: dict = {"name": v.get("name", "unknown")}
            if "hostPath" in v:
                entry["type"] = "hostPath"
            elif "emptyDir" in v:
                entry["type"] = "emptyDir"
            elif "configMap" in v:
                entry["type"] = "configMap"
            elif "secret" in v:
                entry["type"] = "secret"
            elif "persistentVolumeClaim" in v:
                entry["type"] = "pvc"
            vol_meta.append(entry)
        result["volumes"] = vol_meta

    containers: list[dict] = []

    for container in pod_spec.get("containers", []) + pod_spec.get("initContainers", []):
        c_meta: dict = {
            "name": container.get("name", "unknown"),
            "image": container.get("image", "unknown"),
        }
        if "securityContext" in container:
            c_meta["securityContext"] = container["securityContext"]
            # Extract capabilities for AI analysis
            caps = container["securityContext"].get("capabilities", {})
            if caps:
                c_meta["capabilities"] = caps
        if "resources" in container:
            c_meta["resources"] = container["resources"]
        containers.append(c_meta)

    result["containers"] = containers
    return result
