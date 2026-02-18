# Unit tests for the Kubernetes policy, run by `conftest verify`.
#
# The fixture below is a deliberately minimal compliant Deployment. Every test
# starts from it and breaks exactly one thing, so a failing test names the rule
# that changed rather than pointing at a wall of unrelated denials.

package main

digest := "@sha256:0000000000000000000000000000000000000000000000000000000000000000"

compliant_container := {
	"name": "app",
	"image": sprintf("ghcr.io/lpogosu/release-metadata%s", [digest]),
	"securityContext": {
		"allowPrivilegeEscalation": false,
		"privileged": false,
		"readOnlyRootFilesystem": true,
		"capabilities": {"drop": ["ALL"]},
	},
	"resources": {
		"requests": {"cpu": "25m", "memory": "64Mi"},
		"limits": {"cpu": "250m", "memory": "128Mi"},
	},
	"livenessProbe": {"httpGet": {"path": "/healthz", "port": 8000}},
	"readinessProbe": {"httpGet": {"path": "/healthz", "port": 8000}},
}

deployment(pod) := {
	"apiVersion": "apps/v1",
	"kind": "Deployment",
	"metadata": {"name": "release-metadata"},
	"spec": {"template": {"spec": pod}},
}

compliant_pod := {
	"automountServiceAccountToken": false,
	"securityContext": {
		"runAsNonRoot": true,
		"runAsUser": 10001,
		"seccompProfile": {"type": "RuntimeDefault"},
	},
	"containers": [compliant_container],
}

compliant := deployment(compliant_pod)

# Rebuild the fixture with one container field replaced.
with_container_field(field, value) := deployment(object.union(
	compliant_pod,
	{"containers": [object.union(compliant_container, {field: value})]},
))

with_pod_field(field, value) := deployment(object.union(compliant_pod, {field: value}))

# object.union merges nested objects rather than replacing them, so a test that
# needs a field to be *absent* has to remove it before adding the replacement.
replacing_pod_field(field, value) := deployment(object.union(
	object.remove(compliant_pod, {field}),
	{field: value},
))

replacing_container_field(field, value) := deployment(object.union(
	compliant_pod,
	{"containers": [object.union(object.remove(compliant_container, {field}), {field: value})]},
))

# --- baseline --------------------------------------------------------------

test_compliant_deployment_passes if {
	count(deny) == 0 with input as compliant
	count(warn) == 0 with input as compliant
}

test_non_workload_documents_are_ignored if {
	count(deny) == 0 with input as {
		"apiVersion": "v1",
		"kind": "Service",
		"metadata": {"name": "release-metadata"},
		"spec": {"ports": [{"port": 80}]},
	}
}

# --- image provenance ------------------------------------------------------

test_tag_instead_of_digest_is_denied if {
	messages := deny with input as with_container_field("image", "ghcr.io/lpogosu/release-metadata:1.4.0")
	some message in messages
	contains(message, "@sha256 digest")
}

test_latest_tag_is_denied_explicitly if {
	messages := deny with input as with_container_field("image", "release-metadata:latest")
	some message in messages
	contains(message, "':latest'")
}

# --- privilege -------------------------------------------------------------

test_pod_level_run_as_non_root_covers_containers if {
	count(deny) == 0 with input as compliant
}

test_missing_run_as_non_root_is_denied if {
	document := replacing_pod_field("securityContext", {"seccompProfile": {"type": "RuntimeDefault"}})
	messages := deny with input as document
	some message in messages
	contains(message, "runAsNonRoot")
}

# A container-level override must beat the pod-level default, otherwise the
# policy passes a workload that actually runs as root.
test_container_override_of_run_as_non_root_is_denied if {
	container := object.union(compliant_container, {"securityContext": object.union(
		compliant_container.securityContext,
		{"runAsNonRoot": false},
	)})
	messages := deny with input as deployment(object.union(compliant_pod, {"containers": [container]}))
	some message in messages
	contains(message, "runAsNonRoot")
}

test_privilege_escalation_is_denied if {
	container := object.union(compliant_container, {"securityContext": object.union(
		compliant_container.securityContext,
		{"allowPrivilegeEscalation": true},
	)})
	messages := deny with input as deployment(object.union(compliant_pod, {"containers": [container]}))
	some message in messages
	contains(message, "allows privilege escalation")
}

test_privileged_container_is_denied if {
	container := object.union(compliant_container, {"securityContext": object.union(
		compliant_container.securityContext,
		{"privileged": true},
	)})
	messages := deny with input as deployment(object.union(compliant_pod, {"containers": [container]}))
	some message in messages
	contains(message, "runs privileged")
}

test_capabilities_not_dropped_is_denied if {
	container := object.union(compliant_container, {"securityContext": object.union(
		compliant_container.securityContext,
		{"capabilities": {"drop": ["NET_RAW"]}},
	)})
	messages := deny with input as deployment(object.union(compliant_pod, {"containers": [container]}))
	some message in messages
	contains(message, "drop ALL capabilities")
}

# An init container has the same access as any other; the policy must see it.
test_init_containers_are_checked_too if {
	pod := object.union(compliant_pod, {"initContainers": [{
		"name": "migrate",
		"image": "busybox:latest",
	}]})
	messages := deny with input as deployment(pod)
	some message in messages
	contains(message, "container migrate")
}

test_host_namespaces_are_denied if {
	messages := deny with input as with_pod_field("hostPID", true)
	some message in messages
	contains(message, "hostPID")
}

test_host_path_volume_is_denied if {
	pod := object.union(compliant_pod, {"volumes": [{
		"name": "docker-socket",
		"hostPath": {"path": "/var/run/docker.sock"},
	}]})
	messages := deny with input as deployment(pod)
	some message in messages
	contains(message, "/var/run/docker.sock")
}

test_emptydir_volume_is_accepted if {
	pod := object.union(compliant_pod, {"volumes": [{
		"name": "tmp",
		"emptyDir": {"sizeLimit": "16Mi"},
	}]})
	count(deny) == 0 with input as deployment(pod)
}

test_automounted_token_is_denied if {
	messages := deny with input as with_pod_field("automountServiceAccountToken", true)
	some message in messages
	contains(message, "service-account token")
}

# Omitting the field is the dangerous case: Kubernetes defaults it to true.
test_omitted_automount_field_is_denied if {
	pod := object.remove(compliant_pod, {"automountServiceAccountToken"})
	messages := deny with input as deployment(pod)
	some message in messages
	contains(message, "service-account token")
}

# --- resources -------------------------------------------------------------

test_missing_memory_limit_is_denied if {
	document := replacing_container_field("resources", {
		"requests": {"cpu": "25m", "memory": "64Mi"},
		"limits": {"cpu": "250m"},
	})
	messages := deny with input as document
	some message in messages
	contains(message, "limits.memory")
}

test_missing_resources_block_is_denied_four_times if {
	container := object.remove(compliant_container, {"resources"})
	messages := deny with input as deployment(object.union(compliant_pod, {"containers": [container]}))
	count([m | some m in messages; contains(m, "sets no")]) == 4
}

# --- hardening -------------------------------------------------------------

test_writable_root_filesystem_is_denied if {
	container := object.union(compliant_container, {"securityContext": object.union(
		compliant_container.securityContext,
		{"readOnlyRootFilesystem": false},
	)})
	messages := deny with input as deployment(object.union(compliant_pod, {"containers": [container]}))
	some message in messages
	contains(message, "readOnlyRootFilesystem")
}

test_unconfined_seccomp_is_denied if {
	document := replacing_pod_field("securityContext", {"runAsNonRoot": true})
	messages := deny with input as document
	some message in messages
	contains(message, "seccomp")
}

test_missing_probes_warn_but_do_not_block if {
	container := object.remove(compliant_container, {"livenessProbe", "readinessProbe"})
	pod := object.union(compliant_pod, {"containers": [container]})
	count(warn) == 2 with input as deployment(pod)
	count(deny) == 0 with input as deployment(pod)
}
