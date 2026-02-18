# Kubernetes workload policy.
#
# The same controls are enforced twice: here, so a bad manifest never merges,
# and by the Kyverno ClusterPolicies in policies/kyverno/, so a manifest that
# never went through CI still cannot reach the cluster. CI checks intent;
# admission checks reality.
#
# `deny` blocks. `warn` is advisory.

package main

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

workload_kinds := {"Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet"}

is_workload if input.kind in workload_kinds

is_pod if input.kind == "Pod"

pod_spec := input.spec.template.spec if is_workload

pod_spec := input.spec if is_pod

# Init and ephemeral containers run with the same privileges as the main ones,
# so a policy that only inspects `containers` leaves the obvious way around it.
all_containers contains container if {
	some container in object.get(pod_spec, "containers", [])
}

all_containers contains container if {
	some container in object.get(pod_spec, "initContainers", [])
}

name_of(container) := object.get(container, "name", "<unnamed>")

container_security(container) := object.get(container, "securityContext", {})

pod_security := object.get(pod_spec, "securityContext", {})

# A container-level setting wins over the pod-level default, so both are checked
# in that order rather than only one of them.
effective(container, field) := value if {
	value := container_security(container)[field]
}

effective(container, field) := value if {
	not field in object.keys(container_security(container))
	value := pod_security[field]
}

digest_pinned(image) if contains(image, "@sha256:")

# ---------------------------------------------------------------------------
# Image provenance
# ---------------------------------------------------------------------------

# Risk: a tag is a mutable pointer. Everything upstream - the scan, the
# signature, the SBOM - describes a digest, so deploying a tag means deploying
# something that was never actually checked.
deny contains msg if {
	some container in all_containers
	not digest_pinned(container.image)
	msg := sprintf(
		"container %s uses image '%s': deploy by @sha256 digest so the signed bytes are the running bytes",
		[name_of(container), container.image],
	)
}

# Risk: `:latest` additionally destroys the ability to say what is running or to
# roll back to what was running.
deny contains msg if {
	some container in all_containers
	endswith(container.image, ":latest")
	msg := sprintf("container %s pins the ':latest' tag", [name_of(container)])
}

# ---------------------------------------------------------------------------
# Privilege
# ---------------------------------------------------------------------------

# Risk: uid 0 in the container is uid 0 on the host under any runtime without
# user namespaces, which turns a container escape into a host compromise.
deny contains msg if {
	some container in all_containers
	effective(container, "runAsNonRoot") != true
	msg := sprintf("container %s does not set runAsNonRoot: true", [name_of(container)])
}

deny contains msg if {
	some container in all_containers
	not effective(container, "runAsNonRoot")
	msg := sprintf("container %s does not set runAsNonRoot: true", [name_of(container)])
}

# Risk: setuid binaries inside the image can otherwise regain privileges that
# the pod spec just dropped.
deny contains msg if {
	some container in all_containers
	container_security(container).allowPrivilegeEscalation != false
	msg := sprintf("container %s allows privilege escalation", [name_of(container)])
}

deny contains msg if {
	some container in all_containers
	not "allowPrivilegeEscalation" in object.keys(container_security(container))
	msg := sprintf("container %s does not set allowPrivilegeEscalation: false", [name_of(container)])
}

# Risk: a privileged container has the host's devices and capabilities. There is
# no meaningful isolation left to reason about.
deny contains msg if {
	some container in all_containers
	container_security(container).privileged == true
	msg := sprintf("container %s runs privileged", [name_of(container)])
}

# Risk: default capabilities include NET_RAW and CHOWN, which are enough to
# spoof traffic on the pod network and to tamper with mounted files. A web
# service needs none of them.
deny contains msg if {
	some container in all_containers
	dropped := object.get(container_security(container), ["capabilities", "drop"], [])
	not "ALL" in dropped
	msg := sprintf("container %s does not drop ALL capabilities", [name_of(container)])
}

# Risk: host namespaces let the pod see and signal processes, sockets and
# interfaces belonging to every other workload on the node.
deny contains msg if {
	some namespace in ["hostNetwork", "hostPID", "hostIPC"]
	object.get(pod_spec, namespace, false) == true
	msg := sprintf("pod requests %s: this removes isolation from the whole node", [namespace])
}

# Risk: a hostPath mount reads and writes the node's filesystem. Mounting the
# container runtime socket or /etc this way is a full node takeover.
deny contains msg if {
	some volume in object.get(pod_spec, "volumes", [])
	"hostPath" in object.keys(volume)
	msg := sprintf(
		"volume %s mounts hostPath '%s' from the node",
		[object.get(volume, "name", "<unnamed>"), volume.hostPath.path],
	)
}

# Risk: an automounted service-account token is a cluster credential sitting in
# every pod, usable by anything that achieves code execution there.
deny contains msg if {
	object.get(pod_spec, "automountServiceAccountToken", true) == true
	msg := "pod automounts a service-account token that the workload does not use"
}

# ---------------------------------------------------------------------------
# Resource limits
# ---------------------------------------------------------------------------

# Risk: without limits, one workload's memory leak or CPU spin evicts or starves
# its neighbours. Availability is a security property when the outage is caused
# on purpose.
deny contains msg if {
	some container in all_containers
	some kind in ["limits", "requests"]
	some resource in ["cpu", "memory"]
	not object.get(container, ["resources", kind, resource], false)
	msg := sprintf("container %s sets no %s.%s", [name_of(container), kind, resource])
}

# ---------------------------------------------------------------------------
# Hardening
# ---------------------------------------------------------------------------

# Risk: a writable root filesystem lets an attacker drop tooling, patch the
# application on disk and survive a restart.
deny contains msg if {
	some container in all_containers
	container_security(container).readOnlyRootFilesystem != true
	msg := sprintf("container %s does not set readOnlyRootFilesystem: true", [name_of(container)])
}

deny contains msg if {
	some container in all_containers
	not "readOnlyRootFilesystem" in object.keys(container_security(container))
	msg := sprintf("container %s does not set readOnlyRootFilesystem: true", [name_of(container)])
}

# Risk: without a seccomp profile the container may issue every syscall the
# kernel offers, including the ones behind most escape primitives.
deny contains msg if {
	some container in all_containers
	profile := object.get(pod_security, ["seccompProfile", "type"], "")
	container_profile := object.get(container_security(container), ["seccompProfile", "type"], profile)
	not container_profile in {"RuntimeDefault", "Localhost"}
	msg := sprintf("container %s runs with an unconfined seccomp profile", [name_of(container)])
}

# Risk (advisory): with no readiness probe the service receives traffic before
# it can answer, and with no liveness probe a wedged replica is never replaced.
warn contains msg if {
	some container in all_containers
	some probe in ["livenessProbe", "readinessProbe"]
	not probe in object.keys(container)
	msg := sprintf("container %s declares no %s", [name_of(container), probe])
}
