# Dockerfile policy.
#
# These rules exist because the image is the last place where a mistake is still
# cheap to fix. Each rule names the risk it mitigates rather than restating the
# pattern it matches.
#
# `deny` stops the build. `warn` is printed and does not.
#
# Input shape comes from conftest's dockerfile parser: a flat array of
# instructions, each {Cmd, Value, Flags, Stage, JSON}.

package main

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

stage_numbers contains n if {
	some instruction in input
	n := instruction.Stage
}

# Only the last stage becomes the shipped image; earlier stages are scaffolding
# and holding them to the same rules produces noise nobody reads.
final_stage := max(stage_numbers)

instructions(name) := [instruction |
	some instruction in input
	instruction.Cmd == name
]

final_instructions(name) := [instruction |
	some instruction in input
	instruction.Cmd == name
	instruction.Stage == final_stage
]

stage_aliases contains name if {
	some instruction in instructions("from")
	count(instruction.Value) == 3
	lower(instruction.Value[1]) == "as"
	name := lower(instruction.Value[2])
}

pinned(image) if {
	contains(image, "@sha256:")
}

pinned(image) if {
	not contains(image, "@")
	parts := split(image, ":")
	count(parts) > 1
	tag := parts[count(parts) - 1]
	tag != "latest"
	not contains(tag, "/")
}

root_user(value) if value == "root"

root_user(value) if value == "0"

root_user(value) if startswith(value, "root:")

root_user(value) if startswith(value, "0:")

# A declared-but-empty default is how a Dockerfile documents a build argument it
# expects to be passed in; it is not a leaked credential.
empty_literal(value) if value == ""

empty_literal(value) if value == `""`

empty_literal(value) if value == "''"

secret_name(name) if {
	patterns := ["password", "passwd", "secret", "token", "api_key", "apikey", "access_key", "private_key"]
	some pattern in patterns
	contains(lower(name), pattern)
}

# The parser reports assignments in two shapes: a single `KEY=value` token for
# the short ARG form, and a flat [key, value, "=", ...] list for everything else.
kv_pairs(instruction) := pairs if {
	count(instruction.Value) == 1
	contains(instruction.Value[0], "=")
	parts := split(instruction.Value[0], "=")
	pairs := {{
		"name": parts[0],
		"value": concat("=", array.slice(parts, 1, count(parts))),
	}}
}

kv_pairs(instruction) := pairs if {
	count(instruction.Value) > 1
	pairs := {{"name": name, "value": value} |
		some index
		name := instruction.Value[index]
		value := instruction.Value[index + 1]
		instruction.Value[index + 2] == "="
	}
}

# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

# Risk: a mutable tag lets someone re-point `:latest` (or any tag) at different
# content after the image was reviewed and scanned. The scan result then
# describes bytes that are no longer what gets pulled.
deny contains msg if {
	some instruction in instructions("from")
	image := instruction.Value[0]
	image != "scratch"
	alias := lower(image)
	not alias in stage_aliases
	not pinned(image)
	msg := sprintf(
		"base image '%s' is not pinned: use an explicit tag, preferably a @sha256 digest",
		[image],
	)
}

# Risk: a process running as uid 0 inside the container starts every container
# escape from the strongest possible position, and turns any file-write bug into
# a host-visible one when the runtime is not fully isolated.
deny contains msg if {
	count(final_instructions("user")) == 0
	msg := "final stage runs as root: add a USER instruction with a non-root uid"
}

deny contains msg if {
	users := final_instructions("user")
	count(users) > 0
	last := users[count(users) - 1]
	root_user(last.Value[0])
	msg := sprintf("final stage switches back to root with USER %s", [last.Value[0]])
}

# Risk: ADD with a URL downloads content at build time with no checksum and no
# signature, so the image depends on whatever that host served that day.
deny contains msg if {
	some instruction in instructions("add")
	some value in instruction.Value
	contains(value, "://")
	msg := sprintf(
		"ADD fetches '%s' over the network: download in a RUN step and verify a checksum",
		[value],
	)
}

# Risk: piping a downloaded script straight into a shell executes unreviewed,
# unverified code with build privileges - the exact shape of the attacks that
# supply-chain controls exist to stop.
deny contains msg if {
	some instruction in instructions("run")
	command := instruction.Value[0]
	regex.match(`(?i)(curl|wget)[^|]*\|\s*(sudo\s+)?(ba)?sh`, command)
	msg := "RUN pipes a downloaded script into a shell: fetch, verify, then execute"
}

# Risk: a credential in ARG or ENV is baked into the image layers and readable
# by anyone who can pull it, no matter how the build was invoked.
deny contains msg if {
	some name in {"arg", "env"}
	some instruction in instructions(name)
	some pair in kv_pairs(instruction)
	secret_name(pair.name)
	not empty_literal(pair.value)
	msg := sprintf(
		"%s %s looks like a credential baked into the image: use a build secret mount",
		[upper(name), pair.name],
	)
}

# Risk: installing from a requirements file without --require-hashes means the
# index decides what ends up in the image. That is precisely how a compromised
# or typosquatted package reaches production.
deny contains msg if {
	some instruction in instructions("run")
	command := instruction.Value[0]
	regex.match(`pip3?\s+install[^&|]*(-r|--requirement)\s`, command)
	not contains(command, "--require-hashes")
	msg := "pip install from a requirements file must pass --require-hashes"
}

# Risk (advisory): without a HEALTHCHECK the orchestrator cannot tell a wedged
# process from a healthy one, so a container that stopped serving stays in the
# rotation. Availability rather than confidentiality, hence warn.
warn contains msg if {
	count(final_instructions("healthcheck")) == 0
	msg := "final stage declares no HEALTHCHECK"
}

# Risk (advisory): recommended packages pull in tooling nobody audited and each
# one adds CVEs that the scan will later demand attention for.
warn contains msg if {
	some instruction in instructions("run")
	command := instruction.Value[0]
	contains(command, "apt-get install")
	not contains(command, "--no-install-recommends")
	msg := "apt-get install without --no-install-recommends enlarges the attack surface"
}
