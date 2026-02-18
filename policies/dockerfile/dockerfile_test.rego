# Unit tests for the Dockerfile policy, run by `conftest verify`.
#
# Each rule is tested from both sides. A policy test that only proves the rule
# fires on bad input cannot catch the far more common failure: a rule that fires
# on everything, gets in the way, and is switched off a week later.

package main

instruction(cmd, value, stage) := {
	"Cmd": cmd,
	"Value": value,
	"Flags": [],
	"JSON": false,
	"Stage": stage,
	"SubCmd": "",
}

hardened_final_stage := [
	instruction("from", ["python@sha256:0000000000000000000000000000000000000000000000000000000000000000"], 0),
	instruction("user", ["10001"], 0),
	instruction("healthcheck", ["CMD /probe"], 0),
]

# --- base image pinning ----------------------------------------------------

test_digest_pinned_base_is_accepted if {
	count(deny) == 0 with input as hardened_final_stage
}

test_explicit_tag_is_accepted if {
	count(deny) == 0 with input as [
		instruction("from", ["python:3.12-slim"], 0),
		instruction("user", ["10001"], 0),
		instruction("healthcheck", ["CMD /probe"], 0),
	]
}

test_latest_tag_is_denied if {
	messages := deny with input as [
		instruction("from", ["python:latest"], 0),
		instruction("user", ["10001"], 0),
		instruction("healthcheck", ["CMD /probe"], 0),
	]
	some message in messages
	contains(message, "not pinned")
}

test_untagged_base_is_denied if {
	messages := deny with input as [
		instruction("from", ["python"], 0),
		instruction("user", ["10001"], 0),
		instruction("healthcheck", ["CMD /probe"], 0),
	]
	some message in messages
	contains(message, "not pinned")
}

# A second FROM that refers to an earlier stage by name is not an image
# reference and must not be reported as an unpinned one.
test_stage_alias_is_not_treated_as_an_image if {
	count(deny) == 0 with input as [
		instruction("from", ["python:3.12-slim", "AS", "build"], 0),
		instruction("from", ["build"], 1),
		instruction("user", ["10001"], 1),
		instruction("healthcheck", ["CMD /probe"], 1),
	]
}

# --- user ------------------------------------------------------------------

test_missing_user_is_denied if {
	messages := deny with input as [
		instruction("from", ["python:3.12-slim"], 0),
		instruction("healthcheck", ["CMD /probe"], 0),
	]
	some message in messages
	contains(message, "runs as root")
}

test_explicit_root_user_is_denied if {
	messages := deny with input as [
		instruction("from", ["python:3.12-slim"], 0),
		instruction("user", ["root"], 0),
		instruction("healthcheck", ["CMD /probe"], 0),
	]
	some message in messages
	contains(message, "switches back to root")
}

# USER in a build stage says nothing about the stage that ships.
test_user_in_earlier_stage_does_not_satisfy_the_rule if {
	messages := deny with input as [
		instruction("from", ["python:3.12-slim", "AS", "build"], 0),
		instruction("user", ["10001"], 0),
		instruction("from", ["python:3.12-slim"], 1),
		instruction("healthcheck", ["CMD /probe"], 1),
	]
	some message in messages
	contains(message, "runs as root")
}

# --- network fetches -------------------------------------------------------

test_remote_add_is_denied if {
	messages := deny with input as array.concat(hardened_final_stage, [
		instruction("add", ["https://example.invalid/tool.tar.gz", "/opt/"], 0),
	])
	some message in messages
	contains(message, "over the network")
}

test_local_add_is_accepted if {
	count(deny) == 0 with input as array.concat(hardened_final_stage, [
		instruction("add", ["dist.tar.gz", "/opt/"], 0),
	])
}

test_curl_piped_into_shell_is_denied if {
	messages := deny with input as array.concat(hardened_final_stage, [
		instruction("run", ["curl -fsSL https://example.invalid/install | sh"], 0),
	])
	some message in messages
	contains(message, "into a shell")
}

test_curl_writing_to_a_file_is_accepted if {
	count(deny) == 0 with input as array.concat(hardened_final_stage, [
		instruction("run", ["curl -fsSL https://example.invalid/tool -o /tmp/tool && sha256sum -c tool.sha256"], 0),
	])
}

# --- credentials -----------------------------------------------------------

test_credential_in_env_is_denied if {
	messages := deny with input as array.concat(hardened_final_stage, [
		instruction("env", ["REGISTRY_TOKEN", "\"ghp-not-a-real-token\"", "="], 0),
	])
	some message in messages
	contains(message, "credential baked into the image")
}

# `ARG NPM_TOKEN=""` declares a build argument; it leaks nothing.
test_empty_credential_default_is_accepted if {
	count(deny) == 0 with input as array.concat(hardened_final_stage, [
		instruction("arg", ["REGISTRY_TOKEN=\"\""], 0),
	])
}

test_non_secret_env_is_accepted if {
	count(deny) == 0 with input as array.concat(hardened_final_stage, [
		instruction("env", ["PYTHONUNBUFFERED", "1", "="], 0),
	])
}

# --- dependency integrity --------------------------------------------------

test_pip_install_without_hashes_is_denied if {
	messages := deny with input as array.concat(hardened_final_stage, [
		instruction("run", ["pip install --no-cache-dir -r requirements.txt"], 0),
	])
	some message in messages
	contains(message, "--require-hashes")
}

test_pip_install_with_hashes_is_accepted if {
	count(deny) == 0 with input as array.concat(hardened_final_stage, [
		instruction("run", ["pip install --no-cache-dir --require-hashes --requirement requirements.txt"], 0),
	])
}

# --- advisory rules --------------------------------------------------------

test_missing_healthcheck_warns_but_does_not_block if {
	messages := warn with input as [
		instruction("from", ["python:3.12-slim"], 0),
		instruction("user", ["10001"], 0),
	]
	count(messages) == 1
	count(deny) == 0 with input as [
		instruction("from", ["python:3.12-slim"], 0),
		instruction("user", ["10001"], 0),
	]
}

test_apt_get_without_no_install_recommends_warns if {
	messages := warn with input as array.concat(hardened_final_stage, [
		instruction("run", ["apt-get update && apt-get install -y curl"], 0),
	])
	some message in messages
	contains(message, "--no-install-recommends")
}
