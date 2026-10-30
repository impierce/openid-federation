#!/usr/bin/env bash
# Installs the agent skills of mattpocock/skills at a release tag, replacing the installed ones.
#
#   scripts/update-agent-skills.sh v1.3.2
#
# The skills are the set the upstream Claude Code plugin ships (its .claude-plugin/plugin.json at
# that tag), installed by the skills CLI into .agents/skills/ with a link per skill in
# .claude/skills/, and pinned in skills-lock.json. Re-installing from scratch drops skills that
# upstream removed.
set -euo pipefail

tag="${1:?usage: $0 <release tag of mattpocock/skills, e.g. v1.3.2>}"
# The skills CLI, pinned. Bump it deliberately, after its release has aged for a couple of weeks.
skills_cli="skills@1.7.2"

cd "$(git rev-parse --show-toplevel)"

names=$(curl -fsSL "https://raw.githubusercontent.com/mattpocock/skills/${tag}/.claude-plugin/plugin.json" |
  jq -r '.skills[] | split("/") | last')
if [ -z "$names" ]; then
  echo "No skills listed in the plugin manifest at ${tag}" >&2
  exit 1
fi

mapfile -t skills <<<"$names"

rm -rf .agents/skills .claude/skills skills-lock.json
npx --yes "$skills_cli" add "https://github.com/mattpocock/skills/tree/${tag}" \
  --agent universal claude-code --skill "${skills[@]}" --yes

echo "Installed $(jq '.skills | length' skills-lock.json) skills from mattpocock/skills ${tag}."
