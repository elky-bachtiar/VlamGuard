# Skill Declined: github-issue does not apply

The **github-issue** skill is not applicable here. The skill description explicitly states:

> Do NOT use for GitLab projects -- use the gitlab-issue skill instead.

And under "When NOT to use":

> GitLab projects (use `glab` instead)

Since you mentioned you are on GitLab, the `github-issue` skill (which uses `gh issue create` and `.github/ISSUE_TEMPLATE/` YAML forms) is the wrong tool. Filing your KEDA bug report on GitLab would require:

1. Using `glab issue create` instead of `gh issue create`.
2. Reading templates from `.gitlab/issue_templates/*.md` (markdown format), not `.github/ISSUE_TEMPLATE/*.yml` (YAML forms).
3. Parsing markdown headers as field separators rather than YAML field definitions.

To proceed, you would need a **gitlab-issue** skill or manual use of the `glab` CLI. If you would like, I can check whether `.gitlab/issue_templates/` contains any templates in this repository and help you file the KEDA bug report directly using `glab`.
