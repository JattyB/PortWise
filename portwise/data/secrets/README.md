PortWise secret rules
=====================

This directory ships a compact Gitleaks-style rule set used by the native JS and
HTML secret analyzer.

Format:
- TOML `[[rules]]` tables with `id`, `description`, `regex`, `secretGroup`,
  `entropy`, `keywords`, and optional `path`.

Source inspiration:
- https://github.com/gitleaks/gitleaks

The shipped rules are tailored for high precision on web content. The analyzer
adds entropy, context, and placeholder suppression on top of the raw rules.
