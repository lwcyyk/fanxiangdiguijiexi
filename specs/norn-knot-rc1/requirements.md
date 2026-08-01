# Go-Norn + Knot Resolver RC1 integration requirements

The integrated release version is `0.3.0-norn-knot-rc1`. It must preserve the
complete history and behavior of PR #1, PR #2, and PR #3 while adding no new
chain adapter or Resolver implementation.

The source commit contains merge history, release-version normalization, and
acceptance tooling. The evidence commit may contain only the three regenerated
acceptance records and generated release evidence under this directory.

The release manifest must set:

```text
production_trace_ready=true
field_package_ready=true
real_server_deployed=false
production_traffic_enabled=false
```

Passing this gate means code and isolated delivery acceptance succeeded. It
does not mean a domain-center server was contacted or production DNS traffic
was enabled.
