# Customer Forwarder Logstash Design

## Purpose

Design a customer-located Logstash service for OpenSearch SIEM.

The service runs inside customer infrastructure and is responsible for:

- collecting first-stage customer logs
- parsing and normalizing supported sources
- preserving raw event content
- buffering locally when the central SIEM is unavailable
- forwarding normalized JSON to the central `ingest-edge` endpoint

The first supported source families are Windows Active Directory, Windows
Sysmon, and generic syslog.

## Decisions

- The customer service forwards to central `ingest-edge` over HTTPS.
- The customer service does not write directly to OpenSearch.
- The service is delivered as a static reusable Docker Compose package.
- The package lives in a new top-level `customer-forwarder/` folder so it can be
  moved to a separate repository later.
- Customer-specific values are local `.env` and YAML config, not generated from
  central GitOps in version one.
- A central source catalog in the main repository is the authority for allowed
  `source_id` values.
- Customer forwarder config and central GitOps source records must use the same
  catalog IDs exactly.
- Logstash persistent queues are the only version-one outage buffer.
- Raw Windows Event XML parsing is out of scope for version one. Windows inputs
  expect structured JSON from a Windows shipper such as Winlogbeat or a
  compatible agent.

## Source Catalog Contract

Add one canonical catalog in the main repository:

```text
source-catalog/sources.yml
```

Initial catalog:

```yaml
sources:
  - id: windows-ad
    dataset: windows-ad
    parser: windows-ad-json
    input: winlogbeat-json
    description: Windows Active Directory security/domain controller events

  - id: windows-sysmon
    dataset: windows-sysmon
    parser: windows-sysmon-json
    input: winlogbeat-json
    description: Windows Sysmon process, network, file, registry, and driver events

  - id: generic-syslog
    dataset: generic-syslog
    parser: generic-syslog
    input: syslog
    description: Generic RFC3164/RFC5424 syslog from network, Linux, and appliances
```

Required invariant:

```text
catalog id == customer forwarder source key
catalog id == emitted siem.source_id
catalog id == central GitOps source id
catalog dataset == central OpenSearch dataset
catalog parser == central GitOps parser
```

The customer forwarder emits `siem.source_id`. The central ingest path still
assigns trusted `customer.slug` from the authenticated credential and must not
trust any customer identity supplied in the event body.

Central GitOps validation rejects any customer source whose `id`, `dataset`, or
`parser` does not match a catalog entry.

The customer forwarder package ships a copied catalog snapshot at:

```text
customer-forwarder/config/source-catalog.yml
```

While the package remains in this repository, tests verify that
`customer-forwarder/config/source-catalog.yml` matches
`source-catalog/sources.yml`.

## Customer-Side Service Layout

Add a new top-level folder:

```text
customer-forwarder/
  README.md
  docker-compose.yml
  .env.example
  requirements.txt
  config/
    forwarder.yml
    source-catalog.yml
    logstash.yml
    pipelines.yml
  pipeline/
    00-inputs.conf
    20-parse-windows-ad.conf
    21-parse-windows-sysmon.conf
    30-parse-generic-syslog.conf
    80-normalize-common.conf
    90-output-ingest-edge.conf
  scripts/
    validate-config.py
    test-logstash-config.sh
  test/
    fixtures/
      windows-ad.json
      windows-sysmon.json
      generic-syslog.log
    expected/
      windows-ad.json
      windows-sysmon.json
      generic-syslog.json
```

Runtime flow:

```text
customer logs
  -> customer-forwarder Logstash inputs
  -> source parser pipeline
  -> common normalization
  -> Logstash persistent queue
  -> HTTPS POST to central ingest-edge
  -> central Logstash routing
  -> OpenSearch data streams
```

Customer-specific local config lives in:

```text
customer-forwarder/config/forwarder.yml
```

Example:

```yaml
forwarder_name: acme-dc-relay-01
sources:
  windows-ad:
    enabled: true
  windows-sysmon:
    enabled: true
  generic-syslog:
    enabled: true
```

`forwarder_name` is an operator label only. It is not an authorization boundary.
The central SIEM derives customer identity from the credential used at
`ingest-edge`.

## Parser Behavior

Every forwarded event should include:

```text
@timestamp
event.original
event.dataset
event.kind
event.category
event.type
siem.source_id
observer.type
tags
```

The forwarder should preserve the original input in `event.original` whenever
the input provides a raw event body or message.

### Windows Active Directory

`windows-ad` expects structured Windows event JSON from a Windows shipper.

Normalize these fields when present:

```text
host.name
winlog.channel
winlog.event_id
winlog.provider_name
event.code
event.action
event.outcome
user.name
user.domain
source.ip
```

Initial event coverage focuses on:

```text
logon and logoff
failed logon
account creation, deletion, and modification
group membership changes
Kerberos and NTLM authentication
privilege use
policy and audit changes
```

### Windows Sysmon

`windows-sysmon` expects structured Sysmon JSON from a Windows shipper.

Normalize these fields when present:

```text
host.name
winlog.event_id
event.code
event.action
process.name
process.executable
process.command_line
process.pid
process.parent.*
file.path
file.hash.*
registry.*
source.ip
destination.ip
destination.port
```

Initial event coverage focuses on:

```text
process creation
network connections
file creation
registry changes
driver and image loads
DNS queries
process access
named pipe events
```

### Generic Syslog

`generic-syslog` accepts RFC3164 or RFC5424 style syslog from network devices,
Linux hosts, and appliances.

Normalize these fields when present:

```text
host.hostname
log.syslog.*
event.original
message
source.ip
```

### Parser Failures

Parser failures must not drop events by default. They should:

- preserve `event.original`
- keep the configured `siem.source_id`
- add `_parser_failure`
- add `_source_catalog_validated` when the source ID passed validation
- forward the event if required routing fields are present

Missing or unknown `siem.source_id` is a configuration error and should fail
validation before Logstash starts.

## Buffering And Failure Behavior

The customer Logstash service uses persistent queues:

```yaml
queue.type: persisted
path.queue: /usr/share/logstash/data/queue
queue.max_bytes: 8gb
dead_letter_queue.enable: true
dead_letter_queue.max_bytes: 512mb
```

`queue.max_bytes` and `dead_letter_queue.max_bytes` are configurable through
local settings, but the queue path must live under the mounted data path.

Docker Compose mounts durable state:

```text
./data/logstash:/usr/share/logstash/data
```

Failure behavior:

```text
central ingest-edge unavailable -> Logstash output retries and persistent queue grows
central returns 401/403 -> configuration/auth error requiring operator action
central returns 429/5xx -> retry/backoff and queue growth
parser failure -> raw event preserved, failure tag added, event forwarded if routing is valid
queue full -> Logstash backpressure; operator increases disk/queue or reduces input
DLQ grows -> operator investigates parser, output, or mapping failures
```

Disk sizing guidance:

```text
queue.max_bytes >= expected outage hours * average ingest GB/hour * safety factor
```

Version one does not add a secondary raw-file archive. Retention, replay, and
cleanup stay inside Logstash persistent queue and DLQ mechanics.

## Security And Configuration

Required environment variables:

```text
CENTRAL_INGEST_URL
CUSTOMER_FORWARDER_USERNAME
CUSTOMER_FORWARDER_PASSWORD
CENTRAL_CA_CERT
```

The output pipeline sends JSON to `CENTRAL_INGEST_URL` using HTTPS with CA
verification. The username and password are the customer credential ID and
secret expected by central `ingest-edge`.

The package must not log passwords, secret values, or full authorization
headers.

The customer-local config must not decide central stream names. It only selects
catalog source IDs. Central Logstash derives target streams from trusted
central GitOps routing.

## Validation And Tests

Central repository validation covers:

```text
source-catalog/sources.yml schema validity
unique source IDs
unique datasets
supported parser names
central GitOps source IDs existing in the catalog
central GitOps source datasets matching the catalog
central GitOps parser values matching the catalog
rendered routing preserving catalog id/dataset/parser
customer-forwarder catalog copy matching the central catalog while in-repo
```

Customer forwarder validation covers:

```text
customer-forwarder/config/source-catalog.yml schema validity
customer-forwarder/config/forwarder.yml source IDs existing in the catalog
enabled sources having Logstash input and parser support
required environment variables being present
persistent queue path living under the mounted data path
```

Test coverage:

```text
unit tests for catalog and forwarder config validation
Logstash config test with Docker when available
fixture parser tests for windows-ad
fixture parser tests for windows-sysmon
fixture parser tests for generic-syslog
negative test for unknown source_id
negative test for missing required environment variables
central GitOps validation test rejecting source IDs outside the catalog
```

Add a focused validation entrypoint:

```bash
bash scripts/test-customer-forwarder.sh
```

The existing repository validation command list should include that script.

## Repo Boundary And Migration Path

`customer-forwarder/` should be treated as a future standalone project. Keep its
runtime config, tests, validation scripts, and dependency list local to that
folder where practical.

The only intentional version-one coupling to the main repo is the source catalog
contract:

```text
source-catalog/sources.yml
customer-forwarder/config/source-catalog.yml
```

After the folder is split into a separate repository, the forwarder can consume
the catalog through one of these mechanisms:

```text
copied release artifact
Git submodule or subtree
published package
downloaded versioned catalog file
```

Version one does not implement remote catalog download. A static copied catalog
plus validation is enough.

## Out Of Scope

- Direct writes from customer infrastructure to OpenSearch.
- Generated per-customer forwarder bundles.
- Remote catalog download.
- Raw Windows Event XML parsing.
- A secondary raw-file archive outside Logstash persistent queue and DLQ.
- Customer-side stream naming decisions.
- Full ECS coverage for every Windows AD, Sysmon, or syslog field.

## Success Criteria

- The main repo has a controlled source catalog with `windows-ad`,
  `windows-sysmon`, and `generic-syslog`.
- Central GitOps rejects source records that do not match the catalog.
- The customer forwarder package starts from static reusable files.
- The customer forwarder rejects local config that references an unknown source
  ID.
- Each supported source emits normalized JSON with `siem.source_id` matching the
  catalog exactly.
- Central `ingest-edge` remains the only customer-facing central ingest target.
- Customer-side Logstash buffers central outages with a durable persistent
  queue.
- Parser failures preserve raw event content and produce visible failure tags.
- The folder can be split into a separate repository without moving unrelated
  central SIEM runtime code.
