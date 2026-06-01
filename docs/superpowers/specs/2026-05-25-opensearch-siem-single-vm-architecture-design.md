# OpenSearch SIEM Single-VM Architecture Design

## Purpose

Design a new version-one architecture for a multi-customer OpenSearch SIEM running on one virtual server in Docker.

The architecture optimizes for:

- one central SIEM VM
- initial capacity of 16 CPU, 32 GB RAM, and 500 GB HDD
- disk expansion as ingest and retention grow
- sustained ingest up to 10 GB/day
- multiple customers with clear separation
- customer-local Logstash forwarding only in version one
- internal SOC/admin access to OpenSearch Dashboards only
- GitOps-managed configuration
- simple first-version operations with a clear scale path

## Decisions

- Central SIEM runs on one Docker host.
- Version one uses one properly sized OpenSearch node, not three OpenSearch containers on the same VM.
- Customer logs enter through customer-local Logstash forwarders only.
- Version one has no direct customer ingest into the central SIEM.
- Central ingestion uses Logstash with persistent queues.
- No Redpanda, Kafka, or external broker is included in version one.
- Customer identity is mapped from one central-ingest credential per customer.
- IP allowlisting is an additional security control for customer forwarders.
- OpenSearch storage uses readable customer slugs in data stream names.
- OpenSearch Dashboards is internal-only for SOC/admin users.
- The project stays SIEM-only in version one; no SOAR/case-management services are included.
- Git is the source of truth for customers, sources, retention, routing, roles, and rendered runtime artifacts.
- External S3-compatible backup storage is designed for, but optional in version one.

## Target Services

The central VM runs these Docker services:

- `opensearch`: single production data/search node.
- `opensearch-dashboards`: internal SOC/admin UI.
- `central-logstash`: authenticated customer-forwarder ingest, queueing, routing, enrichment, normalization, and OpenSearch output.
- `gitops-renderer`: validation/rendering job that converts desired state into generated runtime artifacts.
- `opensearch-gitops-reconciler`: dry-run/apply job for OpenSearch templates, ISM policies, roles, role mappings, and other managed objects.
- `ingest-edge`: optional reverse proxy or firewall-facing listener for TLS termination, IP allowlist enforcement, and forwarding to central Logstash.
- `backup-job`: optional snapshot and repository backup job when external object storage is configured.

Customer networks run one or more local Logstash forwarders. Those forwarders collect local logs and forward outbound to the central SIEM.

OpenSearch is deliberately a single node in version one. Multiple OpenSearch containers on the same VM do not provide real high availability because they share the same VM, disk, CPU, RAM, and failure domain. The first architecture spends resources on heap, filesystem cache, persistent queues, shard control, and retention instead.

## High-Level Flow

```text
Customer devices
  -> customer-local Logstash forwarder
  -> local persistent queue
  -> outbound TLS connection to central SIEM
  -> customer credential and source IP allowlist check
  -> central Logstash persistent queue
  -> customer/source validation and enrichment
  -> ECS-style normalization where practical
  -> OpenSearch customer data streams
  -> internal OpenSearch Dashboards and alerting
```

Customer devices do not send syslog, Beats, or webhook traffic directly to the central SIEM in version one.

## Ingestion Architecture

Each customer-local Logstash forwarder is responsible for:

- accepting syslog, agent, application, and local integration logs inside the customer network
- buffering locally with a bounded persistent queue
- tagging events with source metadata from customer-approved forwarder config
- forwarding outbound to the central SIEM over TLS
- authenticating with the customer credential
- reporting operational health through logs and metrics

Central Logstash is responsible for:

- accepting only authenticated customer-forwarder traffic
- enforcing customer credential mapping
- relying on IP allowlists as an additional perimeter control
- using persistent queues to absorb short OpenSearch outages or slowdowns
- deriving trusted customer identity from the credential mapping
- validating source and dataset metadata against GitOps desired state
- routing unknown or unauthorized source traffic to quarantine or rejection policy
- normalizing common fields where practical
- writing to approved customer-scoped OpenSearch data streams

Central Logstash must not trust event-supplied `customer.slug`, `customer.id`, stream names, retention names, or authorization fields.

## Tenant Separation

Tenant separation is enforced across configuration, ingest, storage, access, and operations.

Default stream patterns:

```text
logs-<customer_slug>-<dataset>
logs-<customer_slug>-<dataset>-quarantine
alerts-<customer_slug>
metrics-platform-*
audit-platform-*
```

Examples:

```text
logs-acme-firewall
logs-acme-windows
logs-contoso-linux
logs-contoso-quarantine
alerts-acme
```

Customer slugs must be:

- readable
- lowercase
- DNS-safe
- immutable once used in a stream name
- unique across the deployment
- validated by GitOps checks before rendered artifacts are produced

Separation controls:

- GitOps registry maps each customer credential to exactly one customer slug.
- IP allowlists constrain where each customer forwarder may connect from.
- Central Logstash assigns customer metadata from trusted customer mapping, not event payloads.
- Source IDs and datasets must be declared for the mapped customer.
- Generated routing config prevents customers from choosing arbitrary destination streams.
- OpenSearch roles restrict service accounts to generated stream patterns.
- Internal SOC/admin users may have cross-customer search rights.
- Customers have no Dashboards access in version one.

OpenSearch roles should still be generated per customer and per service boundary so future customer-facing access can be added without changing stream naming.

## Data Model

Every accepted event should receive these trusted fields:

- `customer.slug`
- `source.id`
- `event.dataset`
- `data_stream.type`
- `data_stream.dataset`
- `data_stream.namespace`
- `event.original` or equivalent raw event preservation

Where practical, normalization should map:

- timestamps
- host names and IDs
- user names and IDs
- source and destination IPs
- source and destination ports
- event action and outcome
- process fields
- file fields
- network protocol fields

The system should preserve raw content even when full normalization is not possible. Strict rejection is reserved for security-sensitive metadata and authorization problems, not for every source-specific parsing mismatch.

## Storage And Retention

Initial capacity target:

```text
16 CPU
32 GB RAM
500 GB HDD
up to 10 GB/day sustained ingest
```

Version-one retention target:

```text
default searchable retention: 7 days
critical selected datasets: up to 30 days
quarantine: 3-7 days
replicas: 0 on the single-node deployment
```

OpenSearch should use data streams for append-only logs. Index templates and ISM policies control rollover and deletion.

Initial policy classes:

```text
critical: rollover by size or age, delete after 30 days
standard: rollover by size or age, delete after 7 days
noisy: rollover by size or age, delete after 3 days
quarantine: delete after 3-7 days
platform audit: retain longer when disk allows
```

Shard rules:

- Do not create one index per device.
- Do not create one stream per source host.
- Use customer/dataset streams.
- Keep primary shard counts low.
- Use no replicas in the single-node version-one deployment.
- Roll over by both size and age to prevent oversized shards and stale hot indices.

Disk pressure is a first-class operational condition. If disk pressure rises, noisy datasets lose retention before critical datasets.

## GitOps Control Plane

Git is the source of truth for version one.

Git owns:

- customers
- customer credential metadata and secret references
- customer IP allowlists
- sources
- datasets
- parser assignment
- retention policies
- stream naming contracts
- Logstash routing config
- Logstash authorization config
- OpenSearch templates
- OpenSearch ISM policies
- OpenSearch roles and role mappings
- alert definitions
- backup configuration

Recommended layout:

```text
gitops/
  desired/
    global/
      retention-policies.yml
      service-accounts.yml
      backup.yml
    customers/
      acme/
        customer.yml
        credentials.yml
        allowlist.yml
        sources/
          firewall.yml
          windows.yml
  rendered/
    logstash/
      customer-auth.yml
      source-routing.yml
      pipelines/
    opensearch/
      index-templates/
      ism-policies/
      roles/
      role-mappings/
```

Rules:

- `gitops/desired/**` is hand-authored.
- `gitops/rendered/**` is generated and committed.
- CI and local validation fail if rendered artifacts are stale.
- Runtime services mount rendered artifacts, not desired files.
- Plaintext customer secrets are not committed.
- Secret values live outside Git or are encrypted with a repo-safe mechanism such as SOPS/age.
- GitOps validation must reject duplicate slugs, unsafe stream names, unknown retention policies, unknown source references, invalid allowlists, and disabled customers with enabled sources.

## Security Model

Version-one security is layered:

```text
customer-local relay
  -> outbound TLS to central SIEM
  -> one credential per customer
  -> source IP/CIDR allowlist
  -> central routing derived from GitOps customer registry
  -> OpenSearch write roles limited to approved stream patterns
```

Security rules:

- A customer credential maps to exactly one `customer.slug`.
- Customer IP allowlists are enforced at the ingest edge or central Logstash boundary.
- Central Logstash does not trust customer identity from the event body.
- Source IDs and datasets must match GitOps desired state for the mapped customer.
- Unknown sources are quarantined or rejected according to policy.
- The Logstash writer role can write only generated log, quarantine, and alert stream patterns.
- Admin users access Dashboards internally only.
- Service accounts are least privilege and rotatable.
- Credential records are designed so they can later evolve to per-relay credentials or mTLS without changing stream naming.

## Backup And Recovery

External S3-compatible object storage is the intended backup target, but it is optional in version one.

Backup scope:

- OpenSearch snapshots to object storage when configured.
- Git repository bundle or mirror backup.
- Encrypted backup of required local secret material if the operator chooses to manage it.
- Documentation for restore order and expected downtime.

If external object storage is not configured, the system must clearly report that there is no real disaster recovery for VM loss. Local-only backups may help with operator mistakes, but they do not protect against disk or VM failure.

## Operations And Monitoring

The deployment should expose these operational signals:

- OpenSearch health
- OpenSearch heap and JVM pressure
- OpenSearch disk watermarks
- Logstash input and output rates
- Logstash persistent queue depth
- Logstash output failures
- per-customer ingest volume
- per-dataset stream growth
- quarantine volume and reasons
- rendered config version
- GitOps reconcile status
- backup and snapshot status

Failure behavior:

- If OpenSearch restarts or slows down, central Logstash queues events up to configured disk limits.
- If central SIEM is unavailable, customer-local Logstash queues events locally.
- If a customer credential or IP allowlist check fails, central ingest rejects the connection or event.
- If a source is unknown, disabled, or mapped to the wrong customer, central ingest routes to quarantine or rejects according to policy.
- If disk crosses watermarks, noisy retention is shortened before critical retention.
- If rendered GitOps artifacts are stale, deployment fails closed.

## Scaling Path

Version-one shape:

```text
customer relays
  -> central Logstash persistent queue
  -> one OpenSearch node
```

Growth path:

```text
v1: relay-only ingest, central Logstash PQ, one OpenSearch node
v2: larger SSD/NVMe storage, tuned heap, more Logstash workers and pipelines
v3: add Redpanda/Kafka-compatible broker and parser/indexer workers
v4: split OpenSearch onto a real multi-VM cluster when one host is the limit
```

The broker boundary should be planned in naming and pipeline structure, but not deployed in version one.

## Out Of Scope For Version One

- Direct central ingest from customer devices.
- Customer access to OpenSearch Dashboards.
- SOAR, cases, automation, and response workflows.
- Redpanda, Kafka, or another broker.
- Multi-VM OpenSearch high availability.
- Per-customer OpenSearch clusters.
- PostgreSQL or an admin API as the configuration source of truth.
- Plaintext secret storage in Git.

## Success Criteria

- A new customer can be added through GitOps desired files.
- Rendered Logstash config maps that customer to exactly one readable slug.
- Rendered OpenSearch objects create the expected customer stream permissions and retention policies.
- Customer-forwarder traffic can only write to the mapped customer streams.
- Unknown sources cannot enter production streams.
- Default retention protects the initial 500 GB disk target at up to 10 GB/day.
- Operators can identify disk pressure, queue pressure, noisy customers, and quarantine spikes.
- The architecture can grow to a broker-backed pipeline later without renaming customer streams.
