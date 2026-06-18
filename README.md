# 2 FA tool

Set proper config in the .env file. Needs L1 connection and access to EN DB.

Then you can run a single batch like this:

```shell
cargo run -- --chain-address 0x32400084C286CF3E17e7B677ea9583e60a000324 --run-one-batch 506508 --dry-run 1
```

Or you can run it in the main mode like this:

```
cargo run
```

The process can serve Kubernetes probes and Prometheus metrics when `METRICS_PORT` or
`--metrics-port` is set:

```shell
cargo run -- --metrics-port 8080
```

- `GET /livez` and `GET /healthz/live` return 200 while the process is running.
- `GET /readyz` and `GET /healthz/ready` return 200 after startup checks and Merkle initialization.
- `GET /metrics` returns Prometheus text-format runtime metrics.
