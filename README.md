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

## Docker

Prebuilt images are published to GitHub Container Registry on every push to `main`:

```shell
docker pull ghcr.io/vladbochok/en-2fa:latest
```

Available tags: `latest` (tip of `main`), `sha-<commit>` for an exact commit, and
`<version>` / `<major>.<minor>` when a `v*` tag is pushed.

Run it with your config (the image reads the same env vars as `.env`):

```shell
docker run --rm --env-file .env ghcr.io/vladbochok/en-2fa:latest
```

Extra CLI flags are appended after the image name, e.g.:

```shell
docker run --rm --env-file .env ghcr.io/vladbochok/en-2fa:latest \
  --chain-address 0x32400084C286CF3E17e7B677ea9583e60a000324 --run-one-batch 506508 --dry-run 1
```

Note: `DATABASE_URL` pointing at `127.0.0.1` refers to the container itself — use the
host's reachable address (or `--network host`) when the EN Postgres runs on the host.
