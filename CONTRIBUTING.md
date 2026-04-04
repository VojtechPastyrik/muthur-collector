# Contributing

## Development setup

```bash
go mod download
make proto
make test
make lint
make helm-lint
```

## PR guidelines

- Run `make test` and `make lint` before submitting
- Keep commits focused and descriptive
- No secrets in commits — use `.env` for local dev (it's gitignored)
- Proto changes must be synced with muthur-central
