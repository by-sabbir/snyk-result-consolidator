# DevOps Task Tyk

## Installation

```bash
go build ./...
```

## Usage

```bash
./devops-task-tyk --images "tykio/tyk-hybrid-docker tykio/tyk-gateway"
```

### Check the result

```bash
column -s, -t < consolidated_vulns.csv | less -N -S
```
