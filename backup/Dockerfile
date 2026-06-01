FROM alpine:3.20
RUN apk add --no-cache bash curl git
COPY backup/backup-opensearch.sh /usr/local/bin/backup-opensearch.sh
COPY backup/backup-gitops-repo.sh /usr/local/bin/backup-gitops-repo.sh
RUN chmod +x /usr/local/bin/backup-opensearch.sh /usr/local/bin/backup-gitops-repo.sh
