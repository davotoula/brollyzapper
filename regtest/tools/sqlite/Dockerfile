# sqlite3 against the server's data volume.
#
# The server image is distroless/static and has no shell — deliberately (§3):
# it is all the attack surface, so it carries no tools. The stack still has to
# be able to ask the database questions (o34.7 asserts on txns rows,
# pending_zap_receipts rows, and the settle_index resume point), and it has to
# be able to rewind the resume point to force a replay.
#
# So the tool is a separate throwaway container mounted on the same named
# volume. Built once by e2e.sh and reused; nothing about it ships.
# Pinned by digest all the same: internal/arch's base-image test says why, and
# Dependabot proposes the refresh (0vk.58).
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
RUN apk add --no-cache sqlite
ENTRYPOINT ["sqlite3"]
