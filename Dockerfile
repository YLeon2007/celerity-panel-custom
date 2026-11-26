# Hysteria Backend - Docker Image
FROM --platform=$BUILDPLATFORM golang:1.25.7-alpine AS rebuild-proof
WORKDIR /build
COPY cc-agent/go.mod cc-agent/go.sum ./cc-agent/
COPY scripts/native-xray-main-proof/proof.go ./scripts/native-xray-main-proof/
COPY scripts/build-rebuild-main-proof.sh ./scripts/
RUN sh scripts/build-rebuild-main-proof.sh /proofs

FROM node:20-alpine

WORKDIR /app

# Install runtime tools for Mongo backup/restore and TEST client proof.
# Git, Bash and Docker CLI/Compose intentionally live only in the isolated updater image.
RUN apk add --no-cache mongodb-tools libstdc++ libgcc curl

# Копируем зависимости
COPY package*.json ./

# Install exactly the production dependency graph pinned in package-lock.json
RUN npm ci --omit=dev

# Копируем исходники
COPY . .
COPY --from=rebuild-proof /proofs/ ./libexec/

# Создаём директории для логов, сертификатов и бэкапов
RUN mkdir -p logs greenlock.d/live greenlock.d/accounts backups && \
    chmod -R 755 greenlock.d backups

# Порты
EXPOSE 8444 80 443

# Запуск
CMD ["node", "index.js"]

