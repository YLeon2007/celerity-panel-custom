# Hysteria Backend - Docker Image
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

# Создаём директории для логов, сертификатов и бэкапов
RUN mkdir -p logs greenlock.d/live greenlock.d/accounts backups && \
    chmod -R 755 greenlock.d backups

# Порты
EXPOSE 8444 80 443

# Запуск
CMD ["node", "index.js"]

