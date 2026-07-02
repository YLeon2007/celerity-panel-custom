# Развёртывание custom-версии

Этот репозиторий позволяет развернуть custom-версию панели C³ CELERITY из исходников одним установочным скриптом.

## Установка одной командой из публичного GitHub-репозитория

```bash
curl -fsSL \
  https://raw.githubusercontent.com/YLeon2007/celerity-panel-custom/main/scripts/install.sh \
  | sudo -E bash
```

Скрипт интерактивно спросит отсутствующие значения (`PANEL_DOMAIN`, `ACME_EMAIL`). Для автоматизации передайте их через переменные окружения.

Для тестирования ветки `develop`:

```bash
export BRANCH='develop'

curl -fsSL \
  https://raw.githubusercontent.com/YLeon2007/celerity-panel-custom/develop/scripts/install.sh \
  | sudo -E bash
```

По умолчанию установщик использует:

```text
REPO=YLeon2007/celerity-panel-custom
BRANCH=main
INSTALL_DIR=/opt/hysteria-panel
COMPOSE_FILE=docker-compose.yml
```

При необходимости можно переопределить параметры:

```bash
export BRANCH=develop
export INSTALL_DIR='/opt/hysteria-panel-dev'
export COMPOSE_FILE='docker-compose.yml'
```

> Если вы разворачиваете не этот публичный repo, а приватный fork, перед запуском задайте `GITHUB_TOKEN` с правом чтения репозитория.

## Безопасность при существующей установке

Если директория `/opt/hysteria-panel` уже существует, установщик создаёт tar-бэкап в:

```text
/opt/hysteria-panel-install-backups/
```

После этого скрипт останавливается и просит запустить его повторно с:

```bash
FORCE=1
```

Это защищает от случайной перезаписи существующей панели.

## Генерируемые секреты

Если переменные не заданы заранее, установщик сам сгенерирует:

```text
ENCRYPTION_KEY
SESSION_SECRET
MONGO_PASSWORD
```

и запишет их в:

```text
/opt/hysteria-panel/.env
```

Файл `.env` никогда не коммитится в репозиторий.

## Обновление существующей custom-установки

```bash
cd /opt/hysteria-panel
git fetch origin main
git checkout main
git pull --ff-only origin main
docker compose -f docker-compose.yml up -d --build
```

## Примечания

- Production-развёртывание использует `docker-compose.yml`: backend собирается из этого репозитория, а HTTPS терминирует Caddy.
- Установщик задаёт `USE_CADDY=true` и ожидает, что DNS-запись для `PANEL_DOMAIN` указывает на сервер.
- По возможности не сохраняйте токены в истории shell; временные GitHub tokens лучше отзывать после завершения развёртывания.
- GitHub Actions workflow для Docker Hub в custom-репозитории отключён по умолчанию, чтобы не спамить письмами о failed runs без настроенных Docker Hub secrets.
