# Безопасное обновление на production

Пошаговая инструкция по безопасному обновлению custom-развёртывания C³ CELERITY.

Документ соответствует текущему workflow публичного custom-репозитория:

```text
Репозиторий: https://github.com/YLeon2007/celerity-panel-custom
Директория установки: /opt/hysteria-panel
Production-ветка: main
Compose-файл: docker-compose.yml
Backend: локальная сборка из исходников
HTTPS: контейнер Caddy
```

---

## Предварительный чеклист

Команды выполняются на сервере панели.

### 1. Перейдите в директорию установки

```bash
cd /opt/hysteria-panel
```

### 2. Проверьте текущее состояние

```bash
git branch --show-current
git rev-parse --short HEAD
docker compose -f docker-compose.yml ps
curl -I https://$(grep '^PANEL_DOMAIN=' .env | cut -d= -f2)/panel/login
```

### 3. Проверьте свободное место

```bash
df -h /
docker system df
```

Для пересборки образа и backup желательно иметь минимум 2 GB свободного места.

### 4. Сохраните `.env` и файлы установки

```bash
TS=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR=/opt/hysteria-panel-install-backups/manual-update-$TS
mkdir -p "$BACKUP_DIR"
cp -a /opt/hysteria-panel/.env "$BACKUP_DIR/.env"
tar --exclude='.git' --exclude='node_modules' --exclude='logs/*.log' \
  -czf "$BACKUP_DIR/hysteria-panel-files.tar.gz" \
  -C /opt hysteria-panel
printf 'Backup dir: %s\n' "$BACKUP_DIR"
```

### 5. Сделайте backup MongoDB

Если `.env` был создан через `scripts/install.sh`, команда ниже использует сгенерированные `MONGO_USER` / `MONGO_PASSWORD`:

```bash
set -a
. ./.env
set +a
TS=$(date +%Y%m%d-%H%M%S)
docker exec hysteria-mongo mongodump \
  --archive=/tmp/hysteria-$TS.archive \
  --username "$MONGO_USER" \
  --password "$MONGO_PASSWORD" \
  --authenticationDatabase=admin
docker cp hysteria-mongo:/tmp/hysteria-$TS.archive ./backups/hysteria-$TS.archive
docker exec hysteria-mongo rm -f /tmp/hysteria-$TS.archive
```

Также можно создать/скачать backup через UI панели, если это настроено.

---

## Обновление из панели

Панель обновляется из **Настройки → Обслуживание → Обновление панели** без SSH.
Механизм работает через отдельный контейнер `hysteria-updater`.

### Однократная настройка

При установке через актуальный `scripts/install.sh` сильный `UPDATER_SECRET` уже
создаётся автоматически. Для старой ручной установки добавьте его самостоятельно:

```bash
echo "UPDATER_SECRET=$(openssl rand -hex 32)" >> .env
chmod 600 .env
docker compose -f docker-compose.yml up -d --build updater backend
```

Без `UPDATER_SECRET` updater fail-safe отклоняет запросы, а UI показывает ручную
инструкцию вместо кнопки установки.

### Как это работает

- Backend **не имеет доступа к Docker socket**; socket смонтирован только в
  изолированный updater-sidecar.
- Backend отправляет HMAC-подписанный одноцелевой запрос на переход к выбранному
  immutable release tag.
- В source-mode updater создаёт backup, выполняет checkout выбранного release tag,
  сначала собирает новый backend и только затем пересоздаёт его. Ошибка checkout
  или build оставляет работающий backend нетронутым.
- Обновление требует повторного ввода пароля администратора и, если включена 2FA,
  TOTP-кода. В UI отображаются changelog и live progress log.
- Rollback выполняется тем же механизмом на более старый release, но не отменяет
  изменения схемы/данных MongoDB — при необходимости используйте database backup.

Backup и rollback-артефакты сохраняются в каталоге `backups/` установки.

> Source-mode делает forced checkout release tag и отбрасывает локальные изменения
> tracked-файлов. `.env`, `data/`, `logs/` и `backups/` не затрагиваются.

---

## Рекомендуемое обновление: сборка из `main`

### 1. Получите и посмотрите изменения

```bash
cd /opt/hysteria-panel
git fetch origin main
git log --oneline --decorate -5 HEAD..origin/main
```

Если вывод пустой — обновлять нечего.

### 2. Убедитесь, что working tree чистый

```bash
git status --short
```

Если есть локальные изменения — сначала разберите их, закоммитьте или сохраните через stash.

### 3. Обновите checkout

```bash
git checkout main
git pull --ff-only origin main
```

### 4. Пересоберите и перезапустите stack

```bash
docker compose -f docker-compose.yml up -d --build
```

Команда пересобирает backend из текущих исходников и пересоздаёт только те контейнеры, которым это нужно.

### 5. Проверьте контейнеры и логи

```bash
docker compose -f docker-compose.yml ps
docker compose -f docker-compose.yml logs --tail=120 backend
docker compose -f docker-compose.yml logs --tail=120 caddy
```

Ожидаемые контейнеры:

```text
hysteria-backend
hysteria-updater
hysteria-caddy
hysteria-mongo
hysteria-redis
```

### 6. Проверьте доступность панели

```bash
DOMAIN=$(grep '^PANEL_DOMAIN=' .env | cut -d= -f2)
curl -I "https://$DOMAIN/panel/login"
curl -I "https://$DOMAIN/panel"
```

Ожидаемо:

```text
/panel/login -> 200
/panel       -> 302 redirect на /panel/login
```

---

## Обновление staging/develop установки

Если сервер специально установлен из `develop`:

```bash
cd /opt/hysteria-panel
git fetch origin develop
git checkout develop
git pull --ff-only origin develop
docker compose -f docker-compose.yml up -d --build
```

Для production используйте `main`, если вы не тестируете unreleased changes осознанно.

---

## Откат

### Вариант 1: откат на предыдущий git commit

```bash
cd /opt/hysteria-panel
git log --oneline -10
git checkout <previous-good-commit>
docker compose -f docker-compose.yml up -d --build
```

После проверки можно временно остаться на detached commit или создать rollback-ветку:

```bash
git switch -c rollback/<date-or-reason>
```

### Вариант 2: восстановить файлы из tar backup

```bash
cd /opt
mv /opt/hysteria-panel /opt/hysteria-panel.broken-$(date +%Y%m%d-%H%M%S)
tar -xzf /opt/hysteria-panel-install-backups/<backup-dir>/hysteria-panel-files.tar.gz -C /opt
cd /opt/hysteria-panel
docker compose -f docker-compose.yml up -d --build
```

### Вариант 3: восстановить MongoDB из backup

Делайте это только если изменилась/повредилась сама база и вы точно готовы потерять более новые данные.

```bash
cd /opt/hysteria-panel
set -a
. ./.env
set +a
docker cp ./backups/hysteria-YYYYMMDD-HHMMSS.archive hysteria-mongo:/tmp/restore.archive
docker exec hysteria-mongo mongorestore \
  --archive=/tmp/restore.archive \
  --drop \
  --username "$MONGO_USER" \
  --password "$MONGO_PASSWORD" \
  --authenticationDatabase=admin
docker exec hysteria-mongo rm -f /tmp/restore.archive
```

---

## Проверки после обновления

1. Войдите в панель.
2. Проверьте статусы нод.
3. Откройте хотя бы одну subscription-ссылку.
4. Проверьте API, если используете API keys.
5. Следите за логами 10-15 минут:

```bash
docker compose -f docker-compose.yml logs -f --tail=80 backend
```

---

## Типовые проблемы

### Backend не стартует

```bash
docker compose -f docker-compose.yml logs --tail=200 backend
docker compose -f docker-compose.yml ps
```

Частые причины:

- неверные значения в `.env`;
- MongoDB или Redis ещё не healthy;
- не хватает памяти/диска;
- в обновлении появилась синтаксическая/runtime ошибка.

### MongoDB не healthy

```bash
docker compose -f docker-compose.yml logs --tail=100 mongo
docker compose -f docker-compose.yml restart mongo
```

### Проблема с Caddy / HTTPS сертификатом

```bash
docker compose -f docker-compose.yml logs --tail=160 caddy
ss -ltnp | grep -E ':80|:443'
dig +short "$DOMAIN"
```

Проверьте, что:

- DNS указывает на этот сервер;
- порты 80 и 443 открыты;
- другой сервис не занимает 80/443;
- `PANEL_DOMAIN` в `.env` указан правильно.

---

## Примечание про Docker Hub

В custom-репозитории сейчас используется source-based deployment через `docker-compose.yml`. Upstream-файл `docker-compose.hub.yml` сохранён, но workflow публикации custom Docker Hub image оставлен ручным/выключенным по умолчанию, пока не настроены namespace образа и GitHub secrets.

Для этого custom repo предпочтителен flow обновления через сборку из исходников, описанный выше.

---

## Рекомендации

1. Сначала тестируйте обновления на staging.
2. Обновляйте в часы минимальной нагрузки.
3. Храните минимум 3 свежих backup базы.
4. Записывайте git commit до и после каждого обновления.
5. Не запускайте `docker system prune -a`, пока не убедились, что rollback не понадобится.

---

## Если что-то пошло не так

1. Не паникуйте — данные MongoDB остаются в Docker volume, если вы явно не делали `--drop`.
2. Проверьте логи: `docker compose -f docker-compose.yml logs --tail=200 backend`.
3. Откатитесь на предыдущий git commit.
4. Восстанавливайте MongoDB только при необходимости.
5. Создайте GitHub issue или приложите логи к maintenance-отчёту.
