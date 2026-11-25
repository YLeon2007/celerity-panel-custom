# C³ CELERITY 1.6.41 — локальные настройки Caddy

Если локальных правок нет, ничего настраивать не нужно: Caddy по-прежнему использует `./Caddyfile`.

1. **До обновления из панели** сохраните рабочий `Caddyfile` с локальными правками в `Caddyfile.local` в каталоге проекта. Не добавляйте его в Git. Укажите `CADDYFILE=./Caddyfile.local` в `.env`. Флаги backend также храните в `.env`: source-updater запускает Compose только с `docker-compose.yml` и не читает `docker-compose.override.yml`.
2. Обновитесь через **Настройки → Обслуживание → Обновление панели**. Updater заменит отслеживаемый `Caddyfile` версией из тега, поэтому не перезапускайте Caddy со старым подключением файла.
3. После перехода на 1.6.41 проверьте наличие `Caddyfile.local` и что `docker compose -f docker-compose.yml config` показывает его как источник `/etc/caddy/Caddyfile`. Пересоздайте только прокси в согласованное окно: `docker compose -f docker-compose.yml up -d --no-deps caddy`. Проверьте HTTPS-доступ к панели. Updater сам пересобирает backend, а новое подключение файла Caddy простым рестартом контейнера не применяется.

При возврате на версию до 1.6.41 сохраните `Caddyfile.local`: `docker-compose.yml` старого выпуска не учитывает `CADDYFILE`. Перед пересозданием Caddy на старой версии отдельно восстановите его рабочую конфигурацию.
