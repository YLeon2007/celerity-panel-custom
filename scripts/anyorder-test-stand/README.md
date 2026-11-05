# Native TEST package — только preparation, shared-node v2

Этот producer делает **один настоящий native artifact**, а не installer/capture/
controller. Product source: `2b1fb3ec194ebc8b141e0173be230f1457fd18c8`, tree
`cef048754830081aa9893f2dd012136992d65454`. Этот candidate требует отдельного
independent review/deploy approval. Producer commit записывается отдельно.
Старые fixed source packs, config v2, `accepted-test-v1`, Fence/runner/store
и application source не меняются. Wave49/v3 не применяется.

## Состав и проверяемые свойства

* Из Git blob-ов exact source pin экспортируются root entry/config/lock/license,
  Dockerfile/root Compose/Caddyfile/env example и полные tracked `src/`, `scripts/`,
  `views/`, `public/`, `templates/`, `updater/`. Это явно ограниченная runtime/source
  closure; `.git`, `.env`, старые images, customer data и чужие node_modules не входят.
* Official Node **20.20.2 linux-x64**, glibc: archive с nodejs.org, TLS и официальный
  SHASUMS256; SHA-256 архива фиксирован в producer. Никаких Alpine/musl symlink hacks.
  Final `runtime/node` и LICENSE взяты из проверенного архива. Host loader/libc/
  libstdc++/libgcc являются Ubuntu prerequisite, не выдуманным bundled loader.
* На TEST host выполняется нормальный `npm ci --omit=dev --no-audit --no-fund`,
  неизменный lock, lifecycle scripts сохранены. CPU=240s, AS=2GiB на child,
  V8 heap=192MiB, jobs=1, nice=10, wall=600s; cache/HOME только в staging.
  Optional native accelerators могут использовать штатный JS fallback.
  Все установленные package versions сверяются с lock; mandatory production
  packages обязательны. В manifest отражены отсутствующие optional packages.
* Tracked generated assets копируются **без rebuild**; SHA каждого asset/source
  проверяется до и после npm и после распаковки. Unpinned `npx esbuild` не вызывается.
* `manifest.json` содержит file/mode/link SHA records, source/producer pins,
  exact targets и **unresolvedInstallationInputs**. Это artifact manifest,
  **не physical inventory, acceptance receipt или разрешение на запуск**.
  `installationReady=false`, `physicalInventory=null`, `authority=null` обязательны.
* Checker и focused tests входят в сам artifact (`tools/`), их bytes сверяются с
  producer pin; повторная проверка распакованного пакета не требует checkout.
  Пятый finite case читает `SHUTDOWN_DEADLINE_MS` из shipped `app/index.js`
  и `TimeoutStopSec` из shipped unit: 1900s оставляет 100s поверх drain 1800s.
  Timeout ≤ drain или margin < 100s отвергается без запуска app/сервиса и ожиданий.
* Checker исполняет actual packaged Node, разрешает все прямые dependencies через
  `createRequire(app/index.js)`, реально загружает установленный `mongoose`,
  проверяет version и `ldd`. **index.js не запускается**, БД/Redis/ноды не трогаются.
  Это artifact/runtime closure proof, не startup/native/G1/PPP/rollback acceptance.

## Повтор сборки (только отдельный private staging на TEST)

Локально, из **clean committed producer worktree**:

```sh
python3 scripts/anyorder-test-stand/package.py export \
  --repo "$PWD" --output "$FRESH_LOCAL_EXPORT"
```

`FRESH_LOCAL_EXPORT` — новый private каталог под разрешённым scratch/evidence,
не source checkout. Создать на `132.243.230.19` **только** новый root-owned 0700
`/opt/c3-test/staging/native-package-<unique-owned-id>`, перенести туда contents
export через dedicated strictly pinned SSH. Не использовать другие hosts/keys.
После переноса, на TEST, в этом каталоге:

```sh
python3 producer/package.py build --stage "$PWD" --output "$PWD/native-test.tar.gz"
mkdir -m 700 unpacked
python3 -c 'import tarfile; tarfile.open("native-test.tar.gz").extractall("unpacked", filter="data")'
INPUT_SHA=$(sha256sum build-input.json | cut -d' ' -f1)
python3 unpacked/tools/package.py check --root "$PWD/unpacked" \
  --expected-input-sha256 "$INPUT_SHA" --execute-runtime
python3 unpacked/tools/test_package.py --root "$PWD/unpacked" --expected-input-sha256 "$INPUT_SHA"
sha256sum native-test.tar.gz unpacked/manifest.json build-input.json
```

Сохранить terminal exit statuses, закрытые npm/probe logs, manifest/input hashes.
Checker logs создаются **рядом** с unpacked, не внутри sealed package. Не редактировать
sealed manifest после сборки. `--require-installation-ready` намеренно отказывает.
Никаких npm/build на Hermes gateway; никаких Docker `exec`, `up`, `pull`, `build`,
network/firewall/systemd writes во время packaging.

Offline Compose rendering (уже установленный Docker Compose >=2.24.4):
задать **явно помеченные TEMPLATE_ONLY** значения обязательных substitutions,
не читать secrets. Compose проверяет существование env_file даже с
`--no-env-resolution`: создать два пустых **offline fixture** файла только в
private staging и задать `C3_BACKEND_ENV_FILE` / `C3_REDIS_HEALTH_ENV_FILE` на них.
В настоящей установке defaults остаются `/opt/c3-test/secrets/...`; отсутствие
private files не игнорируется. В private staging:

```sh
docker compose --project-directory "$PWD/unpacked/app" \
  -f "$PWD/unpacked/app/docker-compose.yml" \
  -f "$PWD/unpacked/deployment/compose.test-native.yml" \
  config --no-env-resolution --format json > compose-template-render.json
```

Это syntax/merge proof с нерешёнными deployment inputs, не конфигурация для `up`.
`!reset`/`!override` — настоящие Compose tags (generic YAML LSP может их не знать).
Native unit проверять `systemd-analyze verify --root=<private-offline-root>` с
копией unit/runtime и installed host systemd unit definitions; никогда не копировать
unit в живой `/etc/systemd/system`, не вызывать daemon-reload/start/enable.

## Deployment templates и будущая установка — отдельный approval gate

**Сейчас запрещено выполнять этот раздел.** Он определяет targets/prerequisites,
не выдаёт installation authority и не предоставляет fake pins.

1. Принять independent candidate review; сделать private checkpoint DB/volumes,
   credentials/admin/HyNode identities и serving TLS. Разобрать реальную Mongo `rs0`
   topology/advertised member address: host-native должен подключаться через
   loopback **с replicaSet=rs0** (при необходимом single-member directConnection
   выбрать поддержанный существующим deployment URI, проверить транзакции отдельно).
   Не реинициализировать RS и не менять Mongo/Redis credentials. Сохранить все
   existing volumes, в том числе реально прочитанный anonymous `/data/configdb`.
2. Future root project `/opt/c3-test/project` — настоящий clean Git checkout exact
   product pin, не app extraction без `.git`. Base — его обычный root Compose с
   пятью services `backend/updater/mongo/redis/caddy` (container backend называется
   `hysteria-backend`). Override заменяет штатный nginx entry на Caddy **8443**,
   не добавляет witness-контейнеры и не занимает MAIN/443. Старые три `c3-test-*`
   replicas должны быть выведены в отдельном согласованном cutover с сохранением
   volumes, а не оставлены параллельными writers. Задать реальными проверенными
   значениями все `C3_*`, MONGO_USER/PASSWORD, UPDATER_SECRET; build/pin продуктовый
   updater и Caddy отдельно. Сначала private authenticated Redis health env
   (`REDISCLI_AUTH`), backend env и TLS files; templates secrets не содержат.
   Root-only rendered merged file **`compose.test-native.rendered.json`** положить
   в project: штатный updater принимает **один** COMPOSE_FILE, не colon-list.
   Он source-mode, с тем же абсолютным project mount/working dir/Docker socket/
   existing HMAC. Native bundle в его mount не входит. Этот rendered file может
   содержать secrets и не должен попасть в source/evidence/package.
3. После отдельного deployment approval распаковать artifact в private staging,
   проверить внешние artifact/manifest/input SHA и checker. Install targets:
   `/opt/c3-test/native/{runtime/node,app/index.js}`, root-owned immutable source/
   runtime/dependencies; writable logs/backups/data отдельно в
   `/opt/c3-test/native-state/{logs,backups,data}` с соответствующими app symlinks.
   Unit bytes — `/etc/systemd/system/c3-test-native.service`, 0644 root:root.
   Bundle inventory/modes/unit bytes и mutable paths пинить после реальной установки,
   не брать physical pins из этого artifact manifest. Unit без [Install],
   Restart=no, root (fresh ordinary attestor требует root); **inactive** до capture.
4. Private `/opt/c3-test/secrets/native.env` 0600 root:root — только пять ключей из
   `native.env.example`, с существующими TEST encryption/session/email и настоящими
   loopback authenticated Mongo/Redis URI. Не копировать populated secrets в пакет.
   Unit фиксирует TEST execution/migrations=true и все PROD/classic flags=false.
   EnvironmentFile нельзя дополнять flags/domain/port/C3_SETTINGS: это может
   перезаписать unit Environment. `C3_SETTINGS` classic bundle здесь не используется.
   **Ordinary index.js слушает все interfaces** (HOST env не поддерживается).
   До activation требуется реальное accepted ingress exclusion TCP/3001 на host
   и подтверждённый доступ Caddy через loopback; одного PORT=3001 недостаточно.
   Этот пакет firewall не меняет и не выдаёт listener за loopback-only.
5. Реально provision P104↔panelB private RFC1918 **/32** overlay без default route
   change и независимые SSH/2222+recovery; получить fresh login. Publicly register
   panelB через существующий API и read back настоящий HyNode ID. Начальная G1:
   P104 `6aecd36265572a55acf7c677` → panelB shared `xray-bridge`, profiles
   `[xray-main,xray-bridge]`. R185 `6aecd36265572a55acf7c67d` остаётся relay/G2;
   US108 остаётся US bridge; пользователь подтвердил reinstall и разрешил отдельному
   worker его bootstrap/registration. Этот шаг к R/US/PROD не подключается, не
   переиспользует их credentials и не ожидает неизменности общего node count.
   После настоящего overlay обновить HyNode.ip/private runner:2222 через supported
   panel form и завершить вызванный schedulePush **до hold**. ID panelB сейчас
   отсутствует; никакого invented placeholder ID/accepted inventory не создаётся.
6. Install existing runner/helpers/maintenance units; принять exact machine/boot/
   raw host-key/endpoint/profile/plan/unit/keep pins и accepted empty originals
   P MAIN+B SIDECAR (B MAIN сохранить отдельно). Physical configs остаются
   `/etc/celerity/topology-test-physical.json` **v2** и
   `/etc/celerity/topology-test-inventory.json` **accepted-test-v1**; они не входят
   в artifact и не генерируются producer. Finite schema bootstrap с остановленными
   consumers — существующие product primitives, не выдуманный CLI.
7. Независимые guards → hold → drain → fresh confirm-access → настоящий owner
   `node scripts/test-topology-owner.js enroll`. Freeze updater→docker→containerd→
   OLD backend по существующему contract. После hold **никаких docker exec**.
   NEW native запускается через PID1/maintenance только после accepted capture и
   получает fresh ordinary root read-only attestor scopes; owner CLI не передаёт
   bearer authority. Unit keep `/system.slice/c3-test-native.service` и app bytes
   должны быть реально приняты до hold. Caddy переключается через заранее принятый
   localhost admin API, не через frozen Docker. Default worker/executor неизменны.

Все restart policies templates явно `no`; package ничего не активирует. Пока
не принят весь installation gate, native unit не загружать/не запускать, старый
backend не останавливать. Следующий **единственный** шаг — отдельный approved
TEST installation/enrollment dispatch по этому v2 profile. После него отдельно
native/G1 acceptance; package verification не открывает PROD и не доказывает PPP,
полный rollback или live startup.
