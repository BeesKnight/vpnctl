# Переход на vpnctld — статус и что осталось

Этот документ отслеживает переход vpnctl с модели "каждый вызов CLI/TUI — самостоятельный процесс, координирующийся через `active.json` на диске" на модель "привилегированный демон `vpnctld` единолично владеет netns/iptables/engine-состоянием в памяти, `vpnctl` — тонкий клиент". Мотивация и общий план — в роадмап-ТЗ ("Часть B"). Здесь — конкретно что сделано и что нет, по состоянию кода.

## Модель демона

Единый системный root-демон на всю машину (не per-user) — `vpnctld`, слушает Unix-сокет `/run/vpnctl.sock` (переопределяется через `$VPNCTL_SOCKET` у клиента, `--socket` у демона). Соответствует текущей реальности: namespace `vpnctl0` — фиксированное имя, активен всегда только один профиль системно.

Протокол (`internal/rpc`): `[4 байта big-endian длина][JSON]`, один запрос — одно соединение (без мультиплексирования), конверт с полем `api_version` (несовпадение — явная ошибка, не крэш).

## Сделано в этом заходе

- **`internal/rpc`** — фрейминг, конверт запрос/ответ, методы `Ping/Activate/Deactivate/Status/TestConnectivity/ListProcesses/KillProcess`.
- **`internal/vpnctld`** — сервер: in-memory состояние под мьютексом (замена `internal/netguard`'s file-backed `ActiveState` — см. ниже про то, что из Части A теперь неактуально), держит один `netguard.NewLinuxEngine(false)`, health-check как горутина с `context.CancelFunc` вместо detached-процесса.
- **`cmd/vpnctld`** — entrypoint демона: требует root, слушает сокет (подчищает stale-сокет от предыдущего аварийно завершённого инстанса), грациозный `Deactivate`+`Teardown` на SIGTERM/SIGINT.
- **`internal/vpnctlclient`** — тонкий клиент: резолвит профиль локально (`profile.Find`, демон никогда не читает `~/.config/vpnctl/profiles` ни для одного пользователя), шлёт уже разрешённый профиль по сокету.
- **Конвертированы**: `vpnctl use/down/status/test/ps/kill` — теперь полностью через демон, **root/sudo больше не нужен** для этих команд. `vpnctl doctor` — добавлена проверка `vpnctld` (reachable/нет) и старая проверка "stale WireGuard socket" переведена на клиентский RPC вместо прямого чтения `netguard`.
- **`vpnctld`'s own state dir**: `netguard.StateDir()` резолвит через "домашнюю директорию реального пользователя" — осмысленно для старой per-invocation CLI-модели, но у демона нет "вызывающего пользователя" вообще, а `systemd-run`/будущий `.service` не даёт `$HOME` — падало с `$HOME is not defined` (поймано живьём на стенде). Починено через `VPNCTL_STATE_HOME=/var/lib/vpnctld` (флаг `--state-dir`), выставляемый демоном себе самому при старте — переиспользует ту же переменную, что уже вводили в Части A для `prerm`. Итоговый путь получается `/var/lib/vpnctld/.local/state/vpnctl/...` (наследие того, что `StateDir()` всегда дописывает `.local/state/vpnctl` к переданному "home") — работает корректно, но при packaging (пункт 3 ниже) стоит решить, нужен ли более прямой путь вида `/var/lib/vpnctl/...` без вложенности.

## ВАЖНО: известное ограничение переходного состояния

После этого захода **два мира не видят друг друга**:

- `vpnctl use/down/status/test/ps/kill/doctor` — работают через демона (in-memory состояние `vpnctld`).
- Голый `vpnctl` (TUI) и `vpnctl run` — **не мигрированы**, по-прежнему требуют root и работают по старой модели (файл `active.json`, `internal/actions`, `internal/netguard.LoadActiveState`/`SaveActiveState`).

Активация профиля через новый CLI (`vpnctl use`) **не отразится** в TUI (TUI покажет "No active profile"), и наоборот — активация через TUI не будет видна `vpnctl status`. Не мигрировавшие пути также не смогут запускать процессы через daemon-активированный профиль (`vpnctl run` не найдёт активный профиль, если он был поднят через демон). Сознательно не стали городить временный dual-write шим между двумя моделями — это выкидываемая работа. **Не смешивать оба пути в одной сессии до завершения миграции TUI/`run`.**

`vpnctl ps`/`vpnctl kill` через демона всегда возвращают пустой список — плюмбинг есть, но трекинг процессов некому наполнять, пока `run`/TUI не переехали (см. ниже).

## Что осталось (следующий заход)

### 1. PTY-прокси для `run`/интерактивных TUI-программ

Самая нетривиальная часть. Сейчас `cmd/vpnctl/run.go`, `internal/tui/runview.go`, `internal/tui/appsview.go` вызывают `netguard.NewLinuxEngine(false).Command(...)` напрямую и либо передают результат в `tea.ExecProcess` (полный захват терминала — TUI-программы, интерактивные apps), либо стримят stdio напрямую (`internal/run.CLI`), либо детачат (`internal/run.GUI`). Всё это требует, чтобы **вызывающий процесс сам был root** (nsenter требует CAP_SYS_ADMIN) — в модели демона непривилегированный клиент физически не может войти в namespace сам.

Решение того же класса, что `docker exec -it`/`ssh`: демон сам держит PTY и целевой процесс внутри netns (nsenter+unshare+dns-shim+setpriv — переиспользовать существующую логику `LinuxEngine.Command`), клиент проксирует сырой поток терминала через сокет. Нужно:
- Новый RPC `Exec` с режимами: `blocking-cli` (пайпы, стриминг stdin/stdout/stderr, ждём exit-код), `pty-tui` (PTY, control-фрейм для resize/SIGWINCH), `detached-gui` (fire-and-forget, возвращаем PID).
- Framing для этого RPC: конверт с типом фрейма (control=JSON / data=raw bytes), т.к. `internal/rpc`'s текущий формат "один запрос — один ответ" не подходит для потоковой передачи.
- Client-side: перевод локального терминала в raw mode, проксирование байт, форвардинг `SIGWINCH`.
- Ровно тогда же наполнится реальными данными `ListProcesses`/`KillProcess` (сейчас пустые).

### 2. Перевод `internal/tui` на клиента демона

Четыре точки прямого обращения к `netguard`/`actions` в обход общего слоя (уже задокументировано разведкой в этой сессии):
- `internal/tui/model.go` — `refreshStatusCmd`/`loadProcessesCmd` (сейчас `actions.CurrentStatus`/`actions.ListProcesses`) → `vpnctlclient.Status`/`ListProcesses`.
- `internal/tui/mainview.go:112` — прямой `netguard.LoadActiveState()` для log-tailing → новый RPC типа `GetActiveLogTail(lines int)` (у демона нет active.json, но есть `EngineLog`-путь в памяти).
- `internal/tui/appsview.go`, `internal/tui/runview.go` — используют `netguard.NewLinuxEngine`+`ng.Command()`+`tea.ExecProcess` → переезжают на RPC `Exec` из пункта 1.
- `cmd/vpnctl/tui.go` — убрать `actions.RequireRoot()` gate после конверсии.

### 3. systemd + packaging

- Новый unit `packaging/vpnctld.service` (`Type=notify`, `Restart=on-failure`, **обязательно `KillMode=process`**). Поймано живьём на стенде: systemd по умолчанию (`KillMode=control-group`) при `systemctl stop` шлёт SIGTERM всей cgroup сервиса — включая дочерний процесс, который демон в этот самый момент порождает для graceful teardown (`awg-quick down` через nsenter, внутри `Shutdown()`→`deactivateLocked()`→`handle.Stop()`). Дочерний процесс убивается на середине, `Stop()` возвращает `exit status 1`, `Teardown()` (снос namespace) из-за этого вообще не вызывается — netns остаётся висеть ровно как в A1. Проверено `systemd-run --property=KillMode=process` — с этим свойством teardown при остановке проходит чисто каждый раз.
- `postinst`: создать группу `vpnctl` (сокет `root:vpnctl 0660`), **one-time миграция**: до первого `systemctl enable --now vpnctld` прогнать по всем `~/.local/state/vpnctl/active.json` ту же force_teardown-логику, что уже есть в `prerm` (иначе апгрейд с файловой версии на демон-версию оставит осиротевший namespace/процессы от старой модели).
- `prerm`: заменить весь per-user teardown-танец на `systemctl stop vpnctld` (демон сам корректно всё снесёт через свой `Shutdown()`), оставить текущий `force_teardown` только как fallback на случай, если демон уже мёртв/не отвечает.
- `nfpm.yaml`: добавить бинарь `vpnctld` + unit-файл в `contents:`.

### 4. Уборка после того, как TUI/`run` переедут

- `internal/healthcheck` + `internal/actions/healthdaemon.go` — удалить (логика уже задублирована как горутина в `internal/vpnctld/healthcheck.go`).
- `internal/actions` целиком — кандидат на удаление, когда последний потребитель (`internal/tui`) переедет на `vpnctlclient`.
- `internal/netguard`'s file-backed `ActiveState`/`UpdateActiveState`/flock-механизм (добавленный в Части A для A2) — станет мёртвым кодом: в демон-модели гонка невозможна архитектурно (единственный владелец состояния в памяти), ровно как и предсказывало исходное ТЗ. Не удалять раньше времени — пока `run`/TUI не мигрировали, эти файлы всё ещё единственный источник правды для них.
- `packaging/prerm`'s текущая многостраничная per-user teardown-логика — заменяется на `systemctl stop`.
