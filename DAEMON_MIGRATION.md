# Переход на vpnctld — статус и что осталось

Этот документ отслеживает переход vpnctl с модели "каждый вызов CLI/TUI — самостоятельный процесс, координирующийся через `active.json` на диске" на модель "привилегированный демон `vpnctld` единолично владеет netns/iptables/engine-состоянием в памяти, `vpnctl` — тонкий клиент". Мотивация и общий план — в роадмап-ТЗ ("Часть B"). Здесь — конкретно что сделано и что нет, по состоянию кода.

## Модель демона

Единый системный root-демон на всю машину (не per-user) — `vpnctld`, слушает Unix-сокет `/run/vpnctl.sock` (переопределяется через `$VPNCTL_SOCKET` у клиента, `--socket` у демона). Соответствует текущей реальности: namespace `vpnctl0` — фиксированное имя, активен всегда только один профиль системно.

Протокол (`internal/rpc`): `[4 байта big-endian длина][JSON]`, один запрос — одно соединение (без мультиплексирования), конверт с полем `api_version` (несовпадение — явная ошибка, не крэш). Одно исключение — `Exec` (см. ниже): после начального хендшейка то же соединение переходит в потоковый режим кадров `[1 байт type][4 байта длина][payload]` (`internal/rpc/stream.go`).

## Сделано

### Фаза 1 — фундамент + простые команды

- **`internal/rpc`** — фрейминг, конверт запрос/ответ, методы `Ping/Activate/Deactivate/Status/TestConnectivity/ListProcesses/KillProcess`.
- **`internal/vpnctld`** — сервер: in-memory состояние под мьютексом (замена `internal/netguard`'s file-backed `ActiveState` — см. ниже про то, что из Части A теперь неактуально), держит один `netguard.NewLinuxEngine(false)`, health-check как горутина с `context.CancelFunc` вместо detached-процесса.
- **`cmd/vpnctld`** — entrypoint демона: требует root, слушает сокет (подчищает stale-сокет от предыдущего аварийно завершённого инстанса), грациозный `Deactivate`+`Teardown` на SIGTERM/SIGINT.
- **`internal/vpnctlclient`** — тонкий клиент: резолвит профиль локально (`profile.Find`, демон никогда не читает `~/.config/vpnctl/profiles` ни для одного пользователя), шлёт уже разрешённый профиль по сокету.
- **Конвертированы**: `vpnctl use/down/status/test` — полностью через демон, root/sudo не нужен.
- **`vpnctld`'s own state dir**: `netguard.StateDir()` резолвит через "домашнюю директорию реального пользователя" — осмысленно для старой per-invocation CLI-модели, но у демона нет "вызывающего пользователя" вообще, а `systemd-run`/`.service` не даёт `$HOME` — падало с `$HOME is not defined` (поймано живьём на стенде). Починено через `VPNCTL_STATE_HOME=/var/lib/vpnctld` (флаг `--state-dir`), выставляемый демоном себе самому при старте — переиспользует ту же переменную, что уже вводили в Части A для `prerm`. Итоговый путь получается `/var/lib/vpnctld/.local/state/vpnctl/...` (наследие того, что `StateDir()` всегда дописывает `.local/state/vpnctl` к переданному "home") — работает корректно, но при packaging стоит решить, нужен ли более прямой путь вида `/var/lib/vpnctl/...` без вложенности.

### Фаза 2 — `vpnctl run` за демоном (PTY/pipe-прокси)

- **Новые зависимости**: `github.com/creack/pty` (сервер — реальный PTY), `golang.org/x/term` (клиент — raw mode + размер терминала).
- **`internal/rpc/stream.go`** — `Exec`-метод: хендшейк как у обычного RPC (`ExecParams{Mode, Argv, Env, DropUID, DropGID, Cols, Rows}` → `ExecStartedResult{PID}`), дальше то же соединение несёт кадры `FrameStdin/FrameStdout/FrameStderr/FrameResize/FrameExit`.
- **`internal/vpnctld/exec.go`** — три режима: `cli` (пайпы, без PTY — как и раньше у `vpnctl run` без флагов, реальный терминал никогда явно не аллоцировался, просто наследовался напрямую), `tui` (настоящий PTY через `creack/pty`, `FrameResize` → `pty.Setsize`), `gui` (detached, `/dev/null`, демон реапит и untrack'ает процесс сам — в отличие от старого `internal/run.GUI`, который никогда не мог этого сделать, потому что процесс vpnctl завершался сразу же). Обрыв соединения ДО завершения процесса → демон убивает его (SIGTERM, потом SIGKILL) — это и есть "отмена", отдельного управляющего кадра не нужно.
- **`ListProcesses`/`KillProcess` теперь реальные**: `Server.processes` наполняется `Exec`'ом, `KillProcess` шлёт сигнал напрямую (`syscall.Kill`) — демон всегда root, поэтому проще клиентской EPERM-эквилибристики из `internal/actions/processes.go`. `deactivateLocked()` перед `Teardown()` убивает все трекнутые процессы (аналог `netguard.killTrackedProcesses`, только по in-memory списку, а не по `active.json`, который демон не пишет) — без этого `vpnctl down`/остановка демона осиротили бы `run`-сессии внутри уничтожаемого namespace.
- **Найденная и починенная гонка**: `ptmx.Close()` в основной горутине `execPTY` конкурировал с `pty.Setsize`/`Write` в горутине, читающей входящие кадры (`relayPTYInput`) — обе трогают один и тот же fd PTY. Поймано `go test -race`, а не угадано. Фикс: перед закрытием `ptmx` основная горутина форсирует выход `relayPTYInput`, дёргая `conn.SetReadDeadline(time.Now())` и дожидаясь её завершения — только потом закрывает `ptmx`.
- **Конвертирован**: `vpnctl run` (все три режима — без флага, `--tui`, `--gui`) — root/sudo не нужен. `internal/run.TUI`/`foreground`-для-TUI и `TypeTUI` удалены как мёртвый код; `internal/run.CLI`/`GUI` остались — `CLI` всё ещё нужен `internal/actions.TestConnectivity` (обслуживает TUI), `GUI` всё ещё нужен `internal/tui/appsview.go` (TUI не мигрировал). `resolveGUIEnv` экспортирован (`run.ResolveGUIEnv`) — переиспользуется новым `cmd/vpnctl/run.go`.

## ВАЖНО: известное ограничение переходного состояния

**Только голый `vpnctl` (TUI, без аргументов) не мигрирован** — по-прежнему требует root и работает по старой модели (файл `active.json`, `internal/actions`, `internal/netguard.LoadActiveState`/`SaveActiveState`). Всё остальное (`use/down/status/test/run/ps/kill/doctor`) работает через демона.

Активация профиля через `vpnctl use` **не отразится** в TUI (TUI покажет "No active profile"), и наоборот. TUI's `run`-экран (`internal/tui/runview.go`) и запуск apps (`appsview.go`) тоже не видят daemon-активированный профиль — они всё ещё используют старую прямую модель. Сознательно не стали городить временный dual-write шим между двумя моделями — это выкидываемая работа. **Не смешивать TUI и остальные команды в одной сессии до завершения миграции TUI.**

## Что осталось (следующий заход)

### 1. Перевод `internal/tui` на клиента демона

Три точки прямого обращения к `netguard`/`actions` в обход общего слоя:
- `internal/tui/model.go` — `refreshStatusCmd`/`loadProcessesCmd` (сейчас `actions.CurrentStatus`/`actions.ListProcesses`) → `vpnctlclient.Status`/`ListProcesses`.
- `internal/tui/mainview.go:112` — прямой `netguard.LoadActiveState()` для log-tailing → новый RPC типа `GetActiveLogTail(lines int)` (у демона нет `active.json`, но есть `EngineLog`-путь в памяти).
- `internal/tui/appsview.go`, `internal/tui/runview.go` — используют `netguard.NewLinuxEngine`+`ng.Command()`+`tea.ExecProcess` → переезжают на уже готовый RPC `Exec` (протокол и демон-сайд не трогать, только клиентская часть — вероятно, обёртка над `vpnctlclient.Exec`, отдающая `*exec.Cmd`-подобный интерфейс для `tea.ExecProcess`, либо прямая замена `tea.ExecProcess` на ручное управление raw-mode, как уже сделано в `vpnctlclient.relay`).
- `cmd/vpnctl/tui.go` — убрать `actions.RequireRoot()` gate после конверсии.

### 2. systemd + packaging

- Новый unit `packaging/vpnctld.service` (`Type=notify`, `Restart=on-failure`, **обязательно `KillMode=process`**). Поймано живьём на стенде: systemd по умолчанию (`KillMode=control-group`) при `systemctl stop` шлёт SIGTERM всей cgroup сервиса — включая дочерний процесс, который демон в этот самый момент порождает для graceful teardown (`awg-quick down` через nsenter, внутри `Shutdown()`→`deactivateLocked()`→`handle.Stop()`). Дочерний процесс убивается на середине, `Stop()` возвращает `exit status 1`, `Teardown()` (снос namespace) из-за этого вообще не вызывается — netns остаётся висеть ровно как в A1. Проверено `systemd-run --property=KillMode=process` — с этим свойством teardown при остановке проходит чисто каждый раз.
- `postinst`: создать группу `vpnctl` (сокет `root:vpnctl 0660`), **one-time миграция**: до первого `systemctl enable --now vpnctld` прогнать по всем `~/.local/state/vpnctl/active.json` ту же force_teardown-логику, что уже есть в `prerm` (иначе апгрейд с файловой версии на демон-версию оставит осиротевший namespace/процессы от старой модели).
- `prerm`: заменить весь per-user teardown-танец на `systemctl stop vpnctld` (демон сам корректно всё снесёт через свой `Shutdown()`), оставить текущий `force_teardown` только как fallback на случай, если демон уже мёртв/не отвечает.
- `nfpm.yaml`: добавить бинарь `vpnctld` + unit-файл в `contents:`.

### 3. Уборка после того, как TUI переедет

- `internal/healthcheck` + `internal/actions/healthdaemon.go` — удалить (логика уже задублирована как горутина в `internal/vpnctld/healthcheck.go`).
- `internal/actions` целиком, `internal/run.CLI`/`GUI`/`foreground` — кандидаты на удаление, когда последний потребитель (`internal/tui`) переедет на `vpnctlclient`.
- `internal/netguard`'s file-backed `ActiveState`/`UpdateActiveState`/flock-механизм (добавленный в Части A для A2) — станет мёртвым кодом: в демон-модели гонка невозможна архитектурно (единственный владелец состояния в памяти), ровно как и предсказывало исходное ТЗ. Не удалять раньше времени — пока TUI не мигрировал, эти файлы всё ещё единственный источник правды для него.
- `packaging/prerm`'s текущая многостраничная per-user teardown-логика — заменяется на `systemctl stop`.
