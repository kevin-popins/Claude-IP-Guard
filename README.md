<p align="center">
  <img src="logos/logog%20and%20safe%20state.png" width="140" alt="Claude IP Guard logo">
</p>

<h1 align="center">Claude IP Guard</h1>

<p align="center">
  A small Windows safety guard for Claude Desktop.
</p>

<p align="center">
  <img alt="Version 1.0.2" src="https://img.shields.io/badge/version-1.0.2-brightgreen?style=for-the-badge">
  <img alt="Windows" src="https://img.shields.io/badge/Windows-WPF-0078D4?style=for-the-badge&logo=windows">
  <img alt=".NET 8" src="https://img.shields.io/badge/.NET-8.0-512BD4?style=for-the-badge&logo=dotnet">
  <img alt="License MIT" src="https://img.shields.io/badge/license-MIT-blue?style=for-the-badge">
  <img alt="Safety first" src="https://img.shields.io/badge/safety-block%20first-red?style=for-the-badge">
</p>

## Русский

Claude IP Guard нужен для простой вещи: не дать Claude Desktop выйти в сеть, если текущий IP относится к стране, в которой запрещено использование Claude, либо если пользователь сам указал IP или диапазон IP, с которого он не хочет выходить к серверам Claude.

Приложение постоянно живет рядом с Claude, проверяет внешний IP, страну, состояние процессов Claude и правила Windows Firewall. Если сеть поменялась, проверка сломалась, провайдеры IP спорят между собой или страна попала в блок, Claude сначала блокируется. Разрешение включается только после успешной проверки.

По умолчанию заблокированы страны: `RU`, `BY`, `IR`, `KP`. Коды стран, которые нужно запретить, настраиваются в `Settings`. Там же можно указать конкретные IP или CIDR-диапазоны для режима IP allowlist. Strict Mode включен: если Claude уже запущен и подтвержден опасный IP, приложение может завершить Claude-процессы после блокировки сети.

Что умеет:

- показывает текущий публичный IP и страну;
- показывает, запущен Claude или нет;
- показывает, разрешен ли Claude в сеть;
- блокирует Claude через Windows Defender Firewall;
- проверяет IP через несколько независимых источников;
- поддерживает режим blocked countries и IP allowlist;
- реагирует на смену сети: сначала блокировка, потом проверка;
- умеет безопасно открыть Claude только после успешной проверки;
- умеет убить Claude и связанные helper-процессы;
- пишет локальные логи и экспортирует диагностический отчет;
- работает из tray и может запускаться вместе с Windows.

Окно можно свернуть обычной кнопкой minimize. Кнопка `X` не выключает защиту: она прячет окно в tray, а приложение продолжает следить за сетью. Полностью закрыть Claude IP Guard можно только через tray menu -> `Exit`; при таком выходе приложение снимает свои firewall-ограничения для Claude.

Чего приложение не делает:

- не читает трафик Claude;
- не читает токены, cookies или ключи;
- не читает содержимое чатов;
- не отправляет ваши данные куда-либо, кроме обычных публичных IP-check запросов.

Главное правило: если что-то не так с сетью, Claude блокируется.

### Сборка

Нужны Windows и .NET 8 SDK.

```powershell
dotnet build ClaudeIPGuard.slnx -c Release
dotnet run --project ClaudeIPGuard.Tests\ClaudeIPGuard.Tests.csproj -c Release
dotnet publish ClaudeIPGuard.App\ClaudeIPGuard.App.csproj -c Release -r win-x64 --self-contained false -o deploy\ClaudeIPGuard
```

Приложение требует права администратора, потому что управляет правилами Windows Firewall.

### Releases

Если вы просто хотите пользоваться приложением, не собирайте проект вручную. Откройте GitHub Releases и скачайте архив:

`ClaudeIPGuard-1.0.2-win-x64.zip`

В архиве уже есть папка приложения. Распакуйте архив в удобное место и запустите `ClaudeIPGuard.App.exe`. Windows попросит права администратора, потому что приложению нужно управлять firewall-правилами.

## English

Claude IP Guard does one practical job: it keeps Claude Desktop offline when the current IP belongs to a country where Claude usage is not allowed, or when the user has explicitly configured an IP or IP range they do not want to use for Claude server access.

The app watches your public IP, country, Claude processes, and Windows Firewall state. If the network changes, the IP check fails, providers disagree, or the country is blocked, Claude is blocked first. Network access is allowed only after a successful safe check.

Default blocked countries are `RU`, `BY`, `IR`, `KP`. Country codes can be changed in `Settings`. You can also configure specific IPs or CIDR ranges for IP allowlist mode. Strict Mode is enabled by default: if Claude is already running and a dangerous IP is confirmed, the app can terminate Claude-related processes after blocking network access.

Features:

- shows the current public IP and country;
- shows whether Claude is running;
- shows whether Claude network access is allowed or blocked;
- blocks Claude with Windows Defender Firewall;
- checks IP through multiple independent providers;
- supports blocked countries and IP allowlist modes;
- reacts to network changes: block first, verify second;
- opens Claude safely only after a successful check;
- kills Claude and related helper processes;
- keeps local logs and exports diagnostic reports;
- runs from the tray and can start with Windows.

The window can be minimized with the normal minimize button. The `X` button does not stop protection: it hides the window to the tray and the guard keeps running. To fully close Claude IP Guard, use tray menu -> `Exit`; on exit, the app removes its own firewall restrictions for Claude.

What it does not do:

- does not inspect Claude traffic;
- does not read tokens, cookies, or keys;
- does not read chat contents;
- does not send your data anywhere except normal public IP-check requests.

The main safety rule: when in doubt, block Claude.

### Build

Requires Windows and the .NET 8 SDK.

```powershell
dotnet build ClaudeIPGuard.slnx -c Release
dotnet run --project ClaudeIPGuard.Tests\ClaudeIPGuard.Tests.csproj -c Release
dotnet publish ClaudeIPGuard.App\ClaudeIPGuard.App.csproj -c Release -r win-x64 --self-contained false -o deploy\ClaudeIPGuard
```

The app requires administrator rights because it manages Windows Firewall rules.

### Releases

If you only want to use the app, do not build it manually. Open GitHub Releases and download:

`ClaudeIPGuard-1.0.2-win-x64.zip`

The archive already contains the app folder. Unzip it anywhere and run `ClaudeIPGuard.App.exe`. Windows will ask for administrator rights because the app needs to manage firewall rules.

## License

MIT. See [LICENSE](LICENSE).

Claude is a product of Anthropic. This project is independent and is not affiliated with Anthropic.
