# AmneziaVPN 2.0 / AmneziaWG 2.0 Decoder

Форк исправляет декодирование новых ссылок `vpn://` из AmneziaVPN 2.0 и извлечение конфигураций AmneziaWG 2.0.

Оригинальный проект [JB-SelfCompany/awg-decoder](https://github.com/JB-SelfCompany/awg-decoder) корректно работал со старым форматом, но для новых ссылок AmneziaVPN мог сохранять JSON-экспорт вместо готового `.conf`. В этом форке добавлена поддержка нового JSON-формата AmneziaVPN 2.0, самодостаточный GUI-декодер для Windows и сборка `.exe`.

## Что исправлено и добавлено

- Исправлено декодирование ссылок `vpn://` из AmneziaVPN 2.0.
- Добавлено извлечение готового AmneziaWG 2.0 `.conf` из JSON-экспорта AmneziaVPN.
- Добавлен самодостаточный GUI-декодер `simple-awg-decoder.py`.
- Добавлена сборка Windows-приложения `AmneziaVPN Decoder.exe` без консольного окна.
- Добавлена обратная конвертация `.conf -> vpn://`.
- Новые файлы не перезаписывают старые: используются имена `NewConfig.conf`, `NewConfig_1.conf`, `NewLink.txt`, `NewLink_1.txt` и так далее.

## Простой запуск

Самый удобный вариант для пользователя Windows:

1. Скачать `AmneziaVPN Decoder.exe` из [Releases](https://github.com/ripton06/awg-decoder/releases).
2. Запустить приложение.
3. Вставить ссылку `vpn://` или использовать ссылку из буфера обмена.
4. Нажать `Создать conf`.

Файл `NewConfig.conf` появится рядом с приложением.

## Обратная конвертация

Чтобы создать ссылку `vpn://` из файла AmneziaWG `.conf`:

1. Запустите приложение.
2. Нажмите `AmneziaWG -> AmneziaVPN`.
3. Выберите `.conf` файл.

Ссылка будет сохранена рядом с приложением в `NewLink.txt`.

## Python-версия

Для запуска из исходников нужен Python 3.11+.

Внешние pip-библиотеки не нужны. GUI использует стандартный модуль `tkinter`, который обычно устанавливается вместе с Python для Windows.

```powershell
python simple-awg-decoder.py
```

Консольное декодирование:

```powershell
python simple-awg-decoder.py --link "vpn://..."
```

Обратная конвертация `.conf -> vpn://`:

```powershell
python simple-awg-decoder.py --encode-file .\config.conf
```

## Сборка exe

Для сборки нужен PyInstaller:

```powershell
python -m pip install pyinstaller
python -m PyInstaller --onefile --windowed --name "AmneziaVPN Decoder" --clean .\simple-awg-decoder.py
```

Готовый файл будет создан в папке `dist`.

## Старый CLI-декодер

`awg-decode.py` оставлен для совместимости с исходным проектом:

```powershell
python awg-decode.py --decode "vpn://..." -o my_config.conf
python awg-decode.py --encode .\config.conf -o link.txt
```

## Лицензия

Проект распространяется по лицензии GPL-3.0. См. [LICENSE](LICENSE).
