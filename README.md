# AmneziaVPN / AmneziaWG Decoder

Утилиты для конвертации конфигураций AmneziaWG и ссылок `vpn://`.

Форк основан на проекте [JB-SelfCompany/awg-decoder](https://github.com/JB-SelfCompany/awg-decoder) и добавляет самодостаточный GUI-декодер для Windows.

## Что умеет

- Декодировать ссылку `vpn://` в файл `NewConfig.conf`.
- Понимать новый JSON-формат экспорта AmneziaVPN и извлекать из него AmneziaWG `.conf`.
- Кодировать `.conf` обратно в ссылку `vpn://`.
- Не перезаписывать существующие файлы: новые файлы получают имена `NewConfig_1.conf`, `NewConfig_2.conf`, `NewLink_1.txt` и так далее.
- Работать как обычный Python-скрипт или как собранное Windows-приложение `.exe`.

## Простой запуск

Самый удобный вариант для пользователя Windows:

1. Запустить `AmneziaVPN Decoder.exe`.
2. Вставить ссылку `vpn://` или использовать ссылку из буфера обмена.
3. Нажать `Создать conf`.

Файл появится рядом с приложением.

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
python simple-awg-decoder.py --encode-file .\Amnezia2.conf
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
