# Проверка и сборка

Нужны Python 3 и Git. Команды из корня публичного проекта:

```powershell
python installer/tests/verify_release_artifacts.py
python installer/tools/prepare_rc10_base.py
```

Пересборка rc11 в отдельном чистом клоне:

```powershell
python installer/build_site_candidate.py --release-rc11
python installer/tests/verify_release_artifacts.py
```

Helper восстанавливает точный ZIP rc10 из локального тега и проверяет SHA256 до записи. Существующий dist/rc11-build намеренно блокирует повтор. Старые результаты не удалять ради повтора. Payload панели переиспользуется побайтно, Go ELF заново не собирается. ZIP может отличаться метаданными времени: проверяются состав и целостность. Эти команды не обращаются к production.

Исторические инструкции installer выполняются из installer/. Для основного публичного тестирования приватный проект не требуется.
