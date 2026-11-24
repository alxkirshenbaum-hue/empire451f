# Проверка rc10

Из корня проекта выполните:

```powershell
python -m zipfile -t installer/dist/installer.zip
Get-FileHash installer/dist/installer.zip -Algorithm SHA256
Get-Content installer/dist/installer.sha256
```

SHA должен совпасть с сохранённой суммой. Исходники принятых компонентов сохраняются без функциональных изменений; операции на серверах не выполняются. Разработка и инструкция пересборки rc11 — в work. Исторические команды installer запускаются из installer/.
