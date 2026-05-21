# CursorKripta

Минимальный Java/Maven-проект для выполнения задания по постквантовой цифровой
подписи XMSSMT с использованием Bouncy Castle.

Программа:

1. подключает провайдеры `BouncyCastlePQCProvider` и `BouncyCastleProvider`;
2. генерирует пару ключей XMSSMT с параметрами `height=20`, `layers=10`,
   `SHA256`;
3. подписывает выбранное латинское сообщение алгоритмом `SHA256withXMSSMT`;
4. проверяет созданную подпись;
5. создает самоподписанный X.509-сертификат на один месяц;
6. сохраняет три файла для отправки на проверку:
   - `outputs/certificate.cer` — сертификат в DER-формате;
   - `outputs/message.txt` — исходное сообщение;
   - `outputs/signature.hex` — подпись сообщения в hex-формате.

## Запуск

```bash
mvn compile exec:java
```

По умолчанию используются демонстрационные данные владельца сертификата:

- CN: `Student Name`
- E-mail: `student@kais.isu.ru`

При необходимости их можно заменить параметрами командной строки:

```bash
mvn compile exec:java -Dexec.args="--cn 'Ivan Ivanov' --email 'ivan@example.com' --message 'My latin message'"
```

Файлы будут созданы в каталоге `outputs`. Для изменения каталога добавьте
параметр `--out`, например:

```bash
mvn compile exec:java -Dexec.args="--out result"
```
