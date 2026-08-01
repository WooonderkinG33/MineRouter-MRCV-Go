# MRCV — MineRouter Crypto Vault (Go)

**Device-Bound Cryptocontainer**

Go-реализация MRCV — побайтово совместима с
[`@minerouter/mrcv`](https://github.com/WooonderkinG33/MineRouter-MRCV) (Node/Electron).

```
XChaCha20-Poly1305 + Argon2id encrypted KV storage
Cryptographically bound to a device
```

Файл `.mrcv`, созданный в Electron, открывается в Go, и наоборот —
формат, криптография и device-binding полностью идентичны.

## Почему MRCV

Традиционные зашифрованные файлы можно скопировать и открыть где угодно,
если есть ключ. MRCV решает это через **device binding**: хранилище
криптографически привязано к устройству, для которого создано, и не
открывается на другой машине.

```
┌──────────────────────────────────────────────┐
│  .mrcv file                                  │
│                                              │
│  Header (84 bytes, AEAD-protected)           │
│  ├─ BindingId (SHA-256 of device binding)    │
│  ├─ Salt + Nonce                             │
│  └─ Flags (mode, format)                     │
├──────────────────────────────────────────────┤
│  Payload (XChaCha20-Poly1305 encrypted JSON) │
└──────────────────────────────────────────────┘
```

**Ключевые свойства:**
- **Device-bound** — открывается только на устройстве с совпадающим BindingId
- **Два режима** — `bound` (при несовпадении файл сохраняется) или `strict`
  (самоуничтожение при несовпадении)
- **Без паролей** — ключ выводится из device binding (Argon2id)
- **Один файл** — всё в одном `.mrcv`
- **AEAD** — заголовок привязан к шифротексту через Poly1305

## Совместимость с JS-версией

| Параметр | JS (libsodium) | Go |
|----------|----------------|-----|
| KDF | Argon2id, iter=3, mem=256MB | `argon2.IDKey` (те же) |
| Шифр | XChaCha20-Poly1305, nonce 24 | `chacha20poly1305.NewX` |
| AAD | заголовок 84 байта | тот же |
| Binding | SHA-256(mobo UUID \| disk serial \| [MAC]) | тот же |
| Формат файла | `MRCV` + version + flags + salt + nonce + bindingId + ct + tag | побайтово тот же |

**Проверено кросс-тестами в обе стороны:**

- `compatibility_test.go` — открывает **реальный файл, созданный `@minerouter/mrcv`**
  (v2.0.2, фикстура в `testdata/js-vault.mrcv`) и сверяет binding-вектор
  байт-в-байт. Запускается обычным `go test ./...`.
- `scripts/cross-node.sh` — обратное направление: Go создаёт vault,
  Node.js читает его. Требует `npm i @minerouter/mrcv` локально.

### «Меняю Node-версию — надо менять Go?»

Да, если изменение касается **формата файла или криптографии**:
magic/version/смещения полей, параметры Argon2id (iter/memory/parallelism),
шифр/AAD. Любое из них ломает совместимость — обе реализации обязаны
меняться вместе, иначе старые файлы перестанут открываться.

Что можно менять **независимо**: только API обёртки, логика вызова,
дополнительные методы — всё, что не влияет на байты `.mrcv` на диске.

Правило: **формат = контракт**. Меняется только с осознанием, что это
ломающее изменение для всех пользователей обеих реализаций.

## Установка

```sh
go get github.com/WooonderkinG33/MineRouter-MRCV-Go
```

Зависимость: только `golang.org/x/crypto` (официальная, Argon2id + XChaCha20).

## Использование

```go
import "github.com/WooonderkinG33/MineRouter-MRCV-Go"

// Открыть хранилище (создаст, если нет), привязанное к устройству.
v, err := mrcv.New(mrcv.Config{Path: "storage.mrcv"})
if err != nil { /* ... */ }

res, err := v.Open()
if err != nil { /* ... */ }
switch res.State {
case "unlocked":
    // хранилище привязано к ЭТОМУ устройству
case "mismatch":
    // файл создан на другом устройстве — не открываем
}

v.Set("client_key", "hex...")
v.Set("nested", map[string]interface{}{"a": 1})
if err := v.Save(); err != nil { /* ... */ }
```

### Конфигурация

| Поле | Дефолт | Зачем |
|------|--------|-------|
| `Path` | `~/.config/@minerouter/mrcv/storage.mrcv` | где хранить |
| `Mode` | `bound` | `bound` (сохранить) / `strict` (уничтожить) |
| `BindingSources` | mobo UUID + disk serial (+ MAC на VM) | свой отпечаток устройства |
| `Memory` | 256 MiB | Argon2id память |
| `Iterations` | 3 | Argon2id итерации |

### API

```go
Open()      (OpenResult, error) // привязка + открыть/создать
Unlock()    error               // расшифровать payload
Lock()                          // очистить ключи из памяти
Save()      error               // записать на диск
Get(k)      interface{}
Set(k, v)   // не сохраняет до Save()
Delete(k)
Has(k)      bool
Keys()      []string
IsOpen() / IsUnlocked() bool
```

## Структура

```
binding.go   device fingerprint (mobo UUID, disk serial, MAC на VM) -> SHA-256
crypto.go    Argon2id + XChaCha20-Poly1305 (AEAD, AAD = header)
storage.go   формат .mrcv побайтово (84-байт header)
vault.go     публичный API (Open/Unlock/Get/Set/Save, bound/strict)
types.go     Config, Mode, BindingSource, ошибки
vault_test.go тесты: roundtrip, формат, strict/bound, подделка файла
```

## Тесты

```sh
go test ./...
```

- roundtrip create → save → open → read
- header layout (магия, смещения полей, reserved-байты)
- strict уничтожает файл при несовпадении binding
- bound сохраняет файл при несовпадении
- подделанный шифротекст не расшифровывается

> Argon2id с 256 MiB делает каждый Open/Unlock ~1-3 сек — это ожидаемо
> (та же стоимость, что в Electron).

## Лицензия

MIT
