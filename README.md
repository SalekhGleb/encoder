# Encoder/Decoder Application

Приложение для шифрования и дешифрования текста с использованием алгоритма AES-256 в режиме CBC. Доступно на английском и русском языках, с консольным и графическим интерфейсом.


## Особенности

- **Шифрование/дешифрование текста** с использованием AES-256-CBC.
- **Поддержка двух языков**: английский и русский.
- **Два интерфейса**: консольный и графический (GUI).
- **Генерация случайных ключей** длиной 32 символа (латиница, цифры, спецсимволы, кириллица).
- **История операций** с возможностью очистки.
- **Смена темы**: светлая и тёмная.
- **Сохранение настроек** и истории между сессиями.

## Требования

- Python 3.6+
- Установленные зависимости (см. ниже)

## Установка

- Клонируйте репозиторий:
   ```
   git clone https://github.com/SalekhGleb/encoder.git
   cd encoder
- Установите зависимости:

  ```
   pip install cryptography ttkbootstrap
Использование
Консольные версии
Английская версия:

    python en_main.py
Русская версия:

    python ru_main.py
Графические версии (GUI)
    Английская версия:

    python en_main_graph.py
Русская версия:

    python ru_main_graph.py
## Инструкция для GUI
- **Шифрование:**

Введите текст во вкладке "Encrypt" (или "Зашифровать").

Укажите ключ или сгенерируйте его.

Нажмите "Encrypt" (или "Зашифровать").

- **Дешифрование:**

Вставьте зашифрованный текст в формате Base64 во вкладке "Decrypt" (или "Расшифровать").

Введите ключ.

Нажмите "Decrypt" (или "Расшифровать").

- **История:**

Просматривайте историю операций во вкладке "History" (или "История").

Очищайте историю кнопкой "Clear History" (или "Очистить историю").

_______________________________________________________________

# Encoder/Decoder Application

An application for text encryption and decryption using the AES-256 algorithm in CBC mode. Available in English and Russian, with a console and graphical interface.


## Features

- **Text encryption/decryption** using AES-256-CBC.
- **Two languages are supported**: English and Russian.
- **Two interfaces**: console and GUI.
- **Generation of random keys** 32 characters long (Latin, numbers, special characters, Cyrillic).
- **Operation history** with the possibility of cleaning.
- **Theme change**: light and dark.
- **Save settings** and history between sessions.

## Requirements

- Python 3.6+
- Installed dependencies (see below)

## Installation

- Clone the repository:
   ```
   git clone https://github.com/SalekhGleb/encoder.git
   cd encoder
- Install dependencies:

  ```
   pip install cryptography ttkbootstrap
Using
Console versions
English version:

    python en_main.py
Russian version:

    python ru_main.py
Graphical Versions (GUI)
English version:

    python en_main_graph.py
Russian version:

    python ru_main_graph.py
## GUI Instructions
- **Encryption:**

Enter the text in the "Encrypt" (or "Encrypt") tab.

Specify the key or generate it.

Click "Encrypt" (or "Encrypt").

- **Decryption:**

Paste the encrypted text in Base64 format in the "Decrypt" (or "Decrypt") tab.

Enter the key.

Click "Decrypt" (or "Decrypt").

- **History:**

View the operation history in the "History" tab (or "History").

Clear the history with the "Clear History" button (or "Clear History").
