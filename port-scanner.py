import socket
import threading
from queue import Queue
import time
from datetime import datetime

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Proxy",
}


def print_banner():
    print("Простой многопоточный сканер открытых портов")
    print("ВАЖНО: Сканируйте ТОЛЬКО те хосты, на которые у вас есть разрешение!")
    print("Сканирование чужих серверов без согласия незаконно.")
    print()


def scan_port(target, port, open_ports):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)  # таймаут 1 секунда
        result = sock.connect_ex((target, port))

        if result == 0:
            service = COMMON_PORTS.get(port, "Неизвестный")
            msg = f"[+] Порт {port:5d} открыт → {service}"
            print(msg)
            open_ports.append((port, service))

        sock.close()
    except Exception:
        pass


def main():
    print_banner()

    target = input("Введите IP или домен для сканирования (например, 127.0.0.1 или scanme.nmap.org): ").strip()
    if not target:
        print("Цель не указана. Выход.")
        return

    mode = input(
        "Режим сканирования? [1] Топ-30 портов (быстро) / [2] Диапазон портов (медленнее) [1/2]: ").strip() or "1"

    ports = []
    if mode == "1":
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723,
                 3306, 3389, 5900, 8080, 8443, 1433, 1521, 5432, 27017, 5000, 9200, 11211, 6379, 7547, 8291]
        print(f"Сканируем топ-30 популярных портов...")
    else:
        try:
            start = int(input("Начальный порт (по умолчанию 1): ") or 1)
            end = int(input("Конечный порт (по умолчанию 1024): ") or 1024)
            ports = list(range(start, end + 1))
            print(f"Сканируем диапазон портов {start}-{end}...")
        except ValueError:
            print("Ошибка ввода диапазона. Выход.")
            return

    print(f"Цель: {target}")
    print(f"Портов к сканированию: {len(ports)}")
    print("-" * 60)

    start_time = time.time()
    open_ports = []
    queue = Queue()

    for port in ports:
        queue.put(port)

    def worker():
        while not queue.empty():
            port = queue.get()
            scan_port(target, port, open_ports)
            queue.task_done()

    thread_count = 50
    for _ in range(thread_count):
        t = threading.Thread(target=worker, daemon=True)
        t.start()

    queue.join()

    elapsed = time.time() - start_time
    print("-" * 60)
    print(f"Сканирование завершено за {elapsed:.2f} секунд")

    if open_ports:
        print(f"\nНайдено открытых портов: {len(open_ports)}")
        for port, service in sorted(open_ports):
            print(f"  {port:5d} → {service}")

        filename = f"open_ports_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M')}.txt"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"Скан {target} от {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Открытых портов: {len(open_ports)}\n\n")
            for port, service in sorted(open_ports):
                f.write(f"{port:5d} → {service}\n")
        print(f"Результаты сохранены в: {filename}")
    else:
        print("Открытых портов не найдено.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nСканирование прервано пользователем.")
    except Exception as e:
        print(f"Произошла ошибка: {e}")
