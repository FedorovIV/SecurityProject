import speedtest

def run_speedtest():
    try:
        # Создание объекта Speedtest
        st = speedtest.Speedtest()

        # Загрузка списка серверов
        print("Получение списка серверов...")
        st.get_servers()

        # Выбор оптимального сервера
        print("Выбор наилучшего сервера...")
        best = st.get_best_server()
        print(f"Подключение к серверу: {best['host']} ({best['country']})")

        # Тест скорости скачивания
        print("Тест скорости скачивания...")
        download_speed = st.download()

        # Тест скорости загрузки
        print("Тест скорости загрузки...")
        upload_speed = st.upload()

        # Печать результатов
        print("\nРезультаты спидтеста:")
        print(f"Скорость скачивания: {download_speed / 1_000_000:.2f} Мбит/с")
        print(f"Скорость загрузки: {upload_speed / 1_000_000:.2f} Мбит/с")
        print(f"Пинг: {best['latency']} мс")

    except Exception as e:
        print(f"Ошибка при выполнении спидтеста: {e}")

if __name__ == "__main__":
    run_speedtest()
