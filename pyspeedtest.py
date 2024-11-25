import pyspeedtest

st = pyspeedtest.st

print(f"Пинг: {st.ping():.2f} мс")
print(f"Скорость загрузки: {st.download() / 1_000_000:.2f} Мбит/с")
print(f"Скорость выгрузки: {st.upload() / 1_000_000:.2f} Мбит/с")
