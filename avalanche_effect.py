import os
import itertools
import argparse
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def read_ciphertexts_from_files(file_paths):
    """
    Читает шифротексты из списка файлов.

    :param file_paths: Список путей к файлам с шифротекстами.
    :return: Список байтовых строк шифротекстов.
    """
    ciphertexts = []
    for path in file_paths:
        with open(path, 'rb') as file:
            ciphertexts.append(file.read())
    return ciphertexts

def read_ciphertexts_from_strings(ciphertext_strings):
    """
    Преобразует список строковых шифротекстов в байтовые строки.

    :param ciphertext_strings: Список строковых представлений шифротекстов (например, в hex).
    :return: Список байтовых строк шифротекстов.
    """
    ciphertexts = [bytes.fromhex(s) for s in ciphertext_strings]
    return ciphertexts

def hamming_distance(b1, b2):
    """
    Вычисляет Хэммингово расстояние между двумя байтовыми строками.

    :param b1: Первая байтовая строка.
    :param b2: Вторая байтовая строка.
    :return: Хэммингово расстояние.
    """
    if len(b1) != len(b2):
        raise ValueError("Длины шифротекстов должны совпадать.")
    return sum(bin(byte1 ^ byte2).count('1') for byte1, byte2 in zip(b1, b2))

def compute_all_hamming_distances(ciphertexts):
    """
    Вычисляет Хэмминговы расстояния между всеми парами шифротекстов.

    :param ciphertexts: Список байтовых строк шифротекстов.
    :return: Список кортежей (индекс1, индекс2, расстояние).
    """
    distances = []
    indices = range(len(ciphertexts))
    for i, j in itertools.combinations(indices, 2):
        dist = hamming_distance(ciphertexts[i], ciphertexts[j])
        distances.append((i, j, dist))
    return distances


def analyze_and_visualize(distances):
    """
    Проводит статистический анализ и визуализирует результаты
    без использования seaborn.
    
    :param distances: Список кортежей (индекс1, индекс2, расстояние).
    """
    # Извлекаем значения расстояний
    distance_values = [d[2] for d in distances]
    
    # Вычисление среднего значения и дисперсии
    average_distance = sum(distance_values) / len(distance_values)
    variance = sum((x - average_distance) ** 2 for x in distance_values) / len(distance_values)
    
    print(f"Среднее Хэммингово расстояние: {average_distance}")
    print(f"Дисперсия Хэммингового расстояния: {variance}")
    
    # Построение гистограммы
    plt.figure(figsize=(10, 6))
    plt.hist(distance_values, bins=20, edgecolor='black', alpha=0.7)
    plt.title("Распределение Хэмминговых расстояний между шифротекстами")
    plt.xlabel("Хэммингово расстояние")
    plt.ylabel("Частота")
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.show()
    
    # Построение тепловой карты матрицы расстояний
    num_texts = max(max(d[0], d[1]) for d in distances) + 1
    distance_matrix = [[0] * num_texts for _ in range(num_texts)]
    
    for i, j, dist in distances:
        distance_matrix[i][j] = dist
        distance_matrix[j][i] = dist  # Матрица симметрична
    
    plt.figure(figsize=(8, 6))
    plt.imshow(distance_matrix, cmap='viridis', interpolation='nearest')
    plt.colorbar(label="Хэммингово расстояние")
    plt.title("Матрица Хэмминговых расстояний между шифротекстами")
    plt.xlabel("Индекс шифротекста")
    plt.ylabel("Индекс шифротекста")
    plt.show()


def generate_ciphertexts(message:str):
    def bit_flip(byte_array, bit_position):
        byte_index = bit_position // 8
        bit_index = bit_position % 8
        byte_array[byte_index] ^= 1 << bit_index
        return byte_array
    
    if isinstance(message, str):
        message = message.encode()

    key = os.urandom(16)  # 128-битный ключ для AES
    cipher = Cipher(algorithms.AES(key), modes.ECB())

    # Дополнение до длины, кратной 16 байтам
    padding_length = 16 - (len(message) % 16)
    padded_message = message + b' ' * padding_length

    key = os.urandom(16)  # 128-битный ключ для AES
    iv = os.urandom(16)   # 128-битный вектор инициализации
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

    # Генерация шифротекста для исходного сообщения
    encryptor = cipher.encryptor()
    original_ciphertext = encryptor.update(padded_message) + encryptor.finalize()

    # Генерация шифротекстов для сообщений с инвертированным битом
    ciphertexts = [original_ciphertext.hex()]
    for bit_pos in range(len(padded_message) * 8):
        modified_message = bytearray(padded_message)
        bit_flip(modified_message, bit_pos)
        encryptor = cipher.encryptor()
        modified_ciphertext = encryptor.update(bytes(modified_message)) + encryptor.finalize()
        ciphertexts.append(modified_ciphertext.hex())

    return ciphertexts


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("message", type=str)
    args = parser.parse_args()

    print(args.message)
    ciphertext_strings = generate_ciphertexts(args.message)
    
    ciphertexts = read_ciphertexts_from_strings(ciphertext_strings)
    
    # Проверка на одинаковую длину шифротекстов
    lengths = [len(ct) for ct in ciphertexts]
    if len(set(lengths)) != 1:
        raise ValueError("Все шифротексты должны быть одной длины.")
    
    # Вычисление Хэмминговых расстояний
    distances = compute_all_hamming_distances(ciphertexts)
    
    # Анализ и визуализация
    analyze_and_visualize(distances)

if __name__ == "__main__":
    main()
