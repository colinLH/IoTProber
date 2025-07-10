import os
import sys
import ast
import logging

sys.path.append(os.path.dirname(os.getcwd()))

from subprocess import check_output, STDOUT


def change_log_file(new_log_path):
    """
    动态地更改日志记录的文件路径。

    Args:
        new_log_path (str): 新的日志文件完整路径。
    """
    logger = logging.getLogger()

    old_handler = None
    for handler in logger.handlers:
        if isinstance(handler, logging.FileHandler):
            old_handler = handler
            logger.removeHandler(handler)
            handler.close()
            break

    if old_handler is None:
        print("Warnings: No active FileHandler found!")

    new_handler = logging.FileHandler(new_log_path, mode='a', encoding='utf-8')

    log_format = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
    new_handler.setFormatter(log_format)

    logger.addHandler(new_handler)

    print(f"Log file has changed to: {new_log_path}")


def hex_to_bit_list(hex_value):
    # 将十六进制数转换为二进制，并去掉前缀 '0b'
    binary_value = bin(hex_value)[2:].zfill(16)  # zfill(16) 确保输出为16位

    # 将二进制字符串转换为比特位列表
    bit_list = [int(bit) for bit in binary_value]

    return bit_list


def write_list_to_file(filepath, data_list):
    with open(filepath, 'w', encoding='utf-8') as f:
        for item in data_list:
            f.write(f"{item}\n")


def execute(command):
    """
    Executes a command on the local host.
    :param str command: the command to be executedi
    :return: returns the output of the STDOUT or STDERR
    """
    print("Shell command : {}".format(command))
    # command = "{}; exit 0".format(command)
    return check_output(command, stderr=STDOUT, shell=True).decode("utf-8")


def list_files_in_folder(directory: str):
    """
    列出目录下所有的文件路径
    :param directory:
    :return:
    """
    all_file_path = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            all_file_path.append(os.path.join(root, file))
    return all_file_path


def get_subdirectories_os(parent_dir):
    if not os.path.isdir(parent_dir):
        print(f"错误: '{parent_dir}' 不是一个有效的目录或不存在。")
        return []

    subdirectories = []
    for name in os.listdir(parent_dir):
        full_path = os.path.join(parent_dir, name)
        if os.path.isdir(full_path):
            subdirectories.append(name)

    return subdirectories


def get_filename_without_extension(file_path):
    return os.path.splitext(os.path.basename(file_path))[0]


def read_list_from_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f.readlines()]


def read_tuple_list_from_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        return [ast.literal_eval(line.strip()) for line in f.readlines()]


def check_extension(file_path: str, extension: str) -> bool:
    # 获取文件的后缀名
    _, ext = os.path.splitext(file_path)

    # 检查是否是 .csv 后缀
    if ext.lower() == extension:
        return True
    else:
        return False


def split_list_by_size(lst, size=2000):
    return [lst[i:i + size] for i in range(0, len(lst), size)]


def decode_mixed_logs(raw: bytes) -> str:
    results = []

    try:
        results.append(raw.decode('utf-8'))
    except UnicodeDecodeError:
        pass  # 继续按字节扫描

    # 查找 UTF-8 解码失败点
    for i in range(len(raw)):
        try:
            prefix = raw[:i].decode('utf-8')
            suffix = raw[i:].decode('gbk')
            return prefix + suffix
        except UnicodeDecodeError:
            continue

    return repr(raw)


def process_labels(labels):
    processed = []
    for label in labels:
        # 去除末尾的 \r 和 \n
        clean_label = label.rstrip('\r\n')
        # 如果长度超过30，按每30字符加一个换行
        if len(clean_label) > 30:
            # 将字符串按每30字符分段并插入换行
            chunks = [clean_label[i:i+30] for i in range(0, len(clean_label), 30)]
            clean_label = '\n'.join(chunks)
        processed.append(clean_label)
    return processed