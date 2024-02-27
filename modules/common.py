import re


def _init():
    global _global_dict
    _global_dict = {}


def set_value(key, value):
    _global_dict[key] = value


def get_value(key):
    try:
        return _global_dict[key]
    except:
        return False


def get_target_list(path):
    target_list = []
    try:
        for target in open(path, 'r', errors='ignores').readlines():
            target = target.replace('\n', '')
            if re.search("https?://.+", target): target_list.append(target.replace('\n', ''))
        return target_list
    except:
        return []


import os, importlib
import platform


def get_dir_files(base_path):  # 递归调用pocs目录下文件返回每条poc的绝对路径
    file_list = []
    if os.path.isdir(base_path):
        for each_file_or_dir in os.listdir(base_path):
            current_path = os.path.join(base_path, each_file_or_dir)
            if os.path.isfile(current_path) and each_file_or_dir.split('.')[-1] != 'py':  # 只加载py形式的poc文件
                continue
            each_path = get_dir_files(current_path)
            for file in each_path:
                file_list.append(file)
    else:
        file_list.append(base_path)
    return file_list


def path_to_modolepath(path):  # 传入相对路径返回模块导入路径
    if 'Windows' in platform.system():
        path = path.lstrip('\\')
        modole_path = path.replace('\\', '.')
    else:
        path = path.lstrip('/')
        modole_path = path.replace('/', '.')
    modole_path = modole_path.replace('.py', '')
    return modole_path


def get_filename_by_path(path):  # 根据路径获取文件名
    if 'Windows' in platform.system():
        filename = path.split('\\')[-1]
    else:
        filename = path.split('/')[-1]
    return filename


def get_poc_modole_list():  # 调用此函数获取 /pocs 下的全部 poc
    poc_module_list = []
    current_path = os.path.abspath('.')
    pocs_base_path = os.path.join(current_path, 'vuln')  # 获取poc路径
    poc_path_list = get_dir_files(pocs_base_path)  # 递归调用pocs目录下文件返回每条poc的绝对路径
    for poc_path in poc_path_list:
        poc_path = poc_path.replace(current_path, '')  # 正则过滤目录头
        poc_modole_path = path_to_modolepath(poc_path)  # 传入相对路径返回模块导入路径
        try:
            poc_module_list.append(importlib.import_module(poc_modole_path))
        except:
            pass
    return poc_module_list


def get_pocinfo_dict():  # 获取pocinfo字典
    pocinfo_dict = {}
    current_path = os.path.abspath('.')
    pocs_base_path = os.path.join(current_path, 'vuln')
    poc_path_list = get_dir_files(pocs_base_path)
    for poc_path in poc_path_list:
        poc_path = poc_path.replace(current_path, '')
        poc_modole_path = path_to_modolepath(poc_path)
        try:
            script_name = get_filename_by_path(poc_path)
            poc_modole = importlib.import_module(poc_modole_path)
            if poc_modole.poc:
                pocinfo_dict[script_name] = poc_modole
        except:
            pass
    return pocinfo_dict


def get_poc_scriptname_list_by_search(path, search_keys_list):     # 此函数通过搜索poc文件名调用相应的poc, 传入poc文件名列表, 返回由poc对象的列表
    search_flag = True if len(search_keys_list) > 0 else False
    poc_scriptname_list = []
    current_path = os.path.abspath('.')
    pocs_base_path = os.path.join(current_path, path)
    poc_path_list = get_dir_files(pocs_base_path)
    if not search_flag:
        for poc_path in poc_path_list:
            script_name = get_filename_by_path(poc_path.replace(current_path, ''))
            if script_name in get_value("pocinfo_dict").keys():
                poc_scriptname_list.append(get_filename_by_path(poc_path.replace(current_path, '')))
        return poc_scriptname_list
    for search_key in search_keys_list:
        for poc_path in poc_path_list:
            script_name = get_filename_by_path(poc_path.replace(current_path, ''))
            if search_key == script_name and search_flag:
                if script_name in get_value("pocinfo_dict").keys():
                    print('成功检测到poc文件: {0}'.format(script_name))
                    poc_scriptname_list.append(script_name)
                    search_flag = False
                    break
                else:
                    search_flag = True
                    print('加载失败: {0}'.format(search_key))
                    break
        if search_flag:
            print('未检测到poc文件: {0}'.format(search_key))
        search_flag = True
    return poc_scriptname_list


def do_path(path):
    base_path = "vuln"
    if path:
        if "\\" in path or "/" in path:
            if 'Windows' in platform.system():
                path = path.replace("/", "\\")
            else:
                path = path.replace('\\', "/")
            if path[0] == "/":
                path = path.lstrip("/")
            return path, []
        else:
            return base_path, path.split(',')
    else:
        return base_path, []
