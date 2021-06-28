import os
from datetime import datetime

dirname = os.path.dirname(__file__)


def lloogg(s, x):
    if s == "b":
        print('--------------------------------------------')
        print(f'{x}')
        print('--------------------------------------------')
    if s == "s":
        print(f'{x}')


def date_string(x):
    lloogg("s", "Date returned")
    if x == 'stamp':
        return datetime. now(). strftime("_%d_%m_%Y_%I:%M:%S_%p")
    if x == 'homelog':
        return datetime. now(). strftime("%I:%M, %B %d, %Y")

# returns a dict with all files in the docx dir without extention


def file_dict(dir):
    lloogg("s", "Traversing dir folder : - Started")
    path = os.path.join(dirname, dir)
    dir_list = os.listdir(path)
    dict_dir = []
    for item in dir_list:
        if item.endswith(".docx"):
            doc = item.split(".")[0]
            dict_dir.append(doc)
    print(dict_dir)
    lloogg("b", "Traversing dir folder : - Finished")
    return dict_dir


def group_dicts():
    path = os.path.join(dirname, 'docx')
    group_list = os.listdir(path)
    lloogg("b", "Retriving Template groups : - started")
    group_dict = []
    x = 1
    for item in group_list:
        check_path = os.path.join(dirname, 'docx', item)
        if os.path.isdir(check_path):
            group_dict.append(item)
    return group_dict


def template_dict():
    template_dict = {}
    group_dict = group_dicts()
    for dirs in group_dict:
        path = os.path.join(dirname, 'docx', dirs)
        file_dict1 = file_dict(path)
        template_dict[dirs] = file_dict1
    return template_dict



