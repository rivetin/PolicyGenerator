import json
import os
import shutil
from pprint import pprint
from docxtpl import DocxTemplate
from werkzeug.utils import secure_filename


def generate_zip(name):

    dirname = os.path.dirname(__file__)
    json_path = os.path.join(dirname, 'static', 'json', name)

    if(os.path.isfile(json_path)):
        json_file = open(json_path, 'r')
        json_obj = json.load(json_file)
    else:
        return (False, False)

    # all_json_list = [f for f in os.listdir(
    #     dirname) if os.path.isfile(os.path.join(dirname, f))]

    def get_temp_list():
        doc_list = []
        for key, value in json_obj['specific_fields'].items():
            doc_list.append(key)
        return doc_list

    def json2dx_common(template_name, dummy_image_name, new_image_name):
        template_path = os.path.join(dirname, 'docx', template_name)
        common_fields_obj = json_obj['common_fields']
        specific_fields_obj = json_obj['specific_fields'][template_name]

        all_fields_obj = common_fields_obj.copy()

        specific_fields_obj = {k: v for k,
                               v in specific_fields_obj.items() if v}
        all_fields_obj.update(specific_fields_obj)

        doc = DocxTemplate(template_path)
        doc.replace_pic(dummy_image_name, new_image_name)
        doc.render(all_fields_obj)
        path = os.path.join(dirname, 'temp', 'vm_' + template_name)
        doc.save(path)

    ##main##

    if not os.path.exists(dirname+'/temp'):
        os.makedirs(dirname+'/temp')

    for tpl in get_temp_list():
        dummy_image_name = 'Picture 1'
        new_image_name = os.path.join(
            dirname, 'instance/uploads', json_obj['common_fields']['filename'])
        json2dx_common(tpl, dummy_image_name, new_image_name)

    if not os.path.exists('zips'):
        os.makedirs('zips')
    zip_name = secure_filename(json_obj['project_name'])
    zip_path = 'zips/zip_'+zip_name
    shutil.make_archive(zip_path, 'zip', 'temp')
    shutil.rmtree('temp')
    zip_path = os.path.join(dirname, 'zips')
    print(zip_path)
    print(zip_name)

    return (zip_path, 'zip_'+zip_name+'.zip')
