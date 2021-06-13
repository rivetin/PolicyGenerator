import json
import os
from pprint import pprint
from docxtpl import DocxTemplate
dirname = os.path.dirname(__file__)

json_path = os.path.join(dirname, 'static', 'json',
                         'don-dadless_13_06_2021_124956_AM.json')
json_file = open(json_path, 'r')
json_obj = json.load(json_file)

project_name = json_obj['project_name']
common_fields_obj = json_obj['common_fields']
specific_fields = {}
for key, value in json_obj['specific_fields'].items():
    x = 1

template_path = os.path.join(dirname, 'template.docx')


def json2dx_common(template, common_fields_obj, dummy_image_name, new_image_name, doc_file_name):
    doc = DocxTemplate(template)
    context = common_fields_obj
    doc.replace_pic(dummy_image_name, new_image_name)
    doc.render(context)
    doc.save(doc_file_name)
    print('Generated!')


json2dx_common(template_path, common_fields_obj, 'Picture 1', '22.jpg', 'brand.docx')
