from flask_wtf import Form
from wtforms.fields import *
from wtforms.validators import Required

class CurateForm(Form):
    ecosystem = SelectField(u'Ecosystem', choices=[('pypi', 'PyPI'), ('npm', 'NPM'),
                                                   ('go', 'Golang'), ('none', 'None')])
    name = TextField(u'Package/VCS URI', validators=[Required()])
    version = TextField(u'Version')
    distro = SelectField(u'Distribution', choices=[('', ''), ('fedora-25-x86_64', 'Fedora 25 x86_64'), ('centos-7-x86_64','RHEL 7 x86_64')])
    submit = SubmitField(u'Curate')

class NewAnalysisForm(Form):
    name = TextField("Name", validators=[Required()])
    version = TextField("Version", validators=[Required()])
