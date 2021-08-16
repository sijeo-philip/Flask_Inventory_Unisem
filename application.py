from flask import Flask, render_template, request, flash, url_for, redirect
from flask_wtf import FlaskForm
import wtforms
from wtforms import StringField, IntegerField, SelectField, FloatField, TextAreaField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length, ValidationError, Email
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import os
##import mysql.connector
##import json


#mydb = mysql.connector.connect(
   # host = "localhost",
   # user = "unisem",
   # password = "unisem123",
   # database = "unisem_inventory_1"
#)

#myCursor = mydb.cursor()

#def msqlFetch(id):
 #   print("ID: ",id)
 #   sql = "SELECT * from components_list WHERE BinNo="+str(id)
 #   myCursor.execute(sql)
 #   result = myCursor.fetchall()
 #   return result

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'secret key undisclosed'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


'''
projectName Variable needs to be populated from the Database once the database is connected
and used. It should be list of tuples i.e.(A, B) where A should be the value that will be posted
to the python function and Integer is expected, B should be the name of the project which will be
given as a choice to the user for selecting the project for each project.
'''
Bins = [("A1","A1"),("A2","A2"),("A3","A3"),("A4","A4"),("A5","A5"),("A6","A6"),("A7","A7"),("A8","A8"),("A9","A9"),("A10","A10"),
        ("A11","A11"),("A12","A12"),("A13","A13"),("B1","B1"),("B2","B2"),("B3","B3"),("B4","B4"),("B5","B5"),("B6","B6"),("B7","B7"),
        ("B8","B8"),("B9","B9"),("B10","B10"),("B11","B11"),("B12","B12"),("B13","B13"),("C1","C1"),("C2","C2"),("C3","C3"),("C4","C4"),
        ("C5","C5"),("C6","C6"),("C7","C7"),("C8","C8"),("C9","C9"),("C10","C10"),("C11","C11"),("C12","C12"),("C13","C13"),("D1","D1"),
        ("D2","D2"),("D3","D3"),("D4","D4"),("D5","D5"),("D6","D6"),("D7","D7"),("D8","D8"),("D9","D9"),("D10","D10"),("D11","D11"),
        ("D12","D12"),("D13","D13"),("E1","E1"),("E2","E2"),("E3","E3"),("E4","E4"),("E5","E5"),("E6","E6"),("E7","E7"),("E8","E8"),
        ("E9","E9"),("E10","E10"),("E11","E11"),("E12","E12"),("E13","E13"),("F1","F1"),("F2","F2"),("F3","F3"),("F4","F4"),("F5","F5"),
        ("F6","F6"),("F7","F7"),("F8","F8"),("F9","F9"),("F10","F10"),("F11","F11"),("F12","F12"),("F13","F13"),("G1","G1"),("G2","G2"),
        ("G3","G3"),("G4","G4"),("G5","G5"),("G6","G6"),("G7","G7"),("G8","G8"),("G9","G9"),("G10","G10"),("G11","G11"),("G12","G12"),
        ("G13","G13"),("H1","H1"),("H2","H2"),("H3","H3"),("H4","H4"),("H5","H5"),("H6","H6"),("H7","H7"),("H8","H8"),("H9","H9"),
        ("H10","H10"),("H11","H11"),("H12","H12"),("H13","H13"),("I1","I1"),("I2","I2"),("I3","I3"),("I4","I4"),("I5","I5"),("I6","I6"),
        ("I7","I7"),("I8","I8"),("I9","I9"),("I10","I10"),("I11","I11"),("I12","I12"),("I13","I13"),("J1","J1"),("J2","J2"),("J3","J3"),
        ("J4","J4"),("J5","J5"),("J6","J6"),("J7","J7"),("J8","J8"),("J9","J9"),("J10","J10"),("J11","J11"),("J12","J12"),("J13","J13"),
        ("K1","K1"),("K2","K2"),("K3","K3"),("K4","K4"),("K5","K5"),("K6","K6"),("K7","K7"),("K8","K8"),("K9","K9"),("K10","K10"),
        ("K11","K11"),("K12","K12"),("K13","K13"),("L1","L1"),("L2","L2"),("L3","L3"),("L4","L4"),("L5","L5"),("L6","L6"),("L7","L7"),
        ("L8","L8"),("L9","L9"),("L10","L10"),("L11","L11"),("L12","L12"),("L13","L13"),("M1","M1"),("M2","M2"),("M3","M3"),("M4","M4"),
        ("M5","M5"),("M6","M6"),("M7","M7"),("M8","M8"),("M9","M9"),("M10","M10"),("M11","M11"),("M12","M12"),("M13","M13")]

DiodeTypes = [("Bridge","Bridge"),("Current Regulator","Current Regulator"),("General","General"),("Power","Power"),
	     ("Switching","Switching"),("PIN","PIN"),("Rectifier","Rectifier"),("Schottky","Schottky"),("Varactor","Varactor"),
             ("Zener","Zener"),("ESD","ESD"),("TVS","TVS")]

chipPackages = [("TH", "THT"),("EBGA","EBGA"),("FCBGA","FCBGA"),("CSOP","CSOP"),("SOP","SOP"),("SSOP","SSOP"),("TSOP","TSOP"),
                ("QFP","QFP"),("LQFP","LQFP"),("TQFP","TQFP"),("HQFP","HQFP"),("LGA","LGA"),("FLGA","FLGA"),("BCC","BCC"),("DTP","DTP")]


mechanicalComponentTypes = [("SCREWS","SCREWS"),("NUTS","NUTS"),("WIRES","WIRES"),("BOLTS","BOLTS"),("CONNECTORS","CONNECTORS"),
			    ("OTHERS","OTHERS")]


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(80), nullable=False)

class RegisterForm(FlaskForm):
    username = StringField("USERNAME", validators=[DataRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField("PASSWORD", validators=[DataRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    confirm_password = PasswordField("CONFIRM PASSWORD", validators=[DataRequired(), Length(min=4, max=20)], render_kw={"placeholder":"Password"})
    email = StringField("EMAIL", validators=[DataRequired(), Email()])
    submit = SubmitField("REGISTER")
    def validate_username(self, username):
        existing_user_name = User.query.filter_by(username=username.data).first()
        if existing_user_name:
            flash("Username Already Exist! Try another one")
            raise ValidationError("That username already exists, Please choose a different one.")

class LoginForm(FlaskForm):
    username = StringField("USERNAME",validators=[DataRequired(), Length(min=4, max=20)], render_kw={"placeholder":"Username"})
    password = PasswordField("PASSWORD", validators=[DataRequired(), Length(min=4, max=20)], render_kw={"placeholder":"Password"})
    submit = SubmitField("LOGIN")


class ResistorForm(FlaskForm):
    manufacturerPartNo = StringField("MPN*", validators=[DataRequired()])
    resValue = FloatField("VALUE*", validators=[DataRequired()])
    measure = SelectField("UNITS*", validators=[DataRequired()], choices=[('MOhm', 'MOhm'),('KOhm','KOhm'),('Ohm','Ohm'),('mOhm','mOhm')])
    tolerance = IntegerField("TOLERANCE IN %*", validators=[DataRequired()])
    resType = SelectField("TYPE*", validators=[DataRequired()], choices=[("Variable","Variable"),("Network","Network"),("Carbon Film",
									 "Carbon Film"), ("Metal Film","Metal Film"), ("Wirewound",
									  "Wirewound"), ("Metal Oxide", "Metal Oxide"),("Metal Strip",
									  "Metal Strip")])
    resPackage = SelectField("PACKAGE*", validators=[DataRequired()], choices=[("01005","01005"),("0201","0201"),("0402","0402"),
									     ("0603","0603"),("0805","0805"),("1206","1206"),
									     ("1210","1210"),("1812","1812"),("2010","2010"),
									     ("2512","2512"),("TH","TH")])
    wattage = FloatField("WATTS*", validators=[DataRequired()])
    watt_measure = SelectField("UNITS*", validators=[DataRequired()], choices=[("W","W"),("mW","mW")])
    project_id = IntegerField("PROJECT ID*",validators=[DataRequired()])
    manufacturer_name = StringField("MAKE*", validators=[DataRequired()])
    bin_no = SelectField("BIN NUMBER*", validators=[DataRequired()], choices=Bins)
    remark = TextAreaField("COMMENTS")
    quantity = IntegerField("QTY", validators=[DataRequired()])
    submit = SubmitField("ADD ITEM")


class CapacitorForm(FlaskForm):
    manufacturerPartNo = StringField("MPN*", validators=[DataRequired()])
    capValue = FloatField("VALUE*", validators=[DataRequired()])
    measure = SelectField("UNITS*", validators=[DataRequired()], choices=[("pF","pF"),("nF","nF"),("uF","uF"),("mF","mF"),("F","F")])
    tolerance = IntegerField("TOLERANCE IN %*", validators=[DataRequired()])
    dielectric = SelectField("DIELECTRIC*", validators=[DataRequired()], choices=[("Vaccum","Vaccum"),("Air","Air"),("Glass","Glass"),
										("Silicium","Silicium"),("P100","P100"),("NP10","NP10"),
										("N150","N150"),("N220","N220"),("X7R","X7R"),
										("Z5U","Z5U"),("Y5V","Y5V"),("X7S","X7S"),("X5R","X5R"),
										("X8R","X8R"),("Paper","Paper"),("PP","PP"),("PET","PET"),
										("PEN","PEN"),("PPS","PPS"),("PTFE","PTFE"),
										("Elcap","Elcap"),("Tantalum","Tantalum"),
										("Niobium","Niobium")])
    capPackage = SelectField("PACKAGE*", validators=[DataRequired()], choices=[("0201","0201"),("0402","0402"),("0603","0603"),
									      ("0805","0805"),("1206","1206"),
									      ("1210","1210"),("1812","1812"),("CASE A","A"),
									      ("CASE B","B"),("CASE C","C"),("CASE D", "D"),
									      ("CASE E","E"),("TH","TH")])
    voltage = IntegerField("VOLTAGE*", validators=[DataRequired()])
    voltMeasure = SelectField("UNITS*", validators=[DataRequired()],choices=[("Volts","V"),("mV","mV"),("kV","kV")])
    project_id = IntegerField("PROJECT ID*", validators=[DataRequired()])
    manufacturer_name = StringField("MAKE*", validators=[DataRequired()])
    bin_no = SelectField("BIN NUMBER*", validators=[DataRequired()], choices=Bins)
    remark = TextAreaField("COMMENTS")
    quantity = IntegerField("QTY", validators=[DataRequired()])
    submit = SubmitField("ADD ITEM")


class InductorForm(FlaskForm):
    manufacturerPartNo = StringField("MPN*", validators=[DataRequired()])
    indValue = FloatField("VALUE*", validators=[DataRequired()])
    measure = SelectField("UNITS*", validators=[DataRequired()], choices=[("pH","pH"),("nH","nH"),("uH","uH"),("mH","mH"),("H","H")])
    tolerance = IntegerField("TOLERANCE IN %*", validators=[DataRequired()])
    frequency = FloatField("FREQUENCY*", validators=[DataRequired()])
    freq_measure = SelectField("UNITS*",validators=[DataRequired()],choices=[("Hz","Hz"),("KHz","KHz"),("MHz","MHz"),("GHz","GHz")])
    indPackage = SelectField("PACKAGE*", validators=[DataRequired()], choices= [("0201","0201"),("0402","0402"),("0603","0603"),
									      ("0805","0805"),("1206","1206"),
									      ("1210","1210"),("1812","1812"),
									      ("CUSTOM","CUSTOM"),("TH","TH")])
    indDCR = FloatField("DCR")
    measureDCR = SelectField("UNITS", choices=[("MOhm","MOhm"),("KOhm","KOhm"),("Ohm","Ohm"),("mOhm","mOhm")])
    project_id =  IntegerField("PROJECT ID*",validators=[DataRequired()])
    manufacturer_name = StringField("MAKE*", validators=[DataRequired()])
    bin_no = SelectField("BIN NUMBER*", validators=[DataRequired()],choices=Bins)
    remark = TextAreaField("COMMENTS")
    quantity = IntegerField("QTY", validators=[DataRequired()])
    submit = SubmitField("ADD ITEM")

class DiodeForm(FlaskForm):
    manufacturerPartNo = StringField("MPN*", validators=[DataRequired()])
    productType = SelectField("DIODE TYPE*", validators=[DataRequired()], choices=DiodeTypes)
    diodePackage = SelectField("PACKAGE*", validators=[DataRequired()], choices=[("0402","0402"),("0603","0603"),("DFN0603","DFN0603"),
									       ("1005","1005"),("1006","1006"),("SOD923","SOD923"),
									       ("SOD923F","SOD923F"),("1012","1012"),("1205","1205"),
									       ("1208","1208"),("TH","TH"),("MELF","MELF"),
									       ("OTHERS","OTHERS")])
    reverseVolts= FloatField("VR IN VOLTS*", validators=[DataRequired()])
    forwardVolts = FloatField("VF IN VOLTS*", validators=[DataRequired()])
    forwardCurrent = FloatField("FORWARD CURRENT*", validators=[DataRequired()])
    ifMeasure = SelectField("UNITS", validators=[DataRequired()], choices=[("A","A"),("mA","mA"),("uA","uA")])
    project_id = IntegerField("PROJECT ID*", validators=[DataRequired()])
    manufacturer_name = StringField("MAKE*", validators=[DataRequired()])
    bin_no = SelectField("BIN NUMBER*", validators=[DataRequired()],choices=Bins)
    remark = TextAreaField("COMMENTS")
    quantity = IntegerField("QTY", validators=[DataRequired()])
    submit = SubmitField("ADD ITEM")

class TransistorForm(FlaskForm):
    manufacturerPartNo = StringField("MPN*", validators=[DataRequired()])
    productType = SelectField("TRANSISTOR TYPE*", validators=[DataRequired()], choices=[("NPN","NPN"),("PNP","PNP"),
											("NPN and PNP","NPN and PNP")])
    transPackage = SelectField("PACKAGE*", validators=[DataRequired()], choices=[("SMD","SMD"),("TH","TH")])
    transConfiguration = SelectField("CONFIGURATION*", choices=[("Dual","Dual"),("Quad","Quad"),("Quint","Quint"),("Single","Single")])
    collectorEmitterVolts = FloatField("VCEO MAX IN VOLTS*", validators=[DataRequired()])
    collectorBaseVolts = FloatField("VCBO IN VOLTS")
    emitterBaseVolts = FloatField("VEBO IN VOLTS")
    collectorEmitterSat = FloatField("VCESAT*", validators=[DataRequired()])
    VCEsat_measure = SelectField("UNITS*", validators=[DataRequired()], choices=[("V","V"),("mV","mV")])
    collectorCurrent = FloatField("COLLECTOR CURRENT*", validators=[DataRequired()])
    collectorCurrentMeasure = SelectField("UNITS*", validators=[DataRequired()], choices=[("A","A"),("mA","mA"),("uA","uA")])
    powerDissipation = FloatField("POWER DISSIPATION*", validators=[DataRequired()])
    powerDissipationMeasure = SelectField("UNITS*", validators=[DataRequired()],choices=[("uW","uW"),("mW","mW"),("W","W")])
    project_id = IntegerField("PROJECT ID*", validators=[DataRequired()])
    manufacturer_name = StringField("MAKE*", validators = [DataRequired()])
    bin_no = SelectField("BIN NUMBER*", validators=[DataRequired()], choices=Bins)
    remark = TextAreaField("COMMENTS")
    quantity = IntegerField("QTY", validators=[DataRequired()])
    submit = SubmitField("ADD ITEM")

class MOSFETForm(FlaskForm):
    manufacturerPartNo = StringField("MPN*", validators=[DataRequired()])
    productType = SelectField("MOSFET TYPE*", validators=[DataRequired()], choices=[("P-Type","P-Type"),("N-Type","N-Type"),
										   ("P and N Type","P and N Type")])
    mosPackage = SelectField("PACKAGE*", validators=[DataRequired()], choices=[("SMD","SMD"),("TH","TH"),("OTHERS","OTHERS")])
    channels = IntegerField("CHANNELS")
    vdsBreakdown = FloatField("VDSBREAKDOWN IN VOLTS*", validators=[DataRequired()])
    drainCurrent = FloatField("DRAIN CURRENT*", validators=[DataRequired()])
    drainCurrentMeasure = SelectField("UNITS*", validators = [DataRequired()], choices=[("uA","uA"),("mA","mA"),("A","A")])
    rdsON = FloatField("RDSON RESISTANCE*", validators=[DataRequired()])
    rdsONMeasure = SelectField("UNITS*", validators=[DataRequired()], choices=[("uOhm","uOhm"),("mOhm","mOhm"),("Ohm","Ohm"),
                                                                              ("kOhm","kOhm"),("MOhm","MOhm"),("GOhm","GOhm")])
    gateSourceVolt = FloatField("VGS VOLTAGE*", validators=[DataRequired()])
    gateSourcVoltMeasure = SelectField("UNITS*", validators=[DataRequired()],choices=[("mV","mV"),("V","V")])
    gateSourceThresholdVolt = FloatField("VGSTH VOLTAGE*", validators=[DataRequired()])
    VgsThMeasure = SelectField("UNITS*", validators=[DataRequired()], choices=[("uV","uV"),("mV","mV"),("V","V")])
    powerDissipation = FloatField("POWER DISSIPATION")
    powerDissipationMeasure = SelectField("UNITS", choices=[("uW","uW"),("mW","mW"),("W","W")])
    project_id = IntegerField("PROJECT ID*", validators=[DataRequired()])
    manufacturer_name = StringField("MAKE*", validators = [DataRequired()])
    bin_no = SelectField("BIN NUMBER*", validators=[DataRequired()], choices=Bins)
    remark = TextAreaField("COMMENTS")
    quantity = IntegerField("QTY", validators=[DataRequired()])
    submit = SubmitField("ADD ITEM")

class LEDForm(FlaskForm):
    manufacturerPartNo = StringField("MPN*", validators=[DataRequired()])
    productType = SelectField("LED TYPE*", validators=[DataRequired()], choices=[("High Power","High Power"),("Mid Power","Mid Power"),
										("Low Power", "Low Power")])
    ledPackage = SelectField("PACKAGE*", validators=[DataRequired()], choices=[("SMD","SMD"),("TH","TH"),("OTHERS","OTHERS")])
    ledWavelength = IntegerField("WAVELENGTH IN NM")
    ledColorTemperature = IntegerField("COLOR TEMPERATURE IN K")
    LedIlluminationColor = StringField("COLOR*", validators=[DataRequired()])
    project_id = IntegerField("PROJECT ID*", validators=[DataRequired()])
    manufacturer_name = StringField("MAKE*", validators = [DataRequired()])
    bin_no = SelectField("BIN NUMBER*", validators=[DataRequired()], choices=Bins)
    remark = TextAreaField("COMMENTS")
    quantity = IntegerField("QTY", validators=[DataRequired()])
    submit = SubmitField("ADD ITEM")

class ActiveForm(FlaskForm):
    manufacturerPartNo = StringField("MPN*", validators=[DataRequired()])
    activePackage = SelectField("PACKAGE*", validators=[DataRequired()], choices=chipPackages)
    active_Description = StringField("DESCRIPTION*", validators=[DataRequired()])
    project_id = IntegerField("PROJECT ID*", validators=[DataRequired()])
    manufacturer_name = StringField("MAKE*", validators = [DataRequired()])
    bin_no = SelectField("BIN NUMBER*", validators=[DataRequired()], choices=Bins)
    remark = TextAreaField("COMMENTS")
    quantity = IntegerField("QTY", validators=[DataRequired()])
    submit = SubmitField("ADD ITEM")

class CustomerForm(FlaskForm):
    customerName = StringField("CUSTOMER NAME*", validators=[DataRequired()])
    Address = TextAreaField("ADDRESS")
    customer_contact_name = StringField("CONTACT NAME*", validators=[DataRequired()])
    phoneNumbers = StringField("CONTACT NUMBER*", validators=[DataRequired()])
    submit = SubmitField("ADD ITEM")

class ProjectForm(FlaskForm):
    projectName = StringField("PROJECT NAME*", validators=[DataRequired()])
    endCustomerId = IntegerField("CUSTOMER ID*", validators=[DataRequired()])
    projectStatus = SelectField("PROJECT STATUS*", validators=[DataRequired()], choices=[("BID","BIDDING"),("PROGRESS","IN PROGRESS"),
    											("DELIVERED", "DELIVERED"),("LOST","LOST")])
    submit = SubmitField("ADD ITEM")

class MechanicalForm(FlaskForm):
    manufacturerPartNo = StringField("MPN*", validators=[DataRequired()])
    partType = SelectField("TYPE*", validators=[DataRequired()], choices=mechanicalComponentTypes)
    mechanicalDescription = StringField("DESCRIPTION*", validators=[DataRequired()])
    project_id = IntegerField("PROJECT ID*", validators=[DataRequired()])
    manufacturer_name = StringField("MAKE*", validators = [DataRequired()])
    bin_no = SelectField("BIN NUMBER*", validators=[DataRequired()], choices=Bins)
    remark = TextAreaField("COMMENTS")
    quantity = IntegerField("QTY", validators=[DataRequired()])
    submit = SubmitField("ADD ITEM")




@app.route('/')
def home():
    if current_user.is_authenticated:
        user_logged = True
        name = current_user.username
    else:
        user_logged = False
        name = None
    return render_template('home.html', login_status=user_logged, name=name)

@app.route('/inventory')
def inventory():
    return render_template('inventory.html')

@app.route('/popup')
def popup():
    return render_template('popup.html')

@app.route('/add_components', methods=['GET','POST'])
@login_required
def add_components():

    resistor_form = ResistorForm()
    capacitor_form = CapacitorForm()
    inductor_form = InductorForm()
    diode_form = DiodeForm()
    transistor_form = TransistorForm()
    mosfet_form = MOSFETForm()
    led_form = LEDForm()
    active_form = ActiveForm()
    mechanical_form = MechanicalForm()

    return render_template('components.html',resistor_form=resistor_form,capacitor_form=capacitor_form, inductor_form=inductor_form, diode_form=diode_form,
			   transistor_form=transistor_form, mosfet_form=mosfet_form, led_form=led_form, active_form=active_form,
			   mechanical_form=mechanical_form)


@app.route('/register', methods=['GET','POST'])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(register_form.password.data)
        new_user = User(username=register_form.username.data, password=hashed_password, email=register_form.email.data)
        db.session.add(new_user)
        db.session.commit()
        flash("Thanks for Registering!", 'success')
        return redirect(url_for('login'))
    return render_template('register.html', register_form=register_form)

@app.route('/login', methods=['GET','POST'])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        user = User.query.filter_by(username=login_form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, login_form.password.data):
                login_user(user)
                return redirect(url_for('home'))

    return render_template('login.html', login_form=login_form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been Successfully Logged Out!!!!", "info")
    return redirect(url_for('home'))

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port="2000")
