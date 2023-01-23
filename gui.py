from tkinter import *
from logic import *


class FullScreenApp(object):
    def __init__(self, master, **kwargs):
        self.master=master
        pad=3
        self._geom='640x480+0+0'
        master.geometry("{0}x{1}+0+0".format(
            master.winfo_screenwidth()-pad, master.winfo_screenheight()-pad))
        master.bind('<Escape>',self.toggle_geom)          
        master.title("PIRAT - Python Risk Assessment Tool")
    def toggle_geom(self,event):
        geom=self.master.winfo_geometry()
        print(geom,self._geom)
        self.master.geometry(self._geom)
        self._geom=geom

def performCalc():
    global entryField
    global industryVariable
    global manufacturerVariable
    global selection, cat1, cat2, cat3, cat4, cat5, cat6, varDesc
    if selection == 2 and varDesc.get() == 3:
        # if the selection is verbose and the description checkmark has been checked
        selection = 3
    elif selection == 3 and varDesc.get() == 0:
        # if we have unchecked the description checkmark
        selection = 2
    categoryList = [cat1, cat2, cat3, cat4, cat5, cat6]
    if checkForError(entryField, manufacturerVariable.get(), selection, categoryList):
        risk = calculateRisk(entryField.get(), industryVariable.get(), manufacturerVariable.get(), selection, categoryList)
        displayRisk(risk)

def displayRisk(riskVal):

    # Create text widget and specify size.
    outputBox = Text(root)
    outputBox.place(relx = 0.27, rely = 0.62, width = 800, height = 330)

    # Scroll bar
    bar = Scrollbar(outputBox)
    bar.pack(side = RIGHT, fill = Y)

    outputBox.config(font=('Courier New',18,'bold'), yscrollcommand = bar.set)
    
    # Insert output into textbox.
    outputBox.insert(END, riskVal)

def deleteField(self):
    global firstClick
    if firstClick:
        entryField.delete(0, END)
        firstClick = False

def welcomeLabelSettings():
    headText = "Welcome to PIRAT - Python Risk Assessment Tool!\n"
    firstLine = "This tool allows you to estimate the risk of compromise of PLC devices by using the information\nfrom the National Vulnerability Database (NVD) and the MITRE ATT&CK Framework\n"
    nextLine = "How do we do it?\nWe process the information from the NVD and MITRE ATT&CK databases and feed it to our risk assessment formula to\n determine the risk factor of the PLC devices"
    welcomeLabel = Label(root, text = headText + firstLine + nextLine, font=("Arial", 22), bg="red")
    welcomeLabel.place(relx = 0.05, rely = 0.05, width=1500, height = 220)
    return welcomeLabel

def instructionLabelSettings():
    instText = "How to use:\n"
    instText += "1. Please select a PLC manufacturer and the industry of your organization from the corresponding dropdown menus\n"
    instText += "2. Select the appropriate output type - 'Risk assessment only' is the default. If 'Verbose' selected, specify whether you want the CVE descriptions to be outputted\n"
    instText += "3. Enter the model of the PLC in the search bar - do not include the name of the manufacturer\n"
    instText += "4. Check the appropriate impact boxes based on the consequences as a result of a PLC attack\n"
    instructionLabel = Label(root, text=instText, font=("Arial", 18))
    instructionLabel.place(relx = 0.12, rely = 0.29)
    return instructionLabel

def entryFieldSettings():
    entryField = Entry(root)
    entryField.insert(0, "Enter the PLC model to analyze:")
    entryField.bind("<ButtonPress-1>", deleteField)
    entryField.place(relx = 0.20, rely = 0.44, width = 500)
    return entryField

def industryDropdownSettings():
    OPTIONS = ["Aerospace","Chemical","Cyber","IT","Health","Law","Manufacturing","Maritime","Military",
               "Gambling", "Education","Finance","Government","Defense","Energy", "Engineering",
               "Petroleum","Retail","Technology","Telecom","Transportation"]
    OPTIONS = sorted(OPTIONS)

    industryVariable = StringVar(root)
    industryVariable.set("Select industry:") # default value

    industryDropdown = OptionMenu(root, industryVariable, *OPTIONS)
    industryDropdown.place(relx = 0.20, rely = 0.49, width = 230)
    return industryVariable

def manufacturerDropdownSettings():
    OPTIONS = ["ABB","Allen Bradley","Beckhoff","Delta","Eaton","Fatek","Festo",
               "Fuji","GeFanuc","Hitachi","Honeywell","Inovance","Kinco","LG",
               "Mitsubishi","Omron","Panasonic","Schneider Electric","Siemens",
               "Toshiba","Unitronics","Wago","Yokogawa","Other"]

    manufacturerVariable = StringVar(root)
    manufacturerVariable.set("Select PLC Manufacturer:") # default value

    manufacturerDropdown = OptionMenu(root, manufacturerVariable, *OPTIONS)
    manufacturerDropdown.place(relx = 0.20, rely = 0.52, width = 230)
    return manufacturerVariable

def selectOutputType():
    global selection
    global var
    selection = var.get()

def radioButtonSettings():
    radioLabel = Label(root, text="Select type of output:")
    radioLabel.place (relx = 0.34, rely = 0.47)

    R1 = Radiobutton(root, text="Risk assessment only", variable=var, value=1,
                     command=selectOutputType)
    R1.place(relx = 0.34, rely = 0.495)
    var.set(1)

    # Verbose will output CVE description + any relevant MITRE ATT&CK info
    R2 = Radiobutton(root, text="Verbose", variable=var, value=2,
                     command=selectOutputType)
    R2.place(relx = 0.34, rely = 0.52)

def checkboxMatrixSettings():
    checkLabel = Label(root, text = "Check one impact severity box for each category:")
    checkLabel.place(relx = 0.55, rely = 0.41)

    catLabel1 = Label(root, text = "Category1")
    catLabel1.place(relx = 0.50, rely = 0.44)
    c1 = Checkbutton(root, text='None',variable=var1, onvalue=1, offvalue=0, command=checkboxSelection)
    c1.place(relx = 0.55, rely=0.44)
    c2 = Checkbutton(root, text='Low',variable=var1, onvalue=2, offvalue=0, command=checkboxSelection)
    c2.place(relx = 0.60, rely=0.44)
    c3 = Checkbutton(root, text='Medium',variable=var1, onvalue=3, offvalue=0, command=checkboxSelection)
    c3.place(relx = 0.65, rely=0.44)
    c4 = Checkbutton(root, text='High',variable=var1, onvalue=4, offvalue=0, command=checkboxSelection)
    c4.place(relx = 0.70, rely=0.44)
    c5 = Checkbutton(root, text='Critical',variable=var1, onvalue=5, offvalue=0, command=checkboxSelection)
    c5.place(relx = 0.75, rely=0.44)

    catLabel2 = Label(root, text = "Category2")
    catLabel2.place(relx = 0.50, rely = 0.47)
    c6 = Checkbutton(root, text='None',variable=var2, onvalue=1, offvalue=0, command=checkboxSelection)
    c6.place(relx = 0.55, rely=0.47)
    c7 = Checkbutton(root, text='Low',variable=var2, onvalue=2, offvalue=0, command=checkboxSelection)
    c7.place(relx = 0.60, rely=0.47)
    c8 = Checkbutton(root, text='Medium',variable=var2, onvalue=3, offvalue=0, command=checkboxSelection)
    c8.place(relx = 0.65, rely=0.47)
    c9 = Checkbutton(root, text='High',variable=var2, onvalue=4, offvalue=0, command=checkboxSelection)
    c9.place(relx = 0.70, rely=0.47)
    c10 = Checkbutton(root, text='Critical',variable=var2, onvalue=5, offvalue=0, command=checkboxSelection)
    c10.place(relx = 0.75, rely=0.47)

    catLabel3 = Label(root, text = "Category3")
    catLabel3.place(relx = 0.50, rely = 0.50)
    c11 = Checkbutton(root, text='None',variable=var3, onvalue=1, offvalue=0, command=checkboxSelection)
    c11.place(relx = 0.55, rely=0.50)
    c12 = Checkbutton(root, text='Low',variable=var3, onvalue=2, offvalue=0, command=checkboxSelection)
    c12.place(relx = 0.60, rely=0.50)
    c13 = Checkbutton(root, text='Medium',variable=var3, onvalue=3, offvalue=0, command=checkboxSelection)
    c13.place(relx = 0.65, rely=0.50)
    c14 = Checkbutton(root, text='High',variable=var3, onvalue=4, offvalue=0, command=checkboxSelection)
    c14.place(relx = 0.70, rely=0.50)
    c15 = Checkbutton(root, text='Critical',variable=var3, onvalue=5, offvalue=0, command=checkboxSelection)
    c15.place(relx = 0.75, rely=0.50)

    catLabel4 = Label(root, text = "Category4")
    catLabel4.place(relx = 0.50, rely = 0.53)
    c16 = Checkbutton(root, text='None',variable=var4, onvalue=1, offvalue=0, command=checkboxSelection)
    c16.place(relx = 0.55, rely=0.53)
    c17 = Checkbutton(root, text='Low',variable=var4, onvalue=2, offvalue=0, command=checkboxSelection)
    c17.place(relx = 0.60, rely=0.53)
    c18 = Checkbutton(root, text='Medium',variable=var4, onvalue=3, offvalue=0, command=checkboxSelection)
    c18.place(relx = 0.65, rely=0.53)
    c19 = Checkbutton(root, text='High',variable=var4, onvalue=4, offvalue=0, command=checkboxSelection)
    c19.place(relx = 0.70, rely=0.53)
    c20 = Checkbutton(root, text='Critical',variable=var4, onvalue=5, offvalue=0, command=checkboxSelection)
    c20.place(relx = 0.75, rely=0.53)

    catLabel5 = Label(root, text = "Category5")
    catLabel5.place(relx = 0.50, rely = 0.56)
    c21 = Checkbutton(root, text='None',variable=var5, onvalue=1, offvalue=0, command=checkboxSelection)
    c21.place(relx = 0.55, rely=0.56)
    c22 = Checkbutton(root, text='Low',variable=var5, onvalue=2, offvalue=0, command=checkboxSelection)
    c22.place(relx = 0.60, rely=0.56)
    c23 = Checkbutton(root, text='Medium',variable=var5, onvalue=3, offvalue=0, command=checkboxSelection)
    c23.place(relx = 0.65, rely=0.56)
    c24 = Checkbutton(root, text='High',variable=var5, onvalue=4, offvalue=0, command=checkboxSelection)
    c24.place(relx = 0.70, rely=0.56)
    c25 = Checkbutton(root, text='Critical',variable=var5, onvalue=5, offvalue=0, command=checkboxSelection)
    c25.place(relx = 0.75, rely=0.56)

    catLabel6 = Label(root, text = "Category6")
    catLabel6.place(relx = 0.50, rely = 0.59)
    c26 = Checkbutton(root, text='None',variable=var6, onvalue=1, offvalue=0, command=checkboxSelection)
    c26.place(relx = 0.55, rely=0.59)
    c27 = Checkbutton(root, text='Low',variable=var6, onvalue=2, offvalue=0, command=checkboxSelection)
    c27.place(relx = 0.60, rely=0.59)
    c28 = Checkbutton(root, text='Medium',variable=var6, onvalue=3, offvalue=0, command=checkboxSelection)
    c28.place(relx = 0.65, rely=0.59)
    c29 = Checkbutton(root, text='High',variable=var6, onvalue=4, offvalue=0, command=checkboxSelection)
    c29.place(relx = 0.70, rely=0.59)
    c30 = Checkbutton(root, text='Critical',variable=var6, onvalue=5, offvalue=0, command=checkboxSelection)
    c30.place(relx = 0.75, rely=0.59) 


def checkboxSelection():
    global cat1, cat2, cat3, cat4, cat5, cat6
    global var1, var2, var3, var4, var5, var6
    cat1 = var1.get()
    cat2 = var2.get()
    cat3 = var3.get()
    cat4 = var4.get()
    cat5 = var5.get()
    cat6 = var6.get()

def verboseCheckboxSettings():
    cDesc = Checkbutton(root, text='Include CVE description',variable=varDesc, onvalue=3, offvalue=0)
    cDesc.place(relx = 0.39, rely=0.52)
        
def buttonSettings():
    calculateButton = Button(root, text="Calculate risk", command=performCalc)
    calculateButton.place(relx = 0.30, rely = 0.56, width = 200, height = 40)

root = Tk()
app = FullScreenApp(root)
firstClick = True
selection = 1
cat1 = 0
cat2 = 0
cat3 = 0
cat4 = 0
cat5 = 0
cat6 = 0
var = IntVar()
var1 = IntVar()
var2 = IntVar()
var3 = IntVar()
var4 = IntVar()
var5 = IntVar()
var6 = IntVar()
varDesc = IntVar()

welcomeLabel = welcomeLabelSettings()

instructionLabel = instructionLabelSettings()

entryField = entryFieldSettings()

calculateButton = buttonSettings()

industryVariable= industryDropdownSettings()

manufacturerVariable = manufacturerDropdownSettings()

checkboxVariable = checkboxMatrixSettings()

radioButtonSettings()

verboseCheckboxSettings()


root.mainloop()