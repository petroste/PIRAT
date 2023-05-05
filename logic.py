from tkinter import messagebox
from nvd import *
from mitre import *
import re
    
def calculateRisk(entryField, industryDropdown, manufacturerDropdown, selection, categoryList):
    # call functions from nvd and mitre
    # have sub functions for each call
    # as much abstraction as possible
    verbose = ""
    multiplier = 0
    attack = Attck()

    # use entry field as an argument for search
    searchTermList = getSearchTermList(entryField, manufacturerDropdown)
    resultTuple = searchPLCInfoNVD(searchTermList)
    damageToProperty = getImpactMultiplier(categoryList[0])
    internalOpLoss = getImpactMultiplier(categoryList[1])
    externalOpLoss = getImpactMultiplier(categoryList[2])
    opInfoTheft = getImpactMultiplier(categoryList[3])
    controlLoss = getImpactMultiplier(categoryList[4])
    viewLoss = getImpactMultiplier(categoryList[5])
    controlManipulation = getImpactMultiplier(categoryList[6])
    viewManipulation = getImpactMultiplier(categoryList[7])
    cveList = resultTuple[0]
    searchIndex = resultTuple[1]
    actorsList = getListOfActorsForIndustry(industryDropdown)

    # check whether the cveList is empty - useless to continue if not
    errorNoCVE(cveList)

    # If verbose, generate verbose output
    if selection == 2:
        verbose = generateVerboseOutput(cveList, actorsList, False)
    elif selection == 3:
        # if the description checkbox was seleced then also print out the description for each CVE
        verbose = generateVerboseOutput(cveList, actorsList, True)

    cvssScore = 0.0
    availabilityEff = 0.0
    confidentialityEff = 0.0
    integrityEff = 0.0
    exploitabilityScore = 0.0
    impactScore = 0.0
    numberVuln = len(cveList)
    actorsScore = getActorNumberRiskScore(actorsList)
    impactCat = damageToProperty * internalOpLoss * externalOpLoss * opInfoTheft * controlLoss * viewLoss * controlManipulation * viewManipulation

    for eachCVE in reversed(cveList):
        if getBaseScoreCVE(eachCVE) == -1:
            # There is no base score for the CVE, likely very recent
            # skip this CVE
            continue
        else:
            multiplier = getMultiplierCVE(eachCVE)
            #cvssScore += float(getBaseScoreCVE(eachCVE))
            #availabilityEff += getImpactConversion(getAvailabilityImpactCVE(eachCVE))  * multiplier
            integrityEff += getImpactConversion(getIntegrityImpactCVE(eachCVE)) * multiplier
            confidentialityEff += getImpactConversion(getConfidentialityImpactCVE(eachCVE)) * multiplier
            exploitabilityScore += getExploitabilityScoreCVE(eachCVE) * multiplier
            impactScore += getImpactScoreCVE(eachCVE) * multiplier

    # actorsScore += getActorScore(len(actorsList))


    #cvssScore /= numberVuln
    #availabilityEff /= numberVuln
    integrityEff /= numberVuln
    confidentialityEff /= numberVuln
    exploitabilityScore /= numberVuln
    impactScore /= numberVuln

    formulaRes = ((exploitabilityScore + confidentialityEff + integrityEff + impactScore) / 4 * actorsScore * impactCat) / 3

    totalRiskOutput = outputRiskInfo(industryDropdown, actorsList, exploitabilityScore, confidentialityEff, integrityEff, impactScore, formulaRes, numberVuln, searchTermList[searchIndex], selection, verbose)
    return totalRiskOutput

def outputRiskInfo(industryDropdown, actorsList, exploitabilityScore, confidentialityEff, integrityEff, impactScore, formulaRes, numberVuln, searchTerm, selection, verbose):

    output = "The number of vulnerabilities for this PLC family is:\n"
    output += str(numberVuln) + "\n"
    output += "The risk score for this PLC family is:\n"
    output += str(round(formulaRes, 2)) + "\n"
    output += "The risk subscores for this PLC family are:\n"
    output += "Exploitability Score: " + str(round(exploitabilityScore, 2)) + "\n"
    output += "Confidentiality Score: " + str(round(confidentialityEff, 2)) + "\n"
    output += "Integrity Score: " + str(round(integrityEff, 2)) + "\n"
    output += "Impact Score: " + str(round(impactScore, 2)) + "\n"
    if formulaRes > 8:
        output += "Your device is at critical risk!\n"
        output += "Check vendor website for latest patches/guidance.\n"
        # if not verbose
        if selection != 4:
            output += "Try calculating risk with verbose output option\nselected for more information about this device.\n"
    elif formulaRes > 6:
        output += "Your device is at high risk!\n"
    elif formulaRes > 4:
        output += "Your device is at medium risk\n"
    else:
        output += "Your device is at low risk!\n"
    output += "The number of APTs that attack the " + industryDropdown + " industry: " + str(len(actorsList)) + "\n"
    output += "The term we searched for is: " + searchTerm + "\n" 
    # output += "The actors which attack the " + industryDropdown + "industry are\n"

#    for actor in actorsList:
#       output += str(actor) + "\n"

    # if verbose
    if selection == 2 or selection == 3:
        output += verbose
        # reset verbose for future queries
        verbose = ""

    return output

def generateVerboseOutput(cveList, actorsList, description):
    verbose = ""
    if (len(actorsList) > 0):
        verbose += "\nAPTs that are known to attack this industry:\n\n"
        verbose += "["
        for actor in actorsList:
            verbose += actor + ", "
        verbose = re.sub(r"..$", "] ", verbose)
        verbose += "\n\n"
    verbose += "Here is some information about the latest CVEs impacting this PLC family.\n\n"

    for eachCVE in reversed(cveList):
        if getBaseScoreCVE(eachCVE) == -1:
            # There is no base score for the CVE, likely very recent
            # skip this CVE
            continue           
        else:
            verbose += getCVE(eachCVE) + "\n\n"
            if description == True:
                verbose += "Description:\n" + getDescriptionCVE(eachCVE) + "\n\n"
            verbose += "Base Score: " + str(getBaseScoreCVE(eachCVE)) + "\n"
            verbose += "Availability Impact: " + str(getAvailabilityImpactCVE(eachCVE)) + "\n"
            verbose += "Confidentiality Impact: " + str(getConfidentialityImpactCVE(eachCVE)) + "\n"
            verbose += "Integrity Impact: " + str(getIntegrityImpactCVE(eachCVE)) + "\n"
            verbose += "Impact Score: " + str(getImpactScoreCVE(eachCVE)) + "\n"
            verbose += "Exploitability Score: " + str(getExploitabilityScoreCVE(eachCVE)) + "\n\n"
            verbose += "========================\n\n"

    return verbose


def checkForError(entryField, manufacturerDropdownVal, selection, categoryList):
    noError = True
    # if the manufacturer is Other and the field is empty we have nothing to search for
    if entryField.get() == "" and manufacturerDropdownVal == "Other":
        # pop up
        messagebox.showerror("The PLC search field is empty!", "Unfortunately, we're not mind readers! Please input a PLC family in the search bar.")
        noError = False
    elif manufacturerDropdownVal == "Select PLC Manufacturer:":
        # pop up
        messagebox.showerror("PLC manufacturer not selected!", "Please select a PLC manufacturer")
        noError = False
    else:
        for cat in categoryList:
            if cat == 0:
                noError = False
                messagebox.showerror("Impact checkbox empty", "Please select a checkbox for each category")                
                break

    return noError

def errorNoCVE(cveList):
    if len(cveList) == 0:
        messagebox.showerror("Search error!", "Apologies, we could not find any PLC model with the given name. Try modifying the input in the search field.")

def searchPLCInfoNVD(searchTermList):

    cveList = []
    indexOfList = 0

    for searchTerm in searchTermList:
        cveList = searchNVD(searchTerm)
        if len(cveList) != 0:
            indexOfList = searchTermList.index(searchTerm)
            break

    cveList2 = getLatestCVEList(cveList)
 
    return cveList2, indexOfList

def getSearchTermList(entryField, manufacturerDropdown):

    searchTermList = []

    # If manufacturer is Other then all search information is in the entryField
    if manufacturerDropdown == "Other":
        manufacturerDropdown = ""

    while (' ' in entryField) or ('-' in entryField):
        searchTermList.insert(0, str(manufacturerDropdown) + " " + entryField)
        entryField = re.split('-| ', entryField, 1)[0]

    # add last element in the string
    searchTermList.append(manufacturerDropdown + " " + entryField)

    # If manufacturer specified then add it as a last resort
    if manufacturerDropdown != "":
        searchTermList.append(str(manufacturerDropdown))

    return searchTermList

def getImpactMultiplier(category):
    multiplier = 1
    if category == 5:
        multiplier = 1
    elif category == 4:
        multiplier = 0.95
    elif category == 3:
        multiplier = 0.9
    elif category == 2:
        multiplier = 0.85
    elif category == 1:
        multiplier = 0.8
    return multiplier

def getCat2Multiplier(category):
    multiplier = 1
    if category == 5:
        multiplier = 1.5
    elif category == 4:
        multiplier = 1.2
    elif category == 3:
        multiplier = 1.0
    elif category == 2:
        multiplier = 0.8
    elif category == 1:
        multiplier = 0.5

def getCat3Multiplier(category):
    multiplier = 1
    if category == 5:
        multiplier = 1.5
    elif category == 4:
        multiplier = 1.2
    elif category == 3:
        multiplier = 1.0
    elif category == 2:
        multiplier = 0.8
    elif category == 1:
        multiplier = 0.5

def getCat4Multiplier(category):
    multiplier = 1
    if category == 5:
        multiplier = 1.5
    elif category == 4:
        multiplier = 1.2
    elif category == 3:
        multiplier = 1.0
    elif category == 2:
        multiplier = 0.8
    elif category == 1:
        multiplier = 0.5

def getCat5Multiplier(category):
    multiplier = 1
    if category == 5:
        multiplier = 1.5
    elif category == 4:
        multiplier = 1.2
    elif category == 3:
        multiplier = 1.0
    elif category == 2:
        multiplier = 0.8
    elif category == 1:
        multiplier = 0.5

def getCat6Multiplier(category):
    multiplier = 1
    if category == 5:
        multiplier = 1.5
    elif category == 4:
        multiplier = 1.2
    elif category == 3:
        multiplier = 1.0
    elif category == 2:
        multiplier = 0.8
    elif category == 1:
        multiplier = 0.5


