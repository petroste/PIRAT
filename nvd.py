import nvdlib
import re
from datetime import datetime, timedelta, date
#name = input ("PLC product name ")
#cveList = nvdlib.searchCVE(keyword=name, limit=10)
#for eachCVE in cveList:
#   print (eachCVE.v3severity + " score:" + str(eachCVE.impact) + "\ndescription: " + str(eachCVE.cve.description.description_data[0].value) + "\n\n")

#riskScore = 0

#for eachCve in cveList:
#    if eachCve.impact.baseMetricV3.cvssV3.baseScore > 8:
#        riskScore = 10
#        break
#    elif eachCve.impact.baseMetricV3.cvssV3.baseScore > 6:
#        riskScore = 8
#       break

#print ("Risk score for this PLC is: " + str(riskScore))

# Find a way to pretty print this data
# Find a way to efficiently search for.

def searchNVD(model):
    # find a way to securely store the key somewhere
    cveList = nvdlib.searchCVE(keywordSearch=model)
    return cveList

def getDescriptionCVE(cveItem):
    return str(cveItem.descriptions[0].value)

def getCVE(cveItem):
    return str(cveItem.id)

def getBaseScoreCVE(cveItem):
    if cveItem.score[1] is not None:
        return cveItem.score[1]
    else:
        return -1

def getAvailabilityImpactCVE(cveItem):
    try:
        return cveItem.metrics.cvssMetricV31[0].cvssData.availabilityImpact
    except AttributeError:
        try:
            return cveItem.metrics.cvssMetricV2[0].cvssData.availabilityImpact
        except AttributeError:
            return 0
        
def getConfidentialityImpactCVE(cveItem):
    try:
        return cveItem.metrics.cvssMetricV31[0].cvssData.confidentialityImpact
    except AttributeError:
        try:
            return cveItem.metrics.cvssMetricV2[0].cvssData.confidentialityImpact
        except AttributeError:
            return 0
        
def getIntegrityImpactCVE(cveItem):
    try:
        return cveItem.metrics.cvssMetricV31[0].cvssData.integrityImpact
    except AttributeError:
        try:
            return cveItem.metrics.cvssMetricV2[0].cvssData.integrityImpact
        except AttributeError:
            return 0
        
def getImpactScoreCVE(cveItem):
    try:
        return cveItem.metrics.cvssMetricV31[0].impactScore
    except AttributeError:
        try:
            return cveItem.metrics.cvssMetricV2[0].impactScore
        except AttributeError:
            return 0

def getExploitabilityScoreCVE(cveItem):
    try:
        return cveItem.metrics.cvssMetricV31[0].exploitabilityScore
    except AttributeError:
        try:
            return cveItem.metrics.cvssMetricV2[0].exploitabilityScore
        except AttributeError:
            return 0

def getImpactConversion(cveWord):
    result = 0
    if cveWord == 'COMPLETE' or cveWord == 'HIGH':
        result = 10
    elif cveWord == 'PARTIAL' or cveWord == 'LOW':
        result = 6
    elif cveWord == 'NONE':
        result = 0
    return result

def getMultiplierCVE(cveItem):
    multiplier = 1
    CVEYearString = cveItem.published
    cveYear = datetime (int(CVEYearString[0:4]), int(CVEYearString[5:7]), int(CVEYearString[8:10]))
    currentYear = datetime.today()
    yearDelta = currentYear - cveYear
    if int(yearDelta.days) <= 365:
        multiplier = 1
    elif int(yearDelta.days) <= (2 * 365):
        multiplier = 0.9
    elif int(yearDelta.days) <= (3 * 365):
        multiplier = 0.8
    elif int(yearDelta.days) <= (4 * 365):
        multiplier = 0.7
    elif int(yearDelta.days) <= (5 * 365):
        multiplier = 0.6
    elif int(yearDelta.days) <= (6 * 365):
        multiplier = 0.5
    elif int(yearDelta.days) <= (7 * 365):
        multiplier = 0.4
    elif int(yearDelta.days) <= (8 * 365):
        multiplier = 0.3  
    elif int(yearDelta.days) <= (9 * 365):
        multiplier = 0.2
    else:
        multiplier = 0.1  

    return multiplier

def getLatestCVEList(cveList):
    index = 0
    for cve in cveList:
        if len(re.findall("^CVE-20[1,2]", str(cve.id))) == 0:
            cveList.pop(index)
        else:
            index += 1
    
    return cveList
