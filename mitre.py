from pyattck import *

attack = Attck()
# IMPORTANT!!!
# pyattck does not work currently due to https://github.com/swimlane/pyattck/issues/125 -> RESOLVED
# check updates for the resolution to the problem

# accessing malware
#for malware in attack.enterprise.malwares:
#    print(malware.id)
#    print(malware.name)

    # accessing actor or groups using this malware
#    for actor in malware.actors:
#        print(actor.id)
#        print(actor.name)

def getListOfActorsForIndustry(industryName):
    actorsList = []
    for actor in attack.enterprise.actors:
        if actor.description is not None and industryName.lower() in actor.description:
            actorsList.append(actor.name)
    return actorsList

def getActorNumberRiskScore(actorsList):
    numActors = len(actorsList)
    if numActors == 0:
        return 0
    elif numActors == 1:
        return 5
    elif numActors == 2:
        return 6
    elif numActors == 3:
        return 7
    elif numActors == 4:
        return 8
    elif numActors == 5:
        return 9
    elif numActors >= 6:
        return 10
    else:
        return 0

