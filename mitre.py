from pyattck import Attck


# IMPORTANT!!!
# pyattck does not work currently due to https://github.com/swimlane/pyattck/issues/125
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
    attack = Attck()
    for actor in attack.enterprise.actors:
        if industryName in actor.description:
            actorsList.append(actor.name)
    return actorsList

def getRiskScoreActorMultiplier(numActors):
    multiplier = 1
    counter = 0
    while counter < numActors:
        multiplier *= 1.1 # This number can be changed to whatever
    return multiplier

def getActorScore(numActors):
    score = 0.0
    
    return score



# get countries of actors --, count them, display a country per country view
