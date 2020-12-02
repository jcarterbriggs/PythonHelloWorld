#!/usr/bin/env python

#//TODO
#   - Calculate mean and median for blocks and misses and be able to slice by category
#   - Bar chart of 


import json
import urllib.request
import operator
import os
import matplotlib.pyplot as plt
APTGroup = "APT29"

companies = ["Bitdefender",
             "CrowdStrike",
             "Cybereason",
             "Cycraft",
             "Cylance",
             "Elastic",
             "F-Secure",
             "FireEye",
             "GoSecure",
             "HanSight",
             "Kaspersky",
             "Malwarebytes",
             "McAfee",
             "Microsoft",
             "PaloAltoNetworks",
             "ReaQta",
             "Secureworks",
             "SentinelOne",
             "Symantec",
             "TrendMicro",
             "VMware"
             ]

FullResults = {}

URLPrefix = "https://attackevals.mitre-engenuity.org/"
URLSuffix = ".1_Results.json"
if not os.path.isdir("./json_files"):
    os.mkdir("./json_files")


# download all the files and enter them into the "FullResults" dictionary
for Comp in companies:
    FulURL = URLPrefix + Comp + ".1." + APTGroup + URLSuffix
    #print("The full URL is: " + FulURL)
    OutputFile = "./json_files/" + Comp + ".json"
    #urllib.request.urlretrieve(FulURL, OutputFile)
    with open(OutputFile) as Company:
        FullResults[str(Comp)] = json.load(Company)

# go through each company and count the detections and failures
for Comp in companies:
    CompResults = FullResults[Comp]
    FullResults[Comp]["MissedDetections"] = 0
    FullResults[Comp]["TelemetryDetections"] = 0
    FullResults[Comp]["MSSDetections"] = 0
    FullResults[Comp]["CompanyName"] = Comp
    TechniquesList = CompResults["Techniques"]
    #print("looking at company " + Comp)

    # Go through each technique in the list
    for Tech1 in TechniquesList:
        #print("looking at technique" + str(Tech1["TechniqueName"]))

        # Go through each step in case there is more than one
        for Step in Tech1["Steps"]:
            # check if there is a detection at all
            if Step["Detections"][0]["DetectionType"] == "None":
                FullResults[Comp]["MissedDetections"] += 1
            elif Step["Detections"][0]["DetectionType"] == "Telemetry":
                FullResults[Comp]["TelemetryDetections"] += 1
            elif Step["Detections"][0]["DetectionType"] == "MSS":
                FullResults[Comp]["MSSDetections"] += 1

                #print(Comp + " Missed " + str(FullResults[Comp]["MissedDetections"]) + " Detections")

#which company missed the most
SortedList = sorted(FullResults.items(), key=operator.itemgetter(0))
#MostMisses = max(FullResults.items()["MissedDetections"], key=operator.itemgetter(1))
#print(SortedList[0]["CompanyName"])

MissedPlotData = {}
for Comp in companies:
    MissedPlotData[str(Comp)] = FullResults[Comp]["MissedDetections"]

#print(str(MissedPlotData[0]))
#plt.xticks(MissedPlotData[0], companies, rotation='vertical')

#plt.plot(*zip(MissedPlotData.items()))
#plt.show()
