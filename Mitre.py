#!/usr/bin/env python
__author__ = "J. Carter Briggs"
__version__ = "1.0"

# //TODO
#   - Calculate mean and median for blocks and misses and be able to slice by category
#   - Bar chart of blocks and misses by company with ability to slice by category
#   - CLI
#   - GUI
#   - Debug switch
#   - refactor classes and methods
#   - Summary by company
#   - Summary by technique
#   - Exception handling
#   - Venv
#   - battle card comparisons
#   - Combine multiple APTs
#   - create separate git repository with readme, license
#   - compile as application


import json
import urllib.request
import operator
import os
import matplotlib.pyplot as plt
import collections

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
file_directory = "./json_files/"
FullResults = {}

URLPrefix = "https://attackevals.mitre-engenuity.org/"
URLSuffix = ".1_Results.json"
Debug = False
Download = False


def downloadFiles():
    if Debug:
        print("Downloading Files")
    if not os.path.isdir(file_directory):
        if Debug:
            print("creating json directory")
        os.mkdir(file_directory)
    # download all the files and enter them into the "FullResults" dictionary
    for Comp in companies:
        FulURL = URLPrefix + Comp + ".1." + APTGroup + URLSuffix
        if Debug:
            print("Downloading from URL: " + FulURL)
        OutputFile = file_directory + Comp + ".json"
        urllib.request.urlretrieve(FulURL, OutputFile)


def initializeResults():
    if Debug:
        print("Initializing Results")
    for Comp in companies:
        ReadFile = file_directory + Comp + ".json"
        with open(ReadFile) as Company:
            if Debug:
                print("loading file " + ReadFile)
            FullResults[str(Comp)] = json.load(Company)


# go through each company and count the detections and failures
def analyzeResults():
    if Debug:
        print("Analyzing Results")
    for Comp in companies:
        CompResults = FullResults[Comp]
        FullResults[Comp]["MissedDetections"] = 0
        FullResults[Comp]["TelemetryDetections"] = 0
        FullResults[Comp]["MSSDetections"] = 0
        FullResults[Comp]["CompanyName"] = Comp
        TechniquesList = CompResults["Techniques"]
        if Debug:
            print("looking at company " + Comp)

        # Go through each technique in the list
        for Tech1 in TechniquesList:
            # if Debug:
            # print("looking at technique " + str(Tech1["TechniqueName"]))

            # Go through each step in case there is more than one
            for Step in Tech1["Steps"]:
                # check if there is a detection at all
                if Step["Detections"][0]["DetectionType"] == "None":
                    FullResults[Comp]["MissedDetections"] += 1
                elif Step["Detections"][0]["DetectionType"] == "Telemetry":
                    FullResults[Comp]["TelemetryDetections"] += 1
                elif Step["Detections"][0]["DetectionType"] == "MSS":
                    FullResults[Comp]["MSSDetections"] += 1

                # print(Comp + " Missed " + str(FullResults[Comp]["MissedDetections"]) + " Detections")


def summarizeMisses():
    for Comp in companies:
        print("Misses for: " + Comp)
        print("   Missed Detections: " + str(FullResults[Comp]["MissedDetections"]))


def summarizeDetections():
    for Comp, Results in FullResults.items():
        print("Results for Company " + Comp)
        print("   Telemetry Detections: " + str(Results["TelemetryDetections"]))


if Download:
    downloadFiles()

initializeResults()

analyzeResults()

# summarizeMisses()
# summarizeDetections()

# which company missed the most
SortedList = sorted(FullResults.items(), key=operator.itemgetter(0))
# MostMisses = max(FullResults.items()["MissedDetections"], key=operator.itemgetter(1))
# print(SortedList[0]["CompanyName"])

D = {}

for Comp, Results in FullResults.items():
    D[Comp] = Results["TelemetryDetections"]

# plt.bar(range(len(D)), list(D.values()), align='center')
# plt.xticks(range(len(D)), list(D.keys()), rotation='vertical')
# plt.show()

L1 = D.items()
L1 = sorted(L1, key=operator.itemgetter(1), reverse=True)

x = 0
x_value = [] * len(L1)
y_value = [] * len(L1)
# print(str(L1[0][0]))

#x_value[0] = 1

for result in L1:
    #x_value[x] = result[0]
    print("result[0] is " + str(result[0]))
    #y_value = result[1]
    print("result[1] is " + str(result[1]))
    print("x is " + str(x))
    x += 1

#plt.bar(x_value, y_value, align='center')
#print("x is: " + x_value)

plt.xlabel("Company")
plt.ylabel("Detections")
plt.title("Detections by Company")
#plt.xticks(range(len(L1)), y_value, rotation='vertical')
#plt.show()
