#!/usr/bin/python
class Website:
    def __init__(self,title):
        self.title = title

    def showTitle(self):
        print(self.title)

obj = Website('pythonbasics.org')
obj.showTitle()
