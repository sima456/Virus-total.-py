from src import BrowserGenerator, Files, URLs, USBDetector
from time import sleep
import os.path
import os 
import csv
import json
from multiprocessing import Process
from colorama import init, Fore, Back, Style
init()

class main():
    def __init__(self) -> None:
        pass

    def __str__(self) -> str:
        pass
    
    def cprint(self, msg, foreground="black", background="white"):
        """
            Help you to Change the output color
            First part is the message which will be shown in output
            Second part is the font color
            Third part is the background color
        """
        fground = foreground.upper()
        bground = background.upper()
        style = getattr(Fore, fground) + getattr(Back, bground)
        print(style + msg + Style.RESET_ALL)


    def runProgram(self):
        self.devicedetector = USBDetector.DeviceDetector()
        self.firstTimeFlag = True
        Process(target=self.usb).start()        


        while True:
            # Menu
            print("Menu:\n\t",
                " 1. SafeBrowser\n\t",
                " 2. Scan\n\t",
                # " 3. USB\n\t",
                )
            num = input("Enter your command: ")

            if num == '1' or num.lower() == 'safebrowser':
                browserName = input("Please enter the name of the browser: chrome - firefox\n\t").lower()
                if browserName not in ['chrome', 'firefox']:
                    self.cprint(f"\tWe don't currently have '{browserName}' browser. Try again!", "red", "black")
                    continue
                browser = BrowserGenerator.SafeBrowse(browserName) # We run and open firefox as our browser other options:'chrome'/'zope.testbrowser'
                try:
                    self.ScanWebsite(browser)
                except:
                    self.cprint("\tBrowser Stopped by user. Continue", "red", "black")
                    continue

            elif num == '2' or num.lower() == 'scan':
                path = input("Please enter the path for scanning: ")
                num, typ = 5, 'mb'
                if input('Do you want to scan specific files with specific size? y/n\t') == 'y':
                    num, typ = input("Enter your limitation (e.g. '5,MB' for files less the 5 megabytes): ").split(',')
                    print(num, typ )
                    if typ not in ['byte', 'kb', 'mb', 'gb', 'tb']:
                        self.cprint("\tYou Entered wrong type! Try again ", "red", "black")
                        continue
                WrongPath_Flag = self.ScanForFilesFolders(FilesPATH=path, MAX_SIZE=(int(num), typ))
                if WrongPath_Flag:
                    self.cprint("\tYou Entered wrong Path! Try again ", "red", "black")
                    continue
            
            # elif num == '3' or num.lower() == 'usb':
            #     path = print("Waiting for new device to inser..")
            #     while True:
            #         newDrives = self.devicedetector.newDeviceDetector()
            #         if len(newDrives) > 0:
            #             self.ScanForFilesFolders(FilesPATH=newDrives, Drive=True)


    def ScanWebsite(self, browser):
        #### Open google.com in the Tab
        browser.startBrowing()

        #### A tab with google.com must be opened till here
        while True:
            if browser.currentURL_is() != browser.previousurl:
                currenturl = browser.currentURL_is() # Here we have the current URL
                browser.previousurl = currenturl 

                ######## Scan the URL and show it in output
                print(f'We are scanning {currenturl} URL')
                urlObject = URLs.Urls(currenturl, "51bd951cd29384782a40f883531b182a06adb725331ea8c38b7b1f00e45826ca")
                
                ## URL scanning starts here
                print("URL Scanning....")
                ScanResponse = urlObject.scan()
                ScanResponseText = ScanResponse.text # Turn response to text in order to show in output
                print(ScanResponseText)
                print("Scanning finished!", "\n")
                ## URL scanning finishes here
                ## Getting report information starts here
                print("Reporting!")
                # print(urlObject.report().text)
                self.urlReportJSON = json.loads(urlObject.report().text)
                self.saveReportIntoCSV(URL=True) ## Calliung Saving Function for saving URL data
                print("Reported!", "\n")
                ## Getting report information finishes here
                ######## URL scan completed and showed in terminal

    def saveReportIntoCSV(self, URL=False, File=False):
        if URL:
            Total_harmless = self.urlReportJSON['data']['attributes']['total_votes']['harmless'] # Value
            Total_malicious = self.urlReportJSON['data']['attributes']['total_votes']['malicious'] # Value

            Threat_names = self.urlReportJSON['data']['attributes']['threat_names'] # List "threat_names": [],
            Last_HTTP_Response_Headers = self.urlReportJSON['data']['attributes']['last_http_response_headers'] # Dict (key:value)
            """ "last_http_response_headers": {
                "Permissions-Policy": "interest-cohort=()",
                "X-Powered-By": "Next.js",
                "Transfer-Encoding": "chunked",
                "Age": "0",
                "Strict-Transport-Security": "max-age=63072000",
                "Server": "Vercel",
                "Cache-Control": "private, no-cache, no-store, max-age=0, must-revalidate",
                "Connection": "keep-alive",
                "X-Vercel-Cache": "MISS",
                "X-Matched-Path": "/",
                "Date": "Sat, 07 Jan 2023 00:10:27 GMT",
                "Content-Type": "text/html; charset=utf-8",
                "Content-Encoding": "gzip",
                "X-Vercel-Id": "cle1::iad1::l99zl-1673050226959-3bbe0dea600a"
            }, """
            
            last_http_response_content_sha256 = self.urlReportJSON['data']['attributes']['last_http_response_content_sha256'] # Value
            """ "last_http_response_content_sha256": "9025020ae038d7aab57e63f081dd1974c7632cc13d7121b4ea49d56088754a54" """
            
            last_analysis_stats = self.urlReportJSON['data']['attributes']['last_analysis_stats'] # Dict
            """ "last_analysis_stats": {
                "harmless": 77,
                "malicious": 0,
                "suspicious": 0,
                "undetected": 13,
                "timeout": 0
            }, """
            
            last_analysis_stats = self.urlReportJSON['data']['attributes']['last_analysis_results'] # Dict
            last_analysis_stats = self.urlReportJSON['data']['attributes']['last_analysis_results'] # Dict
            """ Consists of more than 70 check scanned with various antivirus. Each of them are a dictionary which key is the name of the method of scanning """

            Listof_last_analysis_stats_KEYs = list(dict(last_analysis_stats).keys()) ## These keys are methods of scanning
            
            with open('ScanReport\\URLs\\lastanalysisSTATs.csv', 'w', encoding='UTF8', newline='') as file:
                fieldnames=['engin_name', 'category', 'result', 'method']
                writer = csv.writer(file) 

                writer.writerow(fieldnames) # Header row

                rows = [
                    [last_analysis_stats[key]['engine_name'], last_analysis_stats[key]['category'], 
                    last_analysis_stats[key]['result'], last_analysis_stats[key]['method']] 
                    for key in Listof_last_analysis_stats_KEYs
                    ]

                ## Rows of data (scan results) are being saved
                # print(rows, '\n\n')
                for row in rows:
                    writer.writerow(row)
                ## Rows saved
                
            print('CSV file updated!')
            
        if File:
            pass
    
    def ScanForFilesFolders(self, FilesPATH='DocToScan', MAX_SIZE=(5, 'MB'), Drive=False):
        if Drive:
            FilesPATH = f'{FilesPATH[0]}:\\'
            print("This directory added and must scan", FilesPATH)

        self.files, self.folders = self.fileFolderFinder(FilesPATH) 
        ## self.files consists of a paths to files existing in that given path(Directory), self.folders Directory existing in the given directory 
        if (self.files, self.folders) == (0, 0):
            return True
        print('This is self.files: ', self.files, '\nThis is self.folders: ', self.folders, '\n\n')
        
        ### Size Calculation for every file
        ConversionDictionary = {'byte': 1, 'kb': 1024, 'mb':1024**2, 'gb':1024**3, 'tb':1024**4}
        maxsize = MAX_SIZE[0] * ConversionDictionary[MAX_SIZE[1].lower()]

        def scanFiles():
            for file in self.files:
                # Get the size of the file
                print('We are checking ', file, ' this file.\n')
                file_size = float(os.path.getsize(f'{file}'))
                for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
                    if file_size < 1024.0:
                        file_size = (float("%3.1f" % file_size), x)
                        break
                    file_size /= 1024.0
                # print(file_size)

                ## Ignoring files greater than 5 MG (Default Value)
                filesize = int(file_size[0]) * ConversionDictionary[file_size[1].lower()]
                if maxsize < filesize:
                    # Ignore
                    print(f'This {file} file Ignored!\n')
                    ...
                else:
                    # break
                    # Scan the File
                    fileObject = Files.Files(f'{file}', '51bd951cd29384782a40f883531b182a06adb725331ea8c38b7b1f00e45826ca')
                    
                    ### Scan the file
                    print(f"Scanning '{file}' File....")
                    ScanResponse = fileObject.scanUpload()
                    ScanResponseText = ScanResponse.text # Turn response to text in order to show in output
                    print(ScanResponseText)
                    print("Scanning File finished!", "\n")

                    ### Report the scanned file
                    print("Reporting!")
                    # print(fileObject.report().text)
                    print("Reported!", "\n")

        checkFile_flag = True
        CheckFolder_flag = True
        if len(self.files) > 0 and checkFile_flag:
            scanFiles()
            checkFile_flag = False
            print('file finisheddddd\n\n')

        if len(self.folders) > 0:
            for folder in self.folders:
                print(f"We are checking '{folder}' folder!")
                self.ScanForFilesFolders(FilesPATH=folder) ## Recursion starts here
            CheckFolder_flag = False
            print('Folder finisheddddd\n\n')

        if not(CheckFolder_flag):
            print("This directory checked completely!") ## Recursion finishes here           


    def usb(self):
        if self.firstTimeFlag:
            sleep(5)
            self.firstTimeFlag = False
        while True:
            newDrives = self.devicedetector.newDeviceDetector()
            if len(newDrives) > 0:
                self.ScanForFilesFolders(FilesPATH=newDrives, Drive=True)

        
    def fileFolderFinder(self, FilesPATH):
        ### Reading the Asked Directory for any files and folders
        folders = []
        files = []
        try:
            for entry in os.scandir(FilesPATH):
                if entry.is_dir():
                    folders.append(entry.path)
                elif entry.is_file():
                    files.append(entry.path)
            self.cprint('Folders:')
            for i in range(len(folders)):
                print("\t", folders[i])
                sleep(.05)
            self.cprint('Files:')
            for i in range(len(files)):
                print("\t", files[i])
                sleep(.05)
            ### Reading the Asked Directory for any files and folders
            return files, folders
        except FileNotFoundError:
            self.cprint("\tPath doesn't Exist!", "red", "black")
            return 0, 0
        except:
            self.cprint("\Error detected!", "red", "black")
            return 0, 0


if __name__ == '__main__':
    mainObject = main()
    mainObject.runProgram()
