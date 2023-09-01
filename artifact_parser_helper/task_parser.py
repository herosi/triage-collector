import xml.dom.minidom
import sys
import os
import datetime
import platform

def creation_date(path_to_file):
    """
    Try to get the date that a file was created, falling back to when it was
    last modified if that isn't possible.
    See http://stackoverflow.com/a/39501288/1709587 for explanation.
    """
    if platform.system() == 'Windows':
        return os.path.getctime(path_to_file)
    else:
        stat = os.stat(path_to_file)
        try:
            return stat.st_birthtime
        except AttributeError:
            # We're probably on Linux. No easy way to get creation dates here,
            # so we'll settle for when its content was last modified.
            return stat.st_mtime

def parse_task(dom):
    reginfo = dom.getElementsByTagName("RegistrationInfo")
    edt = reginfo[0].getElementsByTagName("Date")
    dt = ""
    if len(edt) > 0:
        dt = edt[0].firstChild.data
    eauthor = reginfo[0].getElementsByTagName("Author")
    author = ""
    if len(eauthor) > 0:
        author = eauthor[0].firstChild.data
        
    uri = ""
    euri = reginfo[0].getElementsByTagName("URI")
    if len(euri) > 0:
        uri = euri[0].firstChild.data

    actions = dom.getElementsByTagName("Actions")
    cmd = ""
    args = ""
    for exec in actions[0].getElementsByTagName("Exec"):
         ecmd = exec.getElementsByTagName("Command")
         if len(ecmd) > 0:
             cmd = ecmd[0].firstChild.data
         eargs = exec.getElementsByTagName("Arguments")
         if len(eargs) > 0:
             args = eargs[0].firstChild.data

    clsid = ""
    ecom = actions[0].getElementsByTagName("ComHandler")
    if len(ecom) > 0:
        eclsid = ecom[0].getElementsByTagName("ClassId")
        if len(eclsid) > 0:
             clsid = eclsid[0].firstChild.data

    return dt, uri, author, cmd, args, clsid

def find_all_files(directory):
    for cur_dir, dirs, files in os.walk(directory):
        for file in files:
            yield os.path.join(cur_dir, file)

def get_file_cmtime(fname):
    return creation_date(fname), os.path.getmtime(fname)


def print_result(input):
    dom = xml.dom.minidom.parse(input)
    result = [datetime.datetime.fromtimestamp(x).strftime('%Y/%m/%d %H:%M:%S.%f') for x in get_file_cmtime(input)]
    result.extend(parse_task(dom))
    result.append(input)
    print("\t".join(result))

def __main__():
    print("File Creation\tFile Modification\tTask Creation\tTask URI\tTask Author\tCommand\tArgs\tCLSID\tFile Name")
    input = sys.argv[1]
    if os.path.isfile(input):
        print_result(input)
    elif os.path.isdir(input):
        for file in find_all_files(input):
            # print(file)
            print_result(file)

if __name__ == "__main__":
    __main__()

#print("%s\t%s\t%s\t%s\t%s" % (dt.firstChild.data, uri.firstChild.data, author.firstChild.data, cmd, args))
