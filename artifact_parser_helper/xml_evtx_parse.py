from __future__ import print_function
import sys
import os
import datetime
import pytz
import json
#from xml.etree.cElementTree import iterparse
from lxml.etree import iterparse
import argparse
import io
#import codecs

sys_header = ["UTC", "local_time", "EID", "RecordId", "Category", "User", "Computer", "PID", "TID"]
dummy_data_header_number = 15

if sys.version_info < (3, 0):
    reload(sys)
    sys.setdefaultencoding("utf-8")
else:
    sys.stdout = io.TextIOWrapper(sys.stdout.detach(), encoding='UTF-8', line_buffering=True)

def gettag(url, tag):
    return '{' + url + '}' + tag

def fixtag(ns, tag, nsmap):
    if ns not in nsmap:
        return tag
    return gettag(nsmap[ns], tag)

def encode_string3(v):
    return v

def encode_string2(v):
    return v.encode('utf-8')

def fix_string3(system_data):
    return [ fix_backslash(str(x)).replace('\r', ' ').replace('\n', ' ').replace('\t', ' ') for x in system_data]

def fix_string2(system_data):
    return [ fix_backslash(unicode(x)).replace('\r', ' ').replace('\n', ' ').replace('\t', ' ').encode('utf-8') for x in system_data]

encode_string = encode_string3
fix_string = fix_string3
if sys.version_info < (3, 0):
    fix_string = fix_string2
    encode_string = encode_string2

def get_records(source, nsmap={}):
    # get an iterable
    # some records from EvtXtract are broken, so we need to use lxml with "recover" option.
    context = iterparse(source, events=("start", "end", "start-ns"), recover=True)
    
    # get the root element
    #event, root = context.next()
    event, root = next(context)
    
    for event, elem in context:
        if event == 'start-ns':
            ns, url = elem
            if not ns in nsmap:
                nsmap[ns] = url
            else:
                if url == "Event_NS":
                    nsmap[url] = url
                elif url == "http://manifests.microsoft.com/win/2006/windows/WMI":
                    nsmap["WMI"] = url
            #print("ns:", ns, url)
        # you need to wait for "end" to get records because some columns
        # return None if you get coluns when you are in "start" event.
        elif event == 'end':
            #print(elem.tag, fixtag("", "Event", nsmap))
            if elem.tag == fixtag("", "Event", nsmap) or elem.tag == "Record":
                yield elem
            # you need to clear root node because of prevention of memory leak.
            root.clear()
    
    root.clear()

def parse_substitutions(elem, log_tz):
    result = {}
    eid = -1
    pid = -1
    tid = -1
    aid = -1
    raid = -1
    erid = -1
    computer = ""
    userid = ""
    date_local = ""
    date_utc = ""
    username = ""
    channel = ""
    for gce in elem:
        gce_text = ""
        date_flag = False
        for ggce in gce:
            if ggce.tag == "Type" and ggce.text == "17":
                date_flag = True
            if ggce.tag == "Value" and ggce.text is not None:
                gce_text = ggce.text
                if date_flag:
                    date_utc, date_local = get_date(ggce.text, log_tz)
        prev_idx = -1
        for k, v in tuple(gce.attrib.items()):
            if v == "":
                idx = -1
            else:
                idx = int(v)
            tag_name = "%s_%02d" % (k, idx)
            val = gce_text
            if k == "index" and idx == 0:
                 tag_name = "Level"
            elif k == "index" and idx == 3:
                 tag_name = "EventID"
            elif k == "index" and idx == 5:
                 tag_name = "Keywords"
            elif k == "index" and idx == 6:
                 tag_name = "TimeCreated"
            elif k == "index" and idx == 8:
                 tag_name = "ProcessID"
                 pid = int(val)
            elif k == "index" and idx == 9:
                 tag_name = "ThreadID"
                 tid = int(val)
            elif k == "index" and idx == 10:
                 tag_name = "EventRecordID"
                 erid = int(val)
            elif k == "index" and idx == 12:
                 tag_name = "UserID"
                 userid = val
                 username = val
            elif k == "index" and idx == 14:
                 tag_name = "Provider_Name"
            elif k == "index" and idx == 15:
                 tag_name = "Provider_Guid"
            elif k == "index" and idx == 16:
                 tag_name = "Channel"
                 channel = val
            elif k == "index" and idx > 16:
                 result[(tag_name, "", "")] = gce_text
            prev_idx = idx
    return date_utc, date_local, result, username, computer, channel, pid, tid, erid

def parse_event_data(elem):
    result = {}
    for gce in elem:
        gce_text = ""
        if gce.text is not None:
            gce_text = gce.text
        #result[tuple(sorted(gce.attrib.items()))] = gce_text
        if len(gce.attrib.items()) > 0:
            for k, v in tuple(gce.attrib.items()):
                result[(gce.tag, k, v)] = gce_text
        else:
            result[(gce.tag, "", "")] = gce_text
    return result

def get_date(st, log_tz):
    try:
        date_utc = datetime.datetime.strptime(st, '%Y-%m-%d %H:%M:%S.%f')
    except ValueError:
        try:
            date_utc = datetime.datetime.strptime(st, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            # 2018-04-16T14:59:59.320273700Z
            date_utc = datetime.datetime.strptime(st[:26], '%Y-%m-%dT%H:%M:%S.%f')
    utc_datetime = pytz.utc.normalize(pytz.utc.localize(date_utc))
    date_local = utc_datetime.astimezone(pytz.timezone(log_tz)).strftime('%Y-%m-%d %H:%M:%S.%f')
    date_utc = utc_datetime.strftime('%Y-%m-%d %H:%M:%S.%f')
    return date_utc, date_local

def parse_system(elem, nsmap, log_tz):
    eid = -1
    pid = -1
    tid = -1
    aid = -1
    raid = -1
    erid = -1
    computer = ""
    userid = ""
    date_local = ""
    date_utc = ""
    username = ""
    channel = ""
    for gce in elem:
        #print("   ", gce.tag, gce.attrib)
        if gce.tag == fixtag("", "EventID", nsmap):
            eid = int(gce.text)
        elif gce.tag == fixtag("", "EventRecordID", nsmap):
            erid = int(gce.text)
        elif gce.tag == fixtag("", "Execution", nsmap):
            pid = int(gce.attrib['ProcessID'])
            tid = int(gce.attrib['ThreadID'])
        elif gce.tag == fixtag("", "TimeCreated", nsmap):
            date_utc, date_local = get_date(gce.attrib['SystemTime'], log_tz)
        elif gce.tag == fixtag("", "Computer", nsmap):
            computer = fix_backslash(gce.text)
        elif gce.tag == fixtag("", "Channel", nsmap):
            channel = fix_backslash(gce.text)
        elif gce.tag == fixtag("", "Correlation", nsmap):
            if 'ActivityID' in gce.attrib and gce.attrib['ActivityID'] != '':
                aid = gce.attrib['ActivityID']
            if 'RelatedActivityID' in gce.attrib and gce.attrib['RelatedActivityID'] != '':
                raid = gce.attrib['RelatedActivityID']
        elif gce.tag == fixtag("", "Security", nsmap):
            if 'UserID' in gce.attrib:
                username = fix_backslash(gce.attrib['UserID'])
    return eid, date_local, date_utc, username, computer, channel, pid, tid, erid

# we need to remove some backslashes because some logs from evtxtract have many backslashes.
# but it might break log elements...
def fix_backslash(val):
    return val.replace('\\.', '.').replace('\\-', '-').replace('\\ ', ' ').replace('\\%', '%').replace('\\:', ':').replace('\\/', '/').replace('\\$', '$').replace('\\@', '@')

def print_event_with_config(system_data, evt_data, attrib_vals, attrib_name="Name", parse_type="attrib", nsmap={}):
    #date_utc, date_local, eid, erid, username, computer, channel = system_data
    ar_evt_data = []
    for av in attrib_vals:
        flag = False
        ns_tag = ""
        if parse_type == "tag":
            ns_tag = fixtag(attrib_name, av, nsmap)
        for k in evt_data:
            tag, dan, dav = k
            if parse_type == "attrib":
                if (tag, attrib_name, av) == (tag, dan, dav):
                    ar_evt_data.append(evt_data[(tag, attrib_name, av)])
                    flag = True
            elif parse_type == "tag":
                if (ns_tag, "", "") == (tag, dan, dav):
                    ar_evt_data.append(evt_data[(tag, dan, dav)])
                    flag = True
            #else:
            #    ar_evt_data.append("")
        if not flag:
            ar_evt_data.append("")
    system_data.extend(ar_evt_data)
    system_data = fix_string(system_data)
    print("\t".join(system_data))

def get_tag_name(k, only_av=True):
    tag, an, av = k
    if tag.find("}") > 0:
        tag = tag.split("}")[-1]
    n = tag
    if only_av and (an or av):
        n = av
    elif an or av:
        n = "_".join([n, an, av])
    return n

def print_all_evt_data(system_data, evt_data, outfile=None, print_flag=True, add_attr=True):
    print_data = system_data.copy()
    outf_data = system_data.copy()
    for k, v in evt_data.items():
        n = get_tag_name(k)
        v = encode_string(v)
        if outfile:
            outf_data.append("%s" % (v))
        if print_flag:
            if add_attr:
                print_data.append("%s: %s" % (n,v))
            else:
                print_data.append("%s" % v)
    
    if outfile:
        line = "\t".join(fix_string(outf_data))
        outfile.write(line + "\n")
        #outfile.write(line)
    if print_flag:
        line = "\t".join(fix_string(print_data))
        print(line)

def parse_childelem(elem, nsmap, attrib_conf, log_tz, source, all_flag=False, add_attr=False, ofiles={}, out_dir=None):
    eid = -1
    pid = -1
    tid = -1
    offset = -1
    erid = -1
    dae_local = ""
    date_utc = ""
    username = ""
    computer = ""
    evt_data = {}
    date_local = ""
    channel = ""
    record_flag = False
    if elem.tag == "Record":
        record_flag = True
    for ce in elem:
        #print(ce.tag, nsmap)
        if ce.tag == fixtag("", "System", nsmap):
            eid, date_local, date_utc, username, computer, channel, pid, tid, erid = parse_system(ce, nsmap, log_tz)
        elif ce.tag == fixtag("", "EventData", nsmap):
            evt_data = parse_event_data(ce)
        elif ce.tag == fixtag("", "UserData", nsmap):
            for gce in ce:
                if gce.tag == fixtag("Event_NS", "EventXML", nsmap):
                    evt_data = parse_event_data(gce)
                elif gce.tag in [fixtag("WMI", "Operation_StartedOperational", nsmap), fixtag("WMI", "Operation_ClientFailure", nsmap)]:
                    evt_data = parse_event_data(gce)
        elif ce.tag == fixtag("", "ProcessingErrorData", nsmap):
            pass
        # for Record from evtxtract
        elif ce.tag == "EventID":
            eid = int(ce.text)
        elif ce.tag == "Offset":
            offset = int(ce.text, 16)
        elif ce.tag == "Substitutions":
            date_utc, date_local, evt_data, username, computer, channel, pid, tid, erid = parse_substitutions(ce, log_tz)
            #print(evt_data)
        elif ce.tag == "ProcessingErrorData":
            pass
    system_data = [date_utc, date_local, eid, erid, channel, username, computer, pid, tid]
    attr_key = "%d,%s" % (eid, channel.replace('\\-', '-').replace('\\/', '/'))
    #if source.startswith(r"\\"):
    #    source = r"\\?\UNC" + source[1:]
    #print("source after :%s" % source, file=sys.stderr)
    fn = source
    if out_dir and os.path.isdir(out_dir):
        #if out_dir.startswith(r"\\"):
        #    out_dir = r"\\?\UNC" + out_dir[1:]
        fn = os.path.join(out_dir, os.path.basename(fn))
    attr_key_file = fn + "." + attr_key.replace(",", "_").replace("/", "_") + ".csv"
    #if record_flag:
    #    system_data = [date_utc, date_local, eid]
    if attr_key in attrib_conf:
        if attr_key_file not in ofiles:
            ofiles[attr_key_file] = io.open(attr_key_file, 'w', encoding='utf-8')
            header = sys_header.copy()
            if len(evt_data) > 0:
                for k, v in evt_data.items():
                    header.append(get_tag_name(k))
            ofiles[attr_key_file].write("\t".join(header) + "\n")
        if 'attrib_names' in attrib_conf[attr_key] and 'attrib_name' in attrib_conf[attr_key]:
            if not all_flag:
                print_all_evt_data(system_data, evt_data, ofiles[attr_key_file], False)
                print_event_with_config(system_data, evt_data,
                                        attrib_conf[attr_key]['attrib_names'],
                                        attrib_conf[attr_key]['attrib_name'])
            else:
                print_all_evt_data(system_data, evt_data, ofiles[attr_key_file], True, add_attr)
            #pass
        elif 'tag_names' in attrib_conf[attr_key] and 'ns' in attrib_conf[attr_key]:
            if not all_flag:
                print_all_evt_data(system_data, evt_data, ofiles[attr_key_file], False)
                print_event_with_config(system_data, evt_data,
                                        attrib_conf[attr_key]['tag_names'],
                                        attrib_conf[attr_key]['ns'],
                                        parse_type="tag",
                                        nsmap=nsmap)
            else:
                print_all_evt_data(system_data, evt_data, ofiles[attr_key_file], True, add_attr)
        elif record_flag and "records" not in ofiles:
            print_all_evt_data(system_data, evt_data, ofiles[attr_key_file], False)
        else:
            print_all_evt_data(system_data, evt_data, ofiles[attr_key_file], True, add_attr)
    elif record_flag:
        if fn + ".records.csv" not in ofiles:
            ofiles[fn + ".records.csv"] = io.open(fn + ".records.csv", 'w', encoding='utf-8')
            #header = ["UTC", "local_time", "EID"]
            header = sys_header.copy()
            if len(evt_data) > 0:
                for k, v in evt_data.items():
                    header.append(get_tag_name(k))
            ofiles[fn + ".records.csv"].write("\t".join(header) + "\n")
            print_all_evt_data(system_data, evt_data, ofiles[fn + ".records.csv"], False)
        else:
            print_all_evt_data(system_data, evt_data, ofiles[fn + ".records.csv"], False)
    elif all_flag:
        if attr_key_file not in ofiles:
            #print("attr_key_file :%s" % attr_key_file, file=sys.stderr)
            ofiles[attr_key_file] = io.open(attr_key_file, 'w', encoding='utf-8')
            header = sys_header.copy()
            if len(evt_data) > 0:
                for k, v in evt_data.items():
                    header.append(get_tag_name(k))
            ofiles[attr_key_file].write("\t".join(header) + "\n")
        print_all_evt_data(system_data, evt_data, ofiles[attr_key_file], True, add_attr)

def config_load(conf_file):
    f = open(conf_file, 'r')
    json_obj = json.load(f)
    f.close()
    return json_obj

def get_options():
    pathname = os.path.abspath(os.path.dirname(sys.argv[0]))
    conf_path = os.path.join(pathname, "to_get_attribs.json")

    parser = argparse.ArgumentParser(description='transform xml evt log to csv')
    parser.add_argument('files', metavar='FILE', type=str, nargs='+',
                        help='files transformed xml into csv')
    parser.add_argument('-t', '--timezone', dest='log_tz',
                        type=str, default='Asia/Tokyo',
                        help='Time zone information (default: %(default)s)')
    parser.add_argument('-c', '--config', dest='config',
                        type=str, default=conf_path,
                        help='Config file JSON formatted (default: %(default)s)')
    parser.add_argument('-a', '--all', dest='all',
                        default=False,
                        action="store_true",
                        help='Get all logs (default: %(default)s)')
    parser.add_argument('-r', '--add-attr-name', dest='add_attr',
                        default=False,
                        action="store_true",
                        help='Add attribute name in columns (default: %(default))')
    parser.add_argument('-o', '--output-dir', dest='out_dir',
                        default=None, type=str,
                        help='Specify the output directory (default: %(default))')

    args = parser.parse_args()
    attrib_conf = config_load(args.config)

    return args.files, args.log_tz, attrib_conf, args.all, args.add_attr, args.out_dir


def parse_xml(source, attrib_conf, log_tz, all_flag=False, add_attr=True, out_dir=None):
    nsmap = {}
    ofiles={}
    if all_flag:
        header = sys_header.copy()
        for i in range(15):
            header.append("Data%d" % (i+1))
        print("\t".join(header))
    for elem in get_records(source, nsmap):
        #print(elem)
        parse_childelem(elem, nsmap, attrib_conf, log_tz, source, all_flag, add_attr, ofiles, out_dir)

def main():
    files, log_tz, attrib_conf, all_flag, add_attr, out_dir = get_options()
    for fn in files:
        parse_xml(fn, attrib_conf, log_tz, all_flag, add_attr, out_dir)

if __name__ == '__main__':
    main()
