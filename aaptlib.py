#!/usr/bin/python
import os, sys
import re
import xml.etree.ElementTree as ET

class Configs:
  AAPT_BIN = "aapt"

# THIS SCRIPT USES BASH COLORS:
class bcolors:
  HEADER = '\033[95m'
  OKBLUE = '\033[94m'
  OKGREEN = '\033[92m'
  WARNING = '\033[93m'
  FAIL = '\033[91m'
  ENDC = '\033[0m'


class AaptDecodeError(ValueError):
    """Subclass of ValueError with the following additional properties:

    msg: The unformatted error message
    apk_file: The apk file passed to aapt
    line: The line where parsing failed
    lineno: The line number where parsing failed
    colno: The column number where parsing failed (may be None)

    """
    def __init__(self, msg, apk_file, line, lineno, colno):
        ValueError.__init__(self, errmsg(msg, lineno, colno))
        self.msg = msg
        self.apk_file = apk_file
        self.line = line
        self.lineno = lineno
        self.colno = colno

    def pretty_print(self):
      print "{0:4}:{1}".format(self.lineno, self.line.rstrip())
      if self.colno is not None:
        print bcolors.FAIL + "____" + "_"*self.colno + "^" + bcolors.ENDC
      print("\n\t{0}{1}{2}".format(bcolors.FAIL, self.msg, bcolors.ENDC))


def errmsg(msg, lineno, colno):
    return '%s: line %d column %d' % (msg, lineno, colno)


class ApkInfo():

  def __init__(self, apk_path):
    self.__apk_path = apk_path
    # lazy load
    self.__dump_badging   = None
    self.__dump_resources = None
    self.__dump_strings   = None
    self.__list           = None


  def __parseAaptDic(self, line, lineno, values, values_start_col):
    state = 0
    valuesDic={}
    for idx, c in enumerate(values):
      if state == 0:
        if c == '\n':
          return valuesDic
        elif c == ' ':
          state = 1
          key = ""
        else:
          raise AaptDecodeError("( ) or a new line expected. But found ({0})".format(c), self.__apk_path, line, lineno, values_start_col + idx)

      elif state == 1:
        # reading KEY
        if c == '=':
          state = 2
        else:
          key += c

      elif state == 2:
        if c != '\'':
          raise AaptDecodeError("(') expected.", self.__apk_path, line, lineno, values_start_col + idx)
        state = 3
        value = ""

      elif state == 3:
        # reading VALUE
        if c == '\'' and values[idx + 1] in [' ','\n']:
          # detect "' " or "'\n"
          valuesDic[key]=value
          state = 0
        else:
          value += c

      else:
        raise AaptDecodeError("Invalid state.", self.__apk_path, line, lineno, values_start_col + idx)


  def __parseAaptArray(self, line, lineno, values, values_start_col):
    pattern = re.compile(r'\'([^\']+)\'')
    valuesArray=[]
    for value in re.findall(pattern, values):
      valuesArray.append(value)
    return valuesArray





  def __parseAaptLine(self, line, lineno):
    key =    line[:line.find(':')]
    values = line[line.find(':')+1:]
    if line.find(':') == -1:
      # no value
      return {
        'key': key,
        'values': None
      }
    elif len(values) == 1 or (values[0] == '\'' and values[len(values)-2] == '\''):
      # simple value
      return {
        'key': key,
        'values': values[1:len(values)-2]
      }
    elif values[0] == ' ' and values[1] != '\'':
      # dictionary
      return {
        'key': key,
        'values': self.__parseAaptDic(line, lineno, values, len(key) + 1 )
      }
    elif values[0] == ' ' and values[1] == '\'':
      # array
      return {
        'key': key,
        'values': self.__parseAaptArray(line, lineno, values, len(key) + 1 )
      }
    else:
      raise AaptDecodeError("Value type not detected.", self.__apk_path, line, lineno, len(key))

  # function to extract package, launchers, versionCode, versionName from an APK file
  def getDumpBadging(self):
    #lazy load
    if self.__dump_badging is not None:
      return self.__dump_badging

    aapt_stream = os.popen("{0} dump badging \"{1}\"".format(Configs.AAPT_BIN, self.__apk_path))
    self.__dump_badging=[]
    for idx, line in enumerate(aapt_stream):
      res = self.__parseAaptLine(line, idx)
      self.__dump_badging.append(res)
    return self.__dump_badging



  def __parseAaptResourceDesc(self, desc):
    # desc example: 'com.google.mail:integer/max_mails:'
    desc_array = re.split("[/:]+", desc)
    return { 'package': desc_array[0], 'type': desc_array[1], 'name': desc_array[2] }

  def __parseAaptResourceType(self, line):
    type_array = line.strip().split(' ')
    return { 'id': type_array[1], 'configCount': type_array[2][12:], 'entryCount': type_array[3], 'resources': [], 'configs': [], 'type': None }

  def __parseAaptResourceSpec(self, line):
    spec_array = line.strip().split(' ')
    return { 'id': spec_array[2], 'desc': self.__parseAaptResourceDesc(spec_array[3]), 'configs': [], 'values': [] }

  def __parseAaptResourceConfig(self, line):
    config_array = line.strip().split(' ')
    #print config_array
    return { 'name': config_array[1], 'resources': [] }

  def __parseAaptResourceResource(self, line):
    resource_array = line.strip().split(' ')
    #print resource_array
    if resource_array[3] == '<bag>':
      return { 'id': resource_array[1], 'desc': self.__parseAaptResourceDesc(resource_array[2]) }
    else:
      return { 'id': resource_array[1], 'desc': self.__parseAaptResourceDesc(resource_array[2]), 't': resource_array[3][2:], 'd': int(resource_array[4][2:], 16) }

  # function to extract resources from an APK file
  def getDumpResources(self):
    #lazy load
    if self.__dump_resources is not None:
      return self.__dump_resources

    aapt_stream = os.popen("{0} dump resources \"{1}\"".format(Configs.AAPT_BIN, self.__apk_path))
    self.__dump_resources=[]

    try:
      line = aapt_stream.next()
      while True:
        # type
        if line.startswith('    type'):
          type = self.__parseAaptResourceType(line)
          self.__dump_resources.append(type)

          # spec
          line = aapt_stream.next()
          while line.startswith('      INVALID TYPE CONFIG') or line.startswith('      spec'):
            while line.startswith('      spec'):
              type['resources'].append(self.__parseAaptResourceSpec(line))
              line = aapt_stream.next()

            if line.startswith('      INVALID TYPE CONFIG'):
              line = aapt_stream.next()

          if len(type['resources']) > 0:
            type['type'] = type['resources'][0]['desc']['type']

          while line.startswith('      config'):
            # config
            config = self.__parseAaptResourceConfig(line)
            type['configs'].append(config)

            # resource in config
            line = aapt_stream.next()
            while line.startswith('        resource'):
              resconfig = self.__parseAaptResourceResource(line)

              # add resource to config
              config['resources'].append(resconfig)
              # add config to resource
              for res in type['resources']:
                if res['desc'] == resconfig['desc']:
                  res['values'].append(
                      { 'config': config, 'resconfig': resconfig })
                  break
              line = aapt_stream.next()

        else:
          # print "TRASH: {0}".format(line)
          line = aapt_stream.next()
    except StopIteration:
      return self.__dump_resources

  # function to extract strings from an APK file
  def getDumpStrings(self):
    #lazy load
    if self.__dump_strings is not None:
      return self.__dump_strings

    aapt_stream = os.popen("{0} dump strings \"{1}\"".format(Configs.AAPT_BIN, self.__apk_path))
    self.__dump_strings=[]

    string = None
    try:
      line = aapt_stream.next()
      if line.rstrip() == 'String pool is unitialized.':
        # there is no strings (return empty array)
        return self.__dump_strings
      line = aapt_stream.next()
      id = 0
      while True:

        # "String #0: res/drawable/actionbar_menu_forward.xml"
        if line.startswith('String #'):
          # new string
          # save current string
          if string != None:
            self.__dump_strings.append(string)

          # create new string
          string = line[line.index(':') + 2:-1]

          # /TEMPORARY
          linesplitted = line.split()
          ida = int(linesplitted[1][1:-1])
          if ida != id:
            # it's a temporary verification to check if 'id' is incremental
            sys.exit("Something is wrong... string id counter is not working... {0} != {1}".format(id, ida))
          #/TEMPORARY
          id = id + 1

        else:
          # append to current string
          string += "\n{0}".format(line[:-1])

        # new line
        line = aapt_stream.next()

    except StopIteration:
      if string != None:
        self.__dump_strings.append(string)
      return self.__dump_strings

  def __parseXmltreeItem(self, line):
    # get identation level
    spaces = 0
    for c in line:
      if c == ' ':
        spaces += 1
      else:
        break;
    identation_level = spaces/2
    stringel=line[spaces:]

    if stringel[0] == 'E':
      # element/node
      r = re.compile('E: (.*) \(line=(\d+)\)')
      matches = r.match(stringel)
      return { "identation_level": identation_level, "type": 'E', "node": ET.Element(matches.group(1)) }
    elif stringel[0] == 'C':
      # element content
      r = re.compile('C: "(.*)"$')
      matches = r.match(stringel)
      return { "identation_level": identation_level, "type": 'C', "content": matches.group(1) }
    elif stringel[0] == 'A':
      # attribute
      # match groups: ...2_______...3______...5___.............7__.......8________.............9___......
      r = re.compile('A: (([^:]*):)?([^(]*)(\((.*)\))?=(\(type (.*)\))?"?([^(" ]*)"? ?(\(Raw: "(.*)"\))?$')
      matches = r.match(stringel)
      # groups
      return {
          "identation_level": identation_level,
          "type":             'A',
          "namespace":        matches.group(2),
          "name":             matches.group(3),
          "name_code":        matches.group(5),
          "value_type":       matches.group(7),
          "value":            matches.group(8),
          "value_raw":        matches.group(9)
      }
    elif stringel[0] == 'N':
      # namespace
      r = re.compile('N: (.*)=(.*)$')
      matches = r.match(stringel)
      return { "identation_level": identation_level, "type": 'N', "name": matches.group(1), "content": matches.group(2) }
    else:
      raise Exception("[XmlTree] invalid type: {0}".format(stringel[0]))

  # function to extract strings from an APK file
  def getDumpXmlTree(self, xmlpath):
    aapt_stream = os.popen("{0} dump xmltree \"{1}\" \"{2}\"".format(Configs.AAPT_BIN, self.__apk_path, xmlpath))

    try:

      line = aapt_stream.next()
      current_item = self.__parseXmltreeItem(line)

      # reading namespaces TODO: add them to the xml.
      namespaces = []
      while current_item['type'] == 'N':
        namespaces.append(current_item['type'])
        line = aapt_stream.next()
        current_item = self.__parseXmltreeItem(line)

      # reading root element
      parent_element = current_item['node']
      parent_stack = [None]*(current_item['identation_level'])
      parent_stack.append(parent_element)

      # reading line by line adding xml elements according do identation
      line = aapt_stream.next()
      while line:
        current_item = self.__parseXmltreeItem(line)

        # update parent element
        parent_stack = parent_stack[:current_item['identation_level']]
        parent_element = parent_stack[-1]

        if current_item['type'] == "C":
          # adding element content: <element>content</content>
          parent_element.text = current_item['content']
        elif current_item['type'] == "A":
          # adding attribute to element: <element attribute="attribute value">content</content>
          parent_element.attrib[current_item['name']] = current_item['value']
        elif current_item['type'] == "N":
          # namespaces must be declared on the begining of the xml.
          raise Excetpion("Namespace item not expected in XmlTree.")
        else:
          # adding the new element to its parent.
          parent_element.append(current_item['node'])
          parent_element = current_item['node']

          # adding current element to "parent_stack"
          parent_stack.append(current_item['node'])

        line = aapt_stream.next()


    except StopIteration:
      # the "parent_stack" was filled with None elements if this xml has namespaces
      for item in parent_stack:
        if item != None:
          return item
      raise Exception("something is wrong with this xml: {0}".format(xmlpath))
  
  def getList(self):
    #lazy load
    if self.__list is not None:
      return self.__list

    aapt_stream = os.popen("{0} list \"{1}\"".format(Configs.AAPT_BIN, self.__apk_path))
    self.__list=[]

    try:
      line = aapt_stream.next()
      while True:
        if line is not None:
          self.__list.append(line)

        # new line
        line = aapt_stream.next()

    except StopIteration:
      return self.__list

  def get_apk_path(self):
    return self.__apk_path
  
  def getPackage(self):
    if self.getDumpBadging()[0]['values'] and self.getDumpBadging()[0]['values']['name']:
      return self.getDumpBadging()[0]['values']['name']
    else:
      return None

  def getVersionCode(self):
    if self.getDumpBadging()[0]['values'] and self.getDumpBadging()[0]['values']['versionCode']:
      return self.getDumpBadging()[0]['values']['versionCode']
    else:
      return None

  def getVersionName(self):
    if self.getDumpBadging()[0]['values'] and self.getDumpBadging()[0]['values']['versionName']:
      return self.getDumpBadging()[0]['values']['versionName']
    else:
      return None

  def getResourceConfigValue(self, resconfig):
    type = resconfig['desc']['type']
    if type == 'string' or type == 'drawable' or type == 'xml' or type == 'layout' or type == 'anim' or type == 'raw' or type == 'menu':
      return self.getDumpStrings()[resconfig['d']]
    elif type == 'bool':
      # 0x00000000: False, 0xffffffff: True
      return resconfig['d'] != 0
    elif type == 'color':
      # return hexa string
      return hex(resconfig['d'])
    elif type == 'integer' or resconfig.has_key('d'):
      # type in [ 'integer', 'dimen' ]
      return resconfig['d']
    else:
      # type in [ 'style', 'array', 'attr' ]
      # for these types aapt return <bag> string.
      raise ValueError("It's impossible to get values for \"{0}\" type. Aapt doesn't support it.".format(type))

  def get_resource_values_by_regex(self, regex_str):
    resource_values = []
    regex = re.compile(regex_str)
    dump_strings = self.getDumpStrings()
    for idx, string_value in enumerate(self.getDumpStrings()):
      if regex.search(string_value):
        resource_values.extend(self.get_resource_values_by_string_idx(idx))
    return resource_values

  def get_resource_values_by_string_idx(self, idx):
    resource_values = []
    for type in self.getDumpResources():
      if type['type'] == 'string':
        for resource in type['resources']:
          for resource_value in resource['values']:
            if resource_value['resconfig']['d'] == idx:
              resource_value['string_value'] = self.getDumpStrings()[idx]
              resource_values.append(resource_value)
    return resource_values
