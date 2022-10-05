#!/usr/bin/env python3
#
# -*-python-*-
#
################################################################################
# License
################################################################################
# The MIT License (MIT)
#
# Copyright (c) 2015 Jeremy Whitlock
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
################################################################################

import configparser, datetime, getpass, os, re, sys, tempfile, shutil
from optparse import OptionParser

try:
  import ldap
except ImportError:
  sys.stderr.write("Unable to locate the 'ldap' module. Please install python-ldap. " \
                   "(http://python-ldap.sourceforge.net)\n")
  sys.exit(1)

################################################################################
# Configuration Options
# uncomment if you want to use them instead of the command line parameters
################################################################################

# This is the distinguished name used to bind to the LDAP server.
#bind_dn = "CN=Jeremy Whitlock,OU=Users,DC=subversion,DC=thoughtspark,DC=org"

# This is the password for the user connecting to the LDAP server.
#bind_password = "pa55w0rd"

# This is the fully-qualified url to the LDAP server.
#url = "ldap://localhost:389"

# This is the distinguished name to where the group search will start.
#base_dn = "DC=subversion,DC=thoughtspark,DC=org"

# This is the query/filter used to identify group objects.
#group_query = "objectClass=group"

# This is the known group DNs that will be used directly as a group
# Default: group_dns = []
#group_dns = "CN=Release Managers,OU=Groups,DC=subversion,DC=thoughtspark,DC=org"

# This is the attribute of the group object that stores the group memberships.
#group_member_attribute = "member"

# This is the query/filter used to identify user objects.
#user_query = "objectClass=user"

# This is the attribute of the user object that stores the userid to be used in
# the authz file.
#userid_attribute = "cn"

# This is the fully-qualified path to the authz file to write to.
#authz_path = "/opt/svn/svn_authz.txt"

# Add members of sub-groups recursively
# does not mean OU recursive (which is by design)
#followgroups = False

################################################################################
# Runtime Options
# uncomment if you want to use them instead of the command line parameters
################################################################################

# Keep the exact LDAP group names without alteration.
# Useful if your group names contain non-word characters, i.e. not in [A-Za-z0-9_].
#keep_names = False

# Do not show logging information, except exit messages.
#silent = False

# This indicates whether or not to give more details during the execution.
# Overrides -q .
#verbose = True

################################################################################
# Application Settings
################################################################################

application_name = "LDAP Groups to Subversion Authz Groups Bridge"
application_version = "1.3.0"
application_description = "The '%s' is a simple script that will query your " \
                          "directory server for group objects and create a " \
                          "representation of those groups in your Subversion " \
                          "authorization (authz) file." % application_name

################################################################################
# Business Logic
################################################################################

def bind():
  """This function will bind to the LDAP instance and return an ldapobject."""

  ldapobject = ldap.initialize(url)

  ldapobject.bind_s(bind_dn, bind_password)

  if verbose:
    if is_outfile_specified:
      sys.stdout.write("Successfully bound to %s...\n" % url)
    else:
      sys.stderr.write("Successfully bound to %s...\n" % url)

  return ldapobject

# bind()
  
def search_for_groups(ldapobject):
  """This function will search the LDAP directory for group definitions."""

  groups = []
  result_set = get_ldap_search_resultset(base_dn, group_query, ldapobject)

  if (len(result_set) == 0):
    if not silent:
      sys.stderr.write("The group_query %s did not return any results.\n" % group_query)
    return

  for i in range(len(result_set)):
    for entry in result_set[i]:
      groups.append(entry)

  if verbose:
    if is_outfile_specified:
      sys.stdout.write("%d groups found.\n" % len(groups))
    else:
      sys.stderr.write("%d groups found.\n" % len(groups))

  return groups

# search_for_groups()

def get_groups(ldapobject):
  """This function will search the LDAP directory for the specificied group DNs."""

  groups = []
  for group_dn in group_dns:
    try:
      result_set = get_ldap_search_resultset(group_dn, group_query, ldapobject, ldap.SCOPE_BASE)
      for i in range(len(result_set)):
        for entry in result_set[i]:
          groups.append(entry)
    except ldap.NO_SUCH_OBJECT as e:
      if not silent:
        sys.stderr.write("Couldn't find a group with DN %s.\n" % group_dn)
      raise e

  if verbose:
    if is_outfile_specified:
      sys.stdout.write("%d groups found.\n" % len(groups))
    else:
      sys.stderr.write("%d groups found.\n" % len(groups))

  return groups

# get_groups()

def get_ldap_search_resultset(base_dn, group_query, ldapobject, scope=ldap.SCOPE_SUBTREE):
  """This function will return a query result set."""
  result_set = []
  if type(base_dn) == str:
#      print(type(base_dn))
      pass
  else:
      base_dn = base_dn.decode("utf-8")
#  print(base_dn)
  result_id = ldapobject.search(base_dn, scope, group_query)

  while 1:
    result_type, result_data = ldapobject.result(result_id, 0)
    if (result_type == ldap.RES_SEARCH_ENTRY):
        result_set.append(result_data)
    elif (result_type == ldap.RES_SEARCH_RESULT):
      break
  return result_set   

# get_ldap_search_resultset()

def get_members_from_group(group, ldapobject):
  """Get members from a group and recursively (optional) in members that are groups
  themselves"""
  members = []
  group_members = []
  if verbose:
    if is_outfile_specified:
      sys.stdout.write("+")
    else:
      sys.stderr.write("+")
  #if group.has_key(group_member_attribute):
  if group_member_attribute in group:
    group_members = group[group_member_attribute]

  # We need to check if the member is a group and handle specially
  for member in group_members:
    try:
      user = get_ldap_search_resultset(member, user_query, ldapobject)

      if (len(user) == 1):
        # The member is a user
        attrs = user[0][0][1]

        #if (attrs.has_key(userid_attribute)):
        if userid_attribute in attrs:
          if verbose:
            if is_outfile_specified:
              sys.stdout.write(".")
            else:
              sys.stderr.write(".")
          if type(attrs[userid_attribute][0]) == str:
              lowerattr = attrs[userid_attribute][0]    
          else:
              lowerattr = attrs[userid_attribute][0].decode("utf-8")   
          #members.append(str.lower(str(attrs[userid_attribute][0])))
          members.append(str.lower(lowerattr))
        else:
          if not silent:
            sys.stderr.write("[WARNING]: %s does not have the %s attribute...\n" \
                              % (user[0][0][0], userid_attribute))
      else:
        # Check to see if this member is really a group
        mg = get_ldap_search_resultset(member, group_query, ldapobject)
 
        if (len(mg) == 1):
          # The member is a group
          if followgroups:
            # We walk in this group to add its members
            for item in get_members_from_group(mg[0][0][1], ldapobject):
              members.append(item)
          else:
            # We add the group as itself
            try:
              members.append("GROUP:" + mg[0][0][0])
            except TypeError:
              if not silent:
                sys.stderr.write("[WARNING]: TypeError with %s...\n" % mg[0])
        else:
          if not silent:
            sys.stderr.write("[WARNING]: %s is a member of %s but is neither a group " \
                             "nor a user.\n" % (member, group['cn'][0]))
    except ldap.LDAPError as error_message:
      if not silent:
#        print(error_message)
        pass
        sys.stderr.write("[WARNING]: %s object was not found...\n" % member)
  # uniq values
  members = sorted(list(set(members)))
  if verbose:
    if is_outfile_specified:
      sys.stdout.write("-")
    else:
      sys.stderr.write("-")
  return members

def create_group_model(groups, ldapobject):
  """This function will take the list of groups created by search_for_groups()
and will create a group membership model for each group."""

  memberships = []
  groupmap = create_group_map(groups)

  if groups:
    for group in groups:
      if verbose:
        if is_outfile_specified:
          sys.stdout.write("[INFO]: Processing group %s: " % group[1]['cn'][0])
        else:
          sys.stderr.write("[INFO]: Processing group %s: " % group[1]['cn'][0])
      members = get_members_from_group(group[1], ldapobject)
      memberships.append(members)
      if verbose:
        if is_outfile_specified:
          sys.stdout.write("\n")
        else:
          sys.stderr.write("\n")

  return (groups, memberships)

# create_group_model()

def get_dict_key_from_value(dict, value):
  """Returns the key of the dictionary entry with the matching value."""
  
  for k, v in dict.items():
    if (v == value):
      return k
  
  return None

# get_dict_key_from_value()

def create_group_map(groups):
  groupmap = {}
  dups = {}

  if groups:
    for group in groups:
      cn = simplify_name(group[1]['cn'][0])
      if not cn in groupmap: 
      #if (not groupmap.has_key(cn)):
        groupmap[cn] = group[0]
      else:
        #if (not dups.has_key(cn)):
        if not cn in dups:
          dups[cn] = 1
        else:
          index = dups[cn]
          
          dups[cn] = (index + 1)
      
        groupmap[cn + str(dups[cn])] = group[0]
  
  return groupmap

# create_group_map()

def simplify_name(name):
  """Creates an authz simple group name."""
#  name = name.decode("utf-8")
#  print (name)
  if type(name) == str:
     pass
  else:
     name = name.decode("utf-8")
  return name if (keep_names) else re.sub(r"\W", "",name)

# simplify_name()

def print_group_model(groups, memberships):
  """This function will write the groups and their members to a file."""

  if not groups:
    return

  now = datetime.datetime.now()
  header_start = "### Start generated content: " + application_name +" ("
  header_middle =  now.strftime("%Y/%m/%d %H:%M:%S")
  header_end = ") ###"
  header = header_start + header_middle + header_end
  footer = "### End generated content: " + application_name + " ###\n"
  text_after_content = ""
  
  file = None
  filemode = None
  tmp_fd, tmp_authz_path = tempfile.mkstemp()
  
  if ((authz_path != None) and (authz_path != "None")):
    if (os.path.exists(authz_path)):
      filemode = os.stat(authz_path)
      file = open(authz_path, 'r')
      tmpfile = open(tmp_authz_path, 'w')
    
      # Remove previous generated content
      inside_content = False
      before_content = True
      
      for line in file.readlines(): # read from the existing file
        if (inside_content): # currently between header and footer
          if (line.find(footer) > -1): # footer found
            inside_content = False
        else:
          if (line.find(header_start) > -1): # header found
            inside_content = True
            before_content = False
          else:
            # write the original content to the new file only if it was not auto-generated
            if before_content:
              tmpfile.write(line) # found before the header: write directly
            else:
              text_after_content += line # found after the header, write to a temporary variable
      
      file.close()
      tmpfile.close()
  
  if (os.path.exists(tmp_authz_path)):
    cp = configparser.ConfigParser()
    cp.read(tmp_authz_path)
    
    if (not cp.has_section("groups")):
      tmpfile = open(tmp_authz_path, 'a')
      tmpfile.write("[groups]\n")
      tmpfile.close()
    # else: do not write the "[group]" tag because it already exists
  else:
    tmpfile = open(tmp_authz_path, 'a')
    tmpfile.write("[groups]\n")
    tmpfile.close()
  
  needs_new_line = False
  
  tmpfile = open(tmp_authz_path, 'r')
  if (tmpfile.readlines()[-1].strip() != ''): # if the last line is not empty
    needs_new_line = True # ask to insert a new empty line at the end
  tmpfile.close()
  
  tmpfile = open(tmp_authz_path, 'a')
  
  if (needs_new_line):
    tmpfile.write("\n")
  
  tmpfile.write(header + "\n")
  
  groupmap = create_group_map(groups)

  if groups:
    for i in range(len(groups)):
      if (i != 0):
        tmpfile.write("\n")
  
      short_name = simplify_name(get_dict_key_from_value(groupmap, groups[i][0]))
    
      tmpfile.write(short_name + " = ")
    
      users = []
      for j in range(len(memberships[i])):
        user = None
        if (memberships[i][j].find("GROUP:") == 0):
          groupkey = get_dict_key_from_value(groupmap, memberships[i][j].replace("GROUP:",""))
          if groupkey:
            user = "@" + groupkey
          else:
            if not silent:
              sys.stderr.write("[WARNING]: subgroup not in search scope: %s. This means " %
                                memberships[i][j].replace("GROUP:","") +
                               "you won't have all members in the SVN group: %s.\n" % 
                                short_name)
        else:
          user = memberships[i][j]

        if user:
          users.append(user)

      tmpfile.write(", ".join(users))
  
  generate_legend(tmpfile, groups)
  
  tmpfile.write("\n" + footer)
  
  tmpfile.write(text_after_content) # write back original content to file
  
  tmpfile.close()

  if authz_path:
    if (os.path.exists(authz_path + ".bak")):
      os.remove(authz_path + ".bak")
  
    if (os.path.exists(authz_path)):
      shutil.move(authz_path, authz_path + ".bak")
  
    shutil.move(tmp_authz_path, authz_path)
    os.chmod(authz_path, filemode.st_mode)
  else:
    tmpfile = open(tmp_authz_path, 'r')

    for line in tmpfile.readlines():
      sys.stdout.write(line)

    tmpfile.close()

    os.remove(tmp_authz_path)

# print_group_model()

def generate_legend(output, groups):
  """This function will generate, and write, the legend to file."""
  if groups:
    output.write("\n")
    output.write("\n###########################################################" +
                 "#####################\n")
    output.write("###########   " + application_name +" (Legend)  ##########\n")
    output.write("###########################################################" +
                 "#####################\n")
  
    groupmap = create_group_map(groups)
  
    for group in groups:
      short_name = simplify_name(get_dict_key_from_value(groupmap, group[0]))
    
      output.write("### " + short_name + " = " + str(group[0]) + "\n")
  
    output.write("###########################################################" +
                 "#####################\n")

# generate_legend()

def load_cli_properties(parser):
  """This function will set the local properties based on cli arguments."""

  global bind_dn
  global bind_password
  global url
  global base_dn
  global group_query
  global group_dns
  global group_member_attribute
  global user_query
  global userid_attribute
  global followgroups
  global authz_path
  global keep_names
  global silent
  global verbose
  
  global is_outfile_specified

  (options, args) = parser.parse_args(args=None, values=None)

  bind_dn = options.bind_dn
  bind_password = options.bind_password
  url = options.url
  base_dn = options.base_dn
  group_query = options.group_query
  group_dns = options.group_dns
  group_member_attribute = options.group_member_attribute
  user_query = options.user_query
  userid_attribute = options.userid_attribute
  followgroups = options.followgroups
  authz_path = options.authz_path
  keep_names = options.keep_names
  silent = options.silent
  verbose = options.verbose
  
  is_outfile_specified = (authz_path != None) and (authz_path != "None")

# load_cli_properties()

def create_cli_parser():
  """Creates an OptionParser and returns it."""
  usage = "usage: %prog [options]"
  parser = OptionParser(usage=usage, description=application_description)

  parser.add_option("-d", "--bind-dn", dest="bind_dn",
                    help="The Distinguished Name (DN) used to bind to the " \
                         "directory with. " \
                         "[Example: CN=Jeremy Whitlock,OU=Users," \
                         "DC=subversion,DC=thoughtspark,DC=org]")
  parser.add_option("-p", "--bind-password", dest="bind_password",
                    help="The password for the user specified with the --bind-dn . " \
                         "[Example: pa55w0rd]")
  parser.add_option("-l", "--url", dest="url",
                    help="The fully-qualified URL (scheme://hostname:port) to " \
                         "the directory server. " \
                         "[Example: ldap://localhost:389]")
  parser.add_option("-b", "--base-dn", dest="base_dn",
                    help="The Distinguished Name (DN) at which the recursive " \
                         "group search will start. " \
                         "[Example: DC=subversion,DC=thoughtspark,DC=org]")
  parser.add_option("-g", "--group-query", dest="group_query",
                    default="objectClass=group",
                    help="The query/filter used to identify group objects. " \
                         "[Example: objectClass=group] " \
                         "[Default: %default]")
  parser.add_option("-k", "--known-group-dn", action="append", dest="group_dns",
                    help="The known group Distinguished Name(s) that will be used " \
                         "directly as a group. Can be more than 1. When this option is " \
                         "used, the --group-query will not be used for searching. " \
                         "Useful if your LDAP server contains a lot of groups. " \
                         "[Example: CN=Release Managers,OU=Groups," \
                         "DC=subversion,DC=thoughtspark,DC=org]")
  parser.add_option("-m", "--group-member-attribute",
                    dest="group_member_attribute", default="member",
                    help="The attribute of the group object that stores the " \
                         "group memberships. " \
                         "[Example: member] " \
                         "[Default: %default]")
  parser.add_option("-u", "--user-query", dest="user_query",
                    default="objectClass=user",
                    help="The query/filter used to identify user objects. " \
                         "[Example: objectClass=user] " \
                         "[Default: %default]")
  parser.add_option("-i", "--userid_attribute", dest="userid_attribute",
                    default="cn",
                    help="The attribute of the user object that stores the " \
                         "userid to be used in the authz file. " \
                         "[Example: cn] " \
                         "[Default: %default]")
  parser.add_option("-f", "--follow-groups", action="store_true",
                    dest="followgroups", default=False,
                    help="Follow sub-groups, i.e. add members of sub-groups " \
                         "recursively. Does not mean OU recursive, which is by design.")
  parser.add_option("-z", "--authz-path", dest="authz_path",
                    help="The fully-qualified path to the authz file to be updated/created.")
  parser.add_option("-n", "--keep-names", action="store_true",
                    dest="keep_names", default=False,
                    help="Keep the exact LDAP group names without alteration. " \
                         "Useful if your group names contain non-word " \
                         "characters, i.e. not in [A-Za-z0-9_].")
  parser.add_option("-q", "--quiet", action="store_true",
                    dest="silent", default=False,
                    help="Do not show logging information, except exit messages.")
  parser.add_option("-v", "--verbose", action="store_true",
                    dest="verbose", default=False,
                    help="Give more details during the execution. Overrides -q .")

  return parser

# create_cli_parser()

def are_properties_set():
  """This function will perform a simple test to make sure none of the
properties are 'None'."""
  try:
    if (bind_dn == None):
      return False
    if (url == None):
      return False
    if (base_dn == None):
      return False
    if (group_query == None):
      return False
    if (group_member_attribute == None):
      return False
    if (user_query == None):
      return False
    if (userid_attribute == None):
      return False
  except:
    # one of the variables may not exist (i.e. not defined at the start of the script)
    return False
  
  # bind_password is not checked since if not passed, the user will be prompted
  # authz_path is not checked since it can be 'None' signifying stdout output

  return True

# are_properties_set()

def get_unset_properties():
  """This function returns a list of unset properties necessary to run."""
  unset_properties = []

  if (bind_dn == None):
    unset_properties += ['bind-dn']
  if (url == None):
    unset_properties += ['url']
  if (base_dn == None):
    unset_properties += ['base-dn']
  if (group_query == None):
    unset_properties += ['group-query']
  if (group_member_attribute == None):
    unset_properties += ['group-member-attribute']
  if (user_query == None):
    unset_properties += ['user-query']
  if (userid_attribute == None):
    unset_properties += ['userid-attribute']

  return unset_properties

# get_unset_properties()

def main():
  """This function is the entry point for this script."""
  
  parser = None

  # If all necessary options are not properly set in the current script file
  # (see at the top of the script)
  if not are_properties_set():
    # Attempt to load them from the command line parameters
    parser = create_cli_parser()
    load_cli_properties(parser)

  # if some properties are not set at this point, there is an error
  if not are_properties_set():
    sys.stderr.write("There is not enough information to proceed.\n")
    
    for prop in get_unset_properties():
      sys.stderr.write("'%s' was not passed\n" % prop)

    sys.stderr.write("\n")
    if parser != None:
      parser.print_help()
      parser.exit()

  # Allow user to type in password if missing
  global bind_password

  if bind_password == None:
    bind_password = getpass.getpass("Please provide the bind DN password: ")

  ldapobject = None
  groups = None
  memberships = None

  try:
    ldapobject = bind()
  except ldap.LDAPError as error_message:
    sys.stderr.write("Could not connect to %s. Error: %s \n" % (url, error_message))
    sys.exit(1)

  try:    
    if group_dns:
      groups = get_groups(ldapobject)    
    else:
      groups = search_for_groups(ldapobject)
  except ldap.LDAPError as error_message:
    sys.stderr.write("Error performing search: %s \n" % error_message)
    sys.exit(1)

  if groups and len(groups) == 0:
    sys.stderr.write("There were no groups found with the group_query / group_dns " \
                     "you supplied.\n")
    sys.exit(1)

  try:
    memberships = create_group_model(groups, ldapobject)[1]
  except ldap.LDAPError as error_message:
    sys.stderr.write("Error creating group model: %s\n" % error_message)
    sys.exit(1)

  print_group_model(groups, memberships)

# main()

if __name__ == "__main__":
  main()
