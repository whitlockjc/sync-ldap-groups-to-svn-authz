#!/usr/bin/env python
#
# -*-python-*-
#
################################################################################
# License
################################################################################
# Copyright (c) 2006 Jeremy Whitlock.  All rights reserved.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
################################################################################

import ConfigParser, datetime, getpass, os, re, sys, tempfile, shutil
from optparse import OptionParser

try:
  import ldap
except ImportError:
  print("Unable to locate the 'ldap' module.  Please install python-ldap.  " \
        "(http://python-ldap.sourceforge.net)")
  sys.exit(1)

################################################################################
# Configuration Options
################################################################################

# This is the distinguished name used to bind to the LDAP server.
# [Example: CN=Jeremy Whitlock,OU=Users,DC=subversion,DC=thoughtspark,DC=org]
bind_dn = None

# This is the password for the user connecting to the LDAP server.
# [Example: pa55w0rd]
bind_password = None

# This is the fully-qualified url to the LDAP server.
# [Example: ldap://localhost:389]
url = None

# This is the distinguished name to where the group search will start.
# [Example: DC=subversion,DC=thoughtspark,DC=org]
base_dn = None

# This is the query/filter used to identify group objects.
# [Example: objectClass=group]
group_query = "objectClass=group"

# This is the attribute of the group object that stores the group memberships.
# [Example: member]
group_member_attribute = "member"

# This is the query/filter used to identify user objects.
# [Example: objectClass=user]
user_query = "objectClass=user"

# This is the attribute of the user object that stores the userid to be used in
# the authz file.  [Example: cn]
userid_attribute = "cn"

# This is the fully-qualified path to the authz file to write to.
# [Example: /opt/svn/svn_authz.txt]
authz_path = None

################################################################################
# Runtime Options
################################################################################

# This indicates whether or not to output logging information
verbose = True

################################################################################
# Application Settings
################################################################################

application_name = "LDAP Groups to Subversion Authz Groups Bridge"
application_version = "1.0.1"
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

  ldapobject.bind(bind_dn, bind_password)

  if verbose:
    print("Successfully bound to %s..." % url)

  return ldapobject

# bind()
  
def search_for_groups(ldapobject):
  """This function will search the LDAP directory for group definitions."""

  groups = []
  result_set = get_ldap_search_resultset(base_dn, group_query, ldapobject)

  if (len(result_set) == 0):
    if verbose:
      print("The group_query %s did not return any results." % group_query)
    return

  for i in range(len(result_set)):
    for entry in result_set[i]:
      groups.append(entry)

  if verbose:
    print("%d groups found." % len(groups))

  return groups

# search_for_groups()

def get_ldap_search_resultset(base_dn, group_query, ldapobject):
  """This function will return a query result set."""
  result_set = []
  result_id = ldapobject.search(base_dn, ldap.SCOPE_SUBTREE, group_query)

  while 1:
    result_type, result_data = ldapobject.result(result_id, 0)

    if (result_type == ldap.RES_SEARCH_ENTRY):
        result_set.append(result_data)
    elif (result_type == ldap.RES_SEARCH_RESULT):
      break

  return result_set   

# get_ldap_search_resultset()

def create_group_model(groups, ldapobject):
  """This function will take the list of groups created by search_for_groups()
and will create a group membership model for each group."""

  memberships = []
  groupmap = create_group_map(groups)

  if groups:
    for group in groups:
      group_members = []
      members = []
    
      if group[1].has_key(group_member_attribute):
        group_members = group[1][group_member_attribute]
    
      # We need to check for if the member is a group and handle specially
      for member in group_members:
        try:
          user = get_ldap_search_resultset(member, user_query, ldapobject)

          if (len(user) == 1):
            # The member is a user
            attrs = user[0][0][1]
        
            if (attrs.has_key(userid_attribute)):
              members.append(attrs[userid_attribute][0])
            else:
              if verbose:
                print("[WARNING]: %s does not have the %s attribute..." \
                      % (user[0][0][0], userid_attribute))
          else:
            # Check to see if this member is really a group
            mg = get_ldap_search_resultset(member, group_query, ldapobject)
          
            if (len(mg) == 1):
              # The member is a group
              try:
                members.append("GROUP:" + get_dict_key_from_value(groupmap,
                                                                 mg[0][0][0]))
              except TypeError:
                print("[WARNING]: %s error..." % mg[0])
            else:
              if verbose:
                print("[WARNING]: %s is a member of %s but is neither a group " \
                      "or a user." % (member, group[1]['cn'][0]))
        except ldap.LDAPError, error_message:
          if verbose:
            print("[WARNING]: %s object was not found..." % member)

      memberships.append(members)

  return (groups, memberships)

# create_group_model()

def get_dict_key_from_value(dict, value):
  """Returns the key of the dictionary entry with the matching value."""
  
  for k, v in dict.iteritems():
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
    
      if (not groupmap.has_key(cn)):
        groupmap[cn] = group[0]
      else:
        if (not dups.has_key(cn)):
          dups[cn] = 1
        else:
          index = dups[cn]
          
          dups[cn] = (index + 1)
      
        groupmap[cn + str(dups[cn])] = group[0]
  
  return groupmap

# create_group_map()

def simplify_name(name):
  """Creates an authz simple group name."""
  return re.sub("\W", "", name)

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
  footer = "### End generated content: " + application_name + " ###"
  
  file = None
  tmp_fd, tmp_authz_path = tempfile.mkstemp()
  
  if ((authz_path != None) and (authz_path != "None")):
    if (os.path.exists(authz_path)):
      file = open(authz_path, 'r')
      tmpfile = open(tmp_authz_path, 'w')
    
      # Remove previous generated content
      inside_content = False
      
      for line in file.readlines():
        if (inside_content):
          if (line.find(footer) > -1):
            inside_content = False
        else:
          if (line.find(header_start) > -1):
            inside_content = True
          else:
            tmpfile.write(line)
      
      file.close()
      tmpfile.close()
  
  if (os.path.exists(tmp_authz_path)):
    cp = ConfigParser.ConfigParser()
    cp.read(tmp_authz_path)
    
    if (not cp.has_section("groups")):
      tmpfile = open(tmp_authz_path, 'a')
      
      tmpfile.write("[groups]\n")
      
      tmpfile.close()
  else:
    tmpfile = open(tmp_authz_path, 'a')
      
    tmpfile.write("[groups]\n")
    
    tmpfile.close()
  
  needs_new_line = False
  
  tmpfile = open(tmp_authz_path, 'r')
  
  if (tmpfile.readlines()[-1].strip() != ''):
    needs_new_line = True
  
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
    
      for j in range(len(memberships[i])):
        if (j != 0):
          tmpfile.write(", ")
      
        if (memberships[i][j].find("GROUP:") == 0):
          tmpfile.write(memberships[i][j].replace("GROUP:","@"))
        else:
          tmpfile.write(memberships[i][j])
  
  generate_legend(tmpfile, groups)
  
  tmpfile.write("\n" + footer)
  
  tmpfile.close()

  if authz_path:
    if (os.path.exists(authz_path + ".bak")):
      os.remove(authz_path + ".bak")
  
    if (os.path.exists(authz_path)):
      shutil.move(authz_path, authz_path + ".bak")
  
    shutil.move(tmp_authz_path, authz_path)
  else:
    tmpfile = open(tmp_authz_path, 'r')

    for line in tmpfile.readlines():
      print(line)

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
  global group_member_attribute
  global user_query
  global userid_attribute
  global authz_path
  global verbose

  (options, args) = parser.parse_args(args=None, values=None)

  bind_dn = options.bind_dn
  bind_password = options.bind_password
  url = options.url
  base_dn = options.base_dn
  group_query = options.group_query
  group_member_attribute = options.group_member_attribute
  user_query = options.user_query
  userid_attribute = options.userid_attribute
  authz_path = options.authz_path
  verbose = options.verbose

# load_cli_properties()

def create_cli_parser():
  """Creates an OptionParser and returns it."""
  usage = "usage: %prog [options]"
  parser = OptionParser(usage=usage, description=application_description)

  parser.add_option("-d", "--bind-dn", dest="bind_dn",
                    help="The DN of the user to bind to the directory with")
  parser.add_option("-p", "--bind-password", dest="bind_password",
                    help="The password for the user specified with the " \
                         "--bind-dn")
  parser.add_option("-l", "--url", dest="url",
                    help="The url (scheme://hostname:port) for the directory " \
                         "server")
  parser.add_option("-b", "--base-dn", dest="base_dn",
                    help="The DN at which to perform the recursive search")
  parser.add_option("-g", "--group-query", dest="group_query",
                    default="objectClass=group",
                    help="The query/filter used to identify group objects. " \
                         "[Default: %default]")
  parser.add_option("-m", "--group-member-attribute",
                    dest="group_member_attribute", default="member",
                    help="The attribute of the group object that stores the " \
                         "group memberships.  [Default: %default]")
  parser.add_option("-u", "--user-query", dest="user_query",
                    default="objectClass=user",
                    help="The query/filter used to identify user objects. " \
                         "[Default: %default]")
  parser.add_option("-i", "--userid_attribute", dest="userid_attribute",
                    default="cn",
                    help="The attribute of the user object that stores the " \
                         "userid to be used in the authz file.  " \
                         "[Default: %default]")
  parser.add_option("-z", "--authz-path", dest="authz_path",
                    help="The path to the authz file to update/create")
  parser.add_option("-q", "--quiet", action="store_false", dest="verbose",
                    default="True", help="Suppress logging information")

  return parser

# create_cli_parser()

def are_properties_set():
  """This function will perform a simple test to make sure none of the
properties are 'None'."""
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

  # Create the OptionParser
  parser = create_cli_parser()

  # Attempt to load properties from the command line if necessary
  if not are_properties_set():
    load_cli_properties(parser)

  if not are_properties_set():
    print("There is not enough information to proceed.")
    
    for prop in get_unset_properties():
      print("'%s' was not passed" % prop)

    print("")
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
  except ldap.LDAPError, error_message:
    print("Could not connect to %s. Error: %s " % (url, error_message))
    sys.exit(1)

  try:
    groups = search_for_groups(ldapobject)
  except ldap.LDAPError, error_message:
    print("Error performing search: %s " % error_message)
    sys.exit(1)

  if groups and len(groups) == 0:
    print("There were no groups found with the group_query you supplied.")
    sys.exit(0)

  try:
    memberships = create_group_model(groups, ldapobject)[1]
  except ldap.LDAPError, error_message:
    print("Error creating group model: %s" % error_message)
    sys.exit(1)

  print_group_model(groups, memberships)

# main()

if __name__ == "__main__":
  main()
