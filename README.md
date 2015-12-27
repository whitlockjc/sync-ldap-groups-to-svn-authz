# Disclaimer

This script was written almost 10 years ago and has been barely maintained.  At the request of the community members I have moved this project from [BitBucket](https://bitbucket.org/whitlockjc/jw-tools) to GitHub.  *(During the migration I changed the license from GPLv3 to MIT.)*  My hope is that this will simplify the involvement of the community.  I do hope to spend some time on this project to get it rewritten not only to address the bugs reported but also to clean things up.  *(I wrote this when my Python kung fu was not all that great and it shows somewhat.)*

# Change Log

2015-08-25 (version 1.3.0):
 - Better management of outputs: all errors/warnings are directed to stderr; info messages are given to stdout if an authz destination file is provided and are redirected to stderr otherwise.
 - New parameter -v to distinguish warning/error and info verbosity (-v enables info logs; -q disables warning/error logs).
 - Exit with error code 1 when no group is found.
 - Hard-coded parameters at the top of the script are now optional.
 - New parameter -n to keep exact LDAP group names. For example, "my-group" is
   no longer replaced by "mygroup".
 - All text found "around" the auto-generated groups are now restored at the right place.
   You can define supergroups from LDAP groups safely.

2015-05-12 (version 1.2.0):
 - Add new capability to retrieve known groups.
 - Fix empty user name when subgroup not in search scope.
 - Bind to LDAP server synchronously.

2010-05-28 (version 1.1.0):
 - fix 'invalid cross-device link' error
 - handle TypeError when group not in search scope
 - print a warning when a sub group is not in search scope
 - add an option to follow sub groups to include all user members recursively (avoids previous warnings)
 - print group processing progress in verbose mode (like : +..++.-.--)

2009-04-15 (version 1.0.2):
 There was a bug with nested groups.

2009-01-22 (version 1.0.1):
 There was a bug when you didn't specify the -z flag and when the query returned no groups.

# Background

When building a Subversion server, people usually go for the setup that requires the least amount of administrative overhead.  For many, especially in the enterprise where Active Directory and OpenLDAP rule, this means hooking up Apache to a directory server to authenticate users via LDAP.  The reason for such a setup is that you can use the same credentials that log you into your computer, and other internal resources usually, to access Subversion.  One less set of credentials for the user to remember and one less user data store for the administrator to maintain.  Initially, this scenario is without any real disadvantage.  But once you want to start using your groups defined in your directory with Subversion's authorization (authz) mechanism, you find one of the shortcomings of such a configuration.

# The Problem

Subversion's authz architecture requires your group definitions to be defined within the authz file.  Subversion's authz architecture is also unaware of third-party data stores for users/groups.  This means that if you do not define your group within the authz file, Subversion will not know whether a user is a member of said group and will ultimately tell you that you do not have access to a resource.  That being said, the current problem is that with this server configuration, either you cannot harness group models defined in your directory server or you have to manually synchronize your group models from your directory server to Subversion's authz file.  There are many downsides to doing things this way:

* It's time consuming
* It's easy to forget that changes have been made and need to be mirrored
* It's very easy to make mistakes when doing it yourself
* ...

So while using LDAP for Subversion authentication is a dream, things are not so nice when it comes to reusing your group models for authz that are defined in your directory server.

# The Solution

Well, it just so happens that I have a solution.  One that is repeatable, loss-less and can be easily setup using the same information you used to configure Apache to authenticate your Subversion users.  The solution is the *"LDAP Groups to Subversion Authz Groups Bridge"* script.

The *"LDAP Groups to Subversion Authz Groups Bridge"* script is written in Python and, as mentioned before, does its work in a loss-less fashion.  This means that while this script will take on the trouble of taking your groups models defined in your directory server and reproducing them in a Subversion authz file, the script will not prohibit you from creating group definitions within the authz file that are not defined in your directory server.  Tired of all of the background?  Ready to see the script in action?  Let's go.

# The Implementation

Implementing the *"LDAP Groups to Subversion Authz Groups Bridge"* is actually simple.  If you've already configured Apache to authenticate your Subversion users, which we will not be covering, you can honestly copy/paste pieces of the Apache configuration into the script.  Before we go through an example though, there are a few prerequisites that you need to have taken care of before the script will run:

* Install Python (http://www.python.org)
* Install the python-ldap module (http://python-ldap.sourceforge.net)

Now that we have those things out of the way, let's look at the help output of the script, just to get our bearings:

```
  Usage: sync_ldap_groups_to_svn_authz.py [options]

  Options:
    -h, --help            show this help message and exit
    -d BIND_DN, --bind-dn=BIND_DN
                          The Distinguished Name (DN) used to bind to the
                          directory with. [Example: CN=Jeremy Whitlock,OU=Users,
                          DC=subversion,DC=thoughtspark,DC=org]
    -p BIND_PASSWORD, --bind-password=BIND_PASSWORD
                          The password for the user specified with the --bind-dn
                          . [Example: pa55w0rd]
    -l URL, --url=URL     The fully-qualified URL (scheme://hostname:port) to
                          the directory server. [Example: ldap://localhost:389]
    -b BASE_DN, --base-dn=BASE_DN
                          The Distinguished Name (DN) at which the recursive
                          group search will start. [Example:
                          DC=subversion,DC=thoughtspark,DC=org]
    -g GROUP_QUERY, --group-query=GROUP_QUERY
                          The query/filter used to identify group objects.
                          [Example: objectClass=group] [Default:
                          objectClass=group]
    -k GROUP_DNS, --known-group-dn=GROUP_DNS
                          The known group Distinguished Name(s) that will be
                          used directly as a group. Can be more than 1. When
                          this option is used, the --group-query will not be
                          used for searching. Useful if your LDAP server
                          contains a lot of groups. [Example: CN=Release Manager
                          s,OU=Groups,DC=subversion,DC=thoughtspark,DC=org]
    -m GROUP_MEMBER_ATTRIBUTE, --group-member-attribute=GROUP_MEMBER_ATTRIBUTE
                          The attribute of the group object that stores the
                          group memberships. [Example: member] [Default: member]
    -u USER_QUERY, --user-query=USER_QUERY
                          The query/filter used to identify user objects.
                          [Example: objectClass=user] [Default:
                          objectClass=user]
    -i USERID_ATTRIBUTE, --userid_attribute=USERID_ATTRIBUTE
                          The attribute of the user object that stores the
                          userid to be used in the authz file. [Example: cn]
                          [Default: cn]
    -f, --follow-groups   Follow sub-groups, i.e. add members of sub-groups
                          recursively. Does not mean OU recursive, which is by
                          design.
    -z AUTHZ_PATH, --authz-path=AUTHZ_PATH
                          The fully-qualified path to the authz file to be
                          updated/created.
    -n, --keep-names      Keep the exact LDAP group names without alteration.
                          Useful if your group names contain non-word
                          characters, i.e. not in [A-Za-z0-9_].
    -q, --quiet           Do not show logging information, except exit messages.
    -v, --verbose         Give more details during the execution. Overrides -q .
```

Anything that has a `[Default:` string in its corresponding documentation is *optional* and can usually be omitted when running against most directory servers.  The things that are not optional are things that you can get from your Apache configuration.  Now that we have our bearings, let's see an example.

Let's pretend that I have a directory structure like this:

*  Release Managers (CN=Release Managers,OU=Groups,DC=subversion,DC=thoughtspark,DC=org)
    * Release Manager One (CN=Release Manager One,OU=Users,DC=subversion,DC=thoughtspark,DC=org)
* Developers (CN=Developers,OU=Groups,DC=subversion,DC=thoughtspark,DC=org)
    * Release Managers (CN=Release Managers,OU=Nested Groups,OU=Groups,DC=subversion,DC=thoughtspark,DC=org)
    * Developer One (CN=Developer One,OU=Users,DC=subversion,DC=thoughtspark,DC=org)
    * Developer Two (CN=Developer Two,OU=Users,DC=subversion,DC=thoughtspark,DC=org)
    * Developer Three (CN=Developer Three,OU=Users,DC=subversion,DC=thoughtspark,DC=org)
* Release Managers (CN=Release Managers,OU=Nested Groups,OU=Groups,DC=subversion,DC=thoughtspark,DC=org)
    * Release Manager Two (CN=Release Manager Two,OU=Users,DC=subversion,DC=thoughtspark,DC=org)
* Administrators (CN=Administrators,CN=Roles,DC=subversion,DC=thoughtspark,DC=org)
    * Jeremy Whitlock (CN=Jeremy Whitlock,OU=Users,DC=subversion,DC=thoughtspark,DC=org)

*(Yes...I have two groups with the same name but in different locations.  This will help showcase how the "LDAP Groups to Subversion Authz Groups Bridge" handles this situation.)*  I now want to run the script:

```
python sync_ldap_groups_to_svn_authz.py \
  -d "CN=Jeremy Whitlock,OU=Users,DC=subversion,DC=thoughtspark,DC=org" \
  -l "ldap://localhost:389" \
  -b "DC=subversion,DC=thoughtspark,DC=org" > svn_auth.txt
```

You'll notice I didn't specify a password.  In this event, the script will prompt you, securely, for a password.  After the script runs, as long as you didn't run with the `-q` flag, you should see output like this:

```
  Successfully bound to ldap://localhost:389
  4 groups found.
```

Okay, things ran smoothly.  *(If you notice any `[WARNING]` output, just look at the message along side the warning to see why.)*  So what does the file look like?

```
[groups]
  ### Start generated content: LDAP Groups to Subversion Authz Groups Bridge (2009/01/19 23:17:07) ###
  ReleaseManagers = Release Manager One
  Developers = @ReleaseManagers1, Developer Three, Developer Two, Developer One
  ReleaseManagers1 = Release Manager Two
  Administrators = Jeremy Whitlock

  ################################################################################
  ###########   LDAP Groups to Subversion Authz Groups Bridge (Legend)  ##########
  ################################################################################
  ### ReleaseManagers = CN=Release Managers,OU=Groups,DC=subversion,DC=thoughtspark,DC=org
  ### Developers = CN=Developers,OU=Groups,DC=subversion,DC=thoughtspark,DC=org
  ### ReleaseManagers1 = CN=Release Managers,OU=Nested Groups,OU=Groups,DC=subversion,DC=thoughtspark,DC=org
  ### Administrators = CN=Administrators,CN=Roles,DC=subversion,DC=thoughtspark,DC=org
  ###############################################################################

  ### End generated content: LDAP Groups to Subversion Authz Groups Bridge ###
```

Here is a list of features, or things to realize, based on the output of this script:

* The `[groups]` section is created but only if necessary
* All generated content is within known "markers" for loss-less regeneration
* The header tells you when the file was last synchronized
* Nested groups, of any level, are supported
* Groups with the same name, but different locations, are supported
* An easy-to-read legend is created for reference reasons

Now that we've seen a very simple example, let's see one more example of how we might take an Apache configuration and turn that into a call to the *"LDAP Groups to Subversion Authz Groups Bridge"*.

Below we have a snippet of the important parts of an Apache configuration using LDAP for Subversion authentication:

```
  ...
  # The distinguished name to bind to the directory server
  AuthLDAPBindDN "CN=Jeremy Whitlock,OU=Users,DC=subversion,DC=thoughtspark,DC=org"

  # The password for the user above
  AuthLDAPBindPassword "myP455w0rd"

  # The LDAP query url
  AuthLDAPURL "ldap://localhost:389/DC=subversion,DC=thoughtspark,DC=org?sAMAccountName?sub?(objectClass=user)"
  ...
```

With the above information, Apache could connect to my theoretical Active Directory server and look for user objects. The way Apache identifies user objects is by the `objectClass` attribute being set to `user`.  Once a user is found, the `sAMAccountName` attribute is queried to see if it matches the user logging in.  Once the user is found, it is authenticated.  That being said, let's parse this information and turn it into a successful call to the *"LDAP Groups to Subversion Authz Groups Bridge"*:

```
python sync_ldap_groups_to_svn_authz.py \
  -d "CN=Jeremy Whitlock,OU=Users,DC=subversion,DC=thoughtspark,DC=org" \
  -p "myP455w0rd" \
  -l "ldap://localhost:389" \
  -b "DC=subversion,DC=thoughtspark,DC=org" \
  -i "sAMAccountName" > svn_auth.txt
```

The new things you see in this call that differ from the first call is that we are now looking for the `sAMAccountName` attribute for the username instead of the `cn` attribute.  You also see that we can pass the password as a command line argument.

# Filtering users

By default the query will return all members of the requested LDAP groups, this will include users whose accounts are disabled in the directory which is undesirable for security reasons. To exclude disabled users from the results from Active Directory, use the following user query filter:

```
  --user-query="(&(objectClass=User)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))]"
```
There are other such filters for Active Directory available at: (http://www.ldapexplorer.com/en/manual/109050000-famous-filters.htm)

# Summary

So now that we've seen how the script is ran, what is necessary to get it running and even a complete example, it's now up to you to get this thing into your Subversion infrastructure.  Immediate ideas are to automate this with your operating system's task scheduler and/or create a web interface to kick this script off on an as-needed basis. Regardless of how you use it, the *"LDAP Groups to Subversion Authz Groups Bridge"* should make the error-prone, tedious and easy-to-forget process of manually synchronizing your LDAP group models to Subversion's authz file much, much easier.  It might even get so easy you forget that Subversion doesn't natively support LDAP groups.
