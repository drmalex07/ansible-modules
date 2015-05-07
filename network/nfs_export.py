#!/usr/bin/python

# NOTE
# This module has the following limitations:
#  * Recognizes exports formatted as <path> <host>(<opts>). So, a line
#    with multiple host descriptors per path wont be recognized correctly.
#  * Assumes a <host> is either a real hostname, an ip address, or a CIDR
#    network. So, a hostname wildcard or a NIS netgroup wont br recognized.

DOCUMENTATION='''
module: nfs_export
short_description: Export an NFS directory
description: >
 Declare an exported NFS directory using /etc/exports.d. For more details on 
 the meaning of options, consult the exports(5) manpage.
options:
  dest:
    description: The exports configuration file
    required: no
    default: /etc/exports
  path:
    description: The exported directory path
    required: yes
  hosts:
    description: The client hosts (addresses or names) 
    required: yes
  readonly: 
    description: |
      Indicate if path should be exported as readonly. See C(ro) and C(rw) 
      options.
    required: no
    default: no
    type: bool
  secure: 
    description: |
      Indicate if client requests for this path should only originate from
      a privileged (<1024) port. See C(secure) and C(insecure) options.
    required: no
    default: yes
    type: bool
  sync: 
    description: |
      Indicate if requests should be replied only after the changes have
      been committed to stable storage. See C(sync) and C(async) options.
    required: no
    default: yes
    type: bool
  subtree_check: 
    description: |
      Enable or disable subtree checking. See C(subtree_check) option.
    required: no
    default: yes
    type: bool
  squash: 
    description: |
      Describe how and if client requests should be mapped (squased) to local 
      users. See C(root_squash), C(no_root_squash) and C(all_squash) options.
    required: no
    choices: ['none', 'all', 'root']
    default: root
  anon_user:
    description: |
      The anonymous user for squased requests. See C(anonuid) option.
    required: no
  anon_group:
    description: |
      The anonymous group for squased requests. See C(anongid) option.
    required: no
'''

EXAMPLES='''

# Provide a real (resolvable) hostname  
- nfs_export: path=/var/local/data-1 hosts=['somehost.local'] squash=none readonly=yes

# Provide an IP address
- nfs_export: path=/var/local/data-1 hosts=['10.0.2.15', '10.0.2.16'] squash=none readonly=no

# Provide a CIDR IPv4 vnetwork 
- nfs_export: path=/var/local/data-1 hosts=['10.0.2.15/31'] squash=none readonly=no

# Provide an IPV6 or an IPv6 network 
- nfs_export: path=/var/local/data-1 hosts=['2001:648:2ffc:1225:a800:cff:fe02:d983/126'] squash=all readonly=no

# Example with non-inline module arguments
- nfs_export: 
    path: /var/local/backups 
    sync: yes
    squash: all
    anon_user: backup
    anon_group: backup
    hosts: 
    - tape1.local
    - tape2.local
'''

import os
import re
import pwd
import grp
import io
import socket
from collections import OrderedDict
from tempfile import NamedTemporaryFile

from ansible.module_utils.basic import *

def build_export_opts(p):
    
    opts = OrderedDict()
    
    readonly = p.get('readonly')
    if readonly:
        opts['ro'] = None
    else:
        opts['rw'] = None

    secure = p.get('secure')
    if secure:
        opts['secure'] = None
    
    sync = p.get('sync')
    if sync: 
        opts['sync'] = None
    else:
        opts['async'] = None

    subtree_check = p.get('subtree_check')
    if subtree_check:
        opts['subtree_check'] = None
    else:
        opts['no_subtree_check'] = None

    squash = p.get('squash')
    if squash == 'root':
        opts['root_squash'] = None
    elif squash == 'none':
        opts['no_root_squash'] = None
    elif squash == 'all':
        opts['all_squash'] = None
    
    anon_user = p.get('anon_user')
    if anon_user:
        opts['anonuid'] = pwd.getpwnam(anon_user).pw_uid

    anon_group = p.get('anon_group')
    if anon_group:
        opts['anongid'] = grp.getgrnam(anon_group).gr_gid

    return opts

def verify_host(host):
    
    # Split prefix length part (if exists)
    try:
        addr, prefix = host.split('/', 1)
    except:
        addr, prefix = host, None
    else:
        try:
            prefix = int(prefix)
        except:
            return False

    # Try to resolve as an IPv4 hostname/address
    try:
        addrinfo = socket.getaddrinfo(addr, None, socket.AF_INET)
    except:
        pass 
    else:
        return ((prefix <= 32) and (prefix > 0)) if prefix else True
    
    # Try to resolve as an IPv6 hostname/address
    try:
        addrinfo = socket.getaddrinfo(addr, None, socket.AF_INET6)
    except:
        pass 
    else:
        return ((prefix <= 128) and (prefix > 0)) if prefix else True

    # Cannot recognize 
    return False

def main():
    
    module = AnsibleModule(
        argument_spec = dict(
           dest = dict(default='/etc/exports'),
           path = dict(required=True),
           hosts = dict(required=True),
           readonly = dict(type='bool', default=False),
           secure = dict(type='bool', default=True),
           sync = dict(type='bool', default=True),
           subtree_check = dict(type='bool', default=True),
           squash = dict(choices=['none', 'all', 'root'], default='root'),
           anon_user = dict(),
           anon_group = dict()
        ),
        supports_check_mode = True
    )
    p = module.params
    dry_run = module.check_mode

    target_config_file = p.get('dest')

    path = os.path.expanduser(p.get('path').rstrip('/'))
    if not os.path.isdir(path): 
        raise ValueError('The given path %s is not a directory' % (path))

    # Read and validate hosts
    
    hosts = p.get('hosts')
    if isinstance(hosts, basestring):
        hosts = hosts.split(',')
    for host in hosts:
        assert verify_host(host), 'The host %s doesnt seem valid' % (host)

    # Build export options

    opts = build_export_opts(p)
    export_opts = ['%s=%s' %(k, v) if v else k for k, v in opts.items()]

    # Generate entries suitable for /etc/exports

    entries = {}
    for host in hosts:
        entries[host] = {
          'matched': False, 
          'line': '%-28s %s(%s)\n' % (path, host, ','.join(export_opts)),
        }

    # Read target file and copy/replace/append lines
    
    if os.path.isfile(target_config_file):
        ifp = open(target_config_file, 'r')
    else:
        ifp = io.StringIO()
    changed = False
    with ifp, NamedTemporaryFile(delete=False) as ofp:
        # Copy or replace existing entries 
        for line1 in ifp:
            if line1.startswith('#') or re.match('$', line1):
                ofp.write(line1) # copy
                continue
            path1, rest1 = line1.strip().split()
            if not path == path1.rstrip('/'):
                ofp.write(line1) # copy
                continue
            m1 = re.match('([:\w][^()\s]+)\(.*\)', rest1)
            assert m1, 'Cannot parse host specifier for %s: %s' % (path1, rest1)
            host1 = m1.group(1)
            entry1 = entries.get(host1)
            if entry1:
                ofp.write(entry1['line']) # replace
                entry1['matched'] = True
                changed = (line1 != entry1['line'])
            else:
                ofp.write(line1) # copy
        # Append non-matched entries
        for host in hosts:
            if not entries[host]['matched']:
                ofp.write(entries[host]['line']) # append
                changed = True
    
    # Update target file 
    
    if not dry_run:
        os.rename(target_config_file, '/tmp/exports.bak')
        os.rename(ofp.name, target_config_file)

    module.exit_json(
        changed = changed, 
        path = path,
        hosts = hosts,
        target = target_config_file if not dry_run else ofp.name,
        opts = opts)

# Go!
main()

